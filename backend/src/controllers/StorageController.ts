import { NextFunction } from 'express';
import fs from 'fs/promises'; // Use Promises API
import path from 'path';
import { CascataRequest } from '../types.js';
import { STORAGE_ROOT } from '../config/main.js';
import { getSectorForExt, validateMagicBytesAsync, parseBytes, walkAsync } from '../utils/index.js';
import { StorageService, StorageConfig } from '../../services/StorageService.js';

export class StorageController {

    // Fix: Use any for next parameter to resolve callable signature issues
    static async listBuckets(req: CascataRequest, res: any, next: any) {
        try {
            const p = path.join(STORAGE_ROOT, req.project.slug);
            await fs.mkdir(p, { recursive: true });
            
            const items = await fs.readdir(p, { withFileTypes: true });
            const buckets = items
                .filter(dirent => dirent.isDirectory())
                .map(dirent => ({ name: dirent.name }));
                
            res.json(buckets);
        } catch (e: any) {
            next(e);
        }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async createBucket(req: CascataRequest, res: any, next: any) {
        try {
            const p = path.join(STORAGE_ROOT, req.project.slug, req.body.name);
            await fs.mkdir(p, { recursive: true });
            res.json({ success: true });
        } catch (e: any) {
            next(e);
        }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async renameBucket(req: CascataRequest, res: any, next: any) {
        try {
            const oldPath = path.join(STORAGE_ROOT, req.project.slug, req.params.name);
            const newPath = path.join(STORAGE_ROOT, req.project.slug, req.body.newName);
            
            try { await fs.access(oldPath); } 
            catch { return res.status(404).json({ error: 'Bucket not found' }); }

            try { await fs.access(newPath); return res.status(400).json({ error: 'Name already exists' }); } 
            catch { }
            
            await fs.rename(oldPath, newPath);
            res.json({ success: true });
        } catch(e: any) {
            res.status(500).json({ error: 'Rename failed: ' + e.message });
        }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async deleteBucket(req: CascataRequest, res: any, next: any) {
        try {
            const bucketPath = path.join(STORAGE_ROOT, req.project.slug, req.params.name);
            if (!bucketPath.startsWith(path.join(STORAGE_ROOT, req.project.slug))) { 
                return res.status(403).json({ error: 'Access denied' }); 
            }
            await fs.rm(bucketPath, { recursive: true, force: true });
            res.json({ success: true }); 
        } catch (e: any) { 
            res.status(500).json({ error: e.message }); 
        }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async createFolder(req: CascataRequest, res: any, next: any) {
        try {
            const { name, path: relativePath } = req.body;
            const bucketPath = path.join(STORAGE_ROOT, req.project.slug, req.params.bucket);
            const targetDir = path.normalize(path.join(bucketPath, relativePath || '', name));

            if (!targetDir.startsWith(bucketPath)) { 
                return res.status(403).json({ error: 'Access Denied: Path Traversal' }); 
            }
            
            try { await fs.access(targetDir); return res.status(400).json({ error: 'Folder already exists' }); } 
            catch { }

            await fs.mkdir(targetDir, { recursive: true });
            res.json({ success: true });
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    }

    // --- HYBRID UPLOAD SYSTEM ---
    
    // 1. Negotiation Phase: "Can I upload this?"
    // Fix: Use any for next parameter to resolve callable signature issues
    static async signUpload(req: CascataRequest, res: any, next: any) {
        try {
            const { name, type, size, path: targetPath } = req.body;
            
            // A. Governance Check
            const governance = req.project.metadata?.storage_governance || {};
            const ext = path.extname(name).replace('.', '').toLowerCase();
            const sector = getSectorForExt(ext);
            const rule = governance[sector] || governance['global'] || { max_size: '10MB', allowed_exts: [] };

            if (rule.allowed_exts && rule.allowed_exts.length > 0 && !rule.allowed_exts.includes(ext)) { 
                return res.status(403).json({ error: `Policy Violation: Extension .${ext} is not allowed.` }); 
            }
            if (size && size > parseBytes(rule.max_size)) { 
                return res.status(403).json({ error: `Policy Violation: File size exceeds limit.` }); 
            }

            // B. Strategy Selection
            const storageConfig: StorageConfig = req.project.metadata?.storage_config || { provider: 'local' };
            const bucket = req.params.bucket;
            
            // Normalize Key
            let relativePath = targetPath || '';
            relativePath = relativePath.replace(new RegExp(`^${bucket}/`), '').replace(/^\/+/, ''); 
            const fullKey = path.join(relativePath, name).replace(/\\/g, '/');

            // C. Generate URL or Proxy Instruction
            const result = await StorageService.createUploadUrl(fullKey, type, storageConfig);
            
            res.json({
                strategy: result.strategy,
                url: result.url,
                method: result.method,
                fields: result.headers, // headers or fields for presigned post
                // If proxy, we can suggest the endpoint
                proxyUrl: result.strategy === 'proxy' ? `/api/data/${req.project.slug}/storage/${bucket}/upload` : undefined
            });

        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    }

    // 2. Execution Phase (Proxy Fallback)
    // Fix: Use any for next parameter to resolve callable signature issues
    static async uploadFile(req: CascataRequest, res: any, next: any) {
        if (!req.file) return res.status(400).json({ error: 'No file found in request body.' });
        
        const cleanup = async () => { try { await fs.unlink(req.file.path); } catch(e) {} };

        try {
            // Re-check Governance (Double Verify)
            const governance = req.project.metadata?.storage_governance || {};
            const ext = path.extname(req.file.originalname).replace('.', '').toLowerCase();
            const sector = getSectorForExt(ext);
            const rule = governance[sector] || governance['global'] || { max_size: '10MB', allowed_exts: [] };
            
            if (rule.allowed_exts && rule.allowed_exts.length > 0 && !rule.allowed_exts.includes(ext)) { 
                await cleanup();
                return res.status(403).json({ error: `Policy Violation: Extension .${ext} is not allowed.` }); 
            }
            const isValidSig = await validateMagicBytesAsync(req.file.path, ext);
            if (!isValidSig) { 
                await cleanup();
                return res.status(400).json({ error: 'Security Alert: File signature mismatch.' }); 
            }
            if (req.file.size > parseBytes(rule.max_size)) { 
                await cleanup();
                return res.status(403).json({ error: `Policy Violation: File size exceeds limit.` }); 
            }

            const storageConfig: StorageConfig = req.project.metadata?.storage_config || { provider: 'local' };
            const bucket = req.params.bucket;
            
            let relativePath = req.body.path || '';
            relativePath = relativePath.replace(new RegExp(`^${bucket}/`), '').replace(/^\/+/, ''); 

            const resultUrl = await StorageService.upload(req.file, req.project.slug, bucket, relativePath, storageConfig);

            if (storageConfig.provider === 'local') {
                const dest = path.join(STORAGE_ROOT, req.project.slug, bucket, relativePath, req.file.originalname);
                await fs.mkdir(path.dirname(dest), { recursive: true });
                try {
                    await fs.rename(req.file.path, dest);
                } catch (moveErr: any) {
                    if (moveErr.code === 'EXDEV') {
                        await fs.copyFile(req.file.path, dest);
                        await fs.unlink(req.file.path);
                    } else { throw moveErr; }
                }
                res.json({ success: true, path: dest.replace(STORAGE_ROOT, ''), provider: 'local' });
            } else {
                await cleanup();
                res.json({ success: true, path: resultUrl, provider: storageConfig.provider, url: resultUrl });
            }

        } catch (e: any) { 
            await cleanup();
            console.error("Upload Error:", e);
            res.status(500).json({ error: e.message || 'Storage Error' });
        }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async listFiles(req: CascataRequest, res: any, next: any) {
        const { path: queryPath } = req.query;
        const bucketPath = path.join(STORAGE_ROOT, req.project.slug, req.params.bucket);
        const targetPath = path.normalize(path.join(bucketPath, (queryPath as string) || ''));
        
        if (!targetPath.startsWith(bucketPath)) { 
            return res.status(403).json({ error: 'Access Denied' }); 
        }
        
        try { await fs.access(targetPath); } catch { return res.json({ items: [] }); }

        try {
            const dirents = await fs.readdir(targetPath, { withFileTypes: true });
            const items = await Promise.all(dirents.map(async (dirent) => {
                const fullPath = path.join(targetPath, dirent.name);
                const relPath = path.relative(bucketPath, fullPath).replace(/\\/g, '/');
                let stats = { size: 0, mtime: new Date() };
                try { if (dirent.isFile()) stats = await fs.stat(fullPath); } catch(e) {}

                return {
                    name: dirent.name,
                    type: dirent.isDirectory() ? 'folder' : 'file',
                    size: stats.size,
                    updated_at: stats.mtime.toISOString(),
                    path: relPath 
                };
            }));
            res.json({ items });
        } catch (e: any) { next(e); }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async search(req: CascataRequest, res: any, next: any) {
        const { q, bucket } = req.query;
        const searchTerm = (q as string || '').toLowerCase();
        const projectRoot = path.join(STORAGE_ROOT, req.project.slug);
        const storageConfig: StorageConfig = req.project.metadata?.storage_config || { provider: 'local' };
        
        if (storageConfig.provider !== 'local') return res.json({ items: [] });

        const searchRoot = bucket ? path.join(projectRoot, bucket as string) : projectRoot;
        if (!searchRoot.startsWith(projectRoot)) return res.status(403).json({ error: 'Access Denied' });
        
        try {
            await fs.access(searchRoot);
            let allFiles = await walkAsync(searchRoot, bucket ? searchRoot : projectRoot);
            if (searchTerm) allFiles = allFiles.filter(f => f.name.toLowerCase().includes(searchTerm));
            res.json({ items: allFiles });
        } catch (e: any) { 
            if (e.code === 'ENOENT') res.json({ items: [] }); else next(e); 
        }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async serveFile(req: CascataRequest, res: any, next: any) {
        const relativePath = req.params[0];
        const storageConfig: StorageConfig = req.project.metadata?.storage_config || { provider: 'local' };
        
        if (storageConfig.provider !== 'local') {
             if (storageConfig.provider === 's3' && storageConfig.s3) {
                 const key = path.join(req.params.bucket, relativePath).replace(/\\/g, '/');
                 let url = '';
                 if (storageConfig.s3.publicUrlBase) url = `${storageConfig.s3.publicUrlBase}/${key}`;
                 else if (storageConfig.s3.endpoint) url = `${storageConfig.s3.endpoint}/${storageConfig.s3.bucket}/${key}`;
                 else url = `https://${storageConfig.s3.bucket}.s3.${storageConfig.s3.region}.amazonaws.com/${key}`;
                 return res.redirect(url);
             }
             return res.status(404).json({ error: "File is hosted externally." });
        }

        const bucketPath = path.join(STORAGE_ROOT, req.project.slug, req.params.bucket);
        const filePath = path.join(bucketPath, relativePath);
        if (!filePath.startsWith(bucketPath)) return res.status(403).json({ error: 'Path Traversal Detected' });
        
        try { await fs.access(filePath); res.sendFile(filePath); } 
        catch { res.status(404).json({ error: 'File Not Found' }); }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async moveFiles(req: CascataRequest, res: any, next: any) {
        const storageConfig: StorageConfig = req.project.metadata?.storage_config || { provider: 'local' };
        if (storageConfig.provider !== 'local') return res.status(501).json({ error: "Move operation not supported for external providers yet." });

        try {
            const { bucket, paths, destination } = req.body;
            const root = path.join(STORAGE_ROOT, req.project.slug);
            const destPath = path.join(root, destination.bucket || bucket, destination.path || '');
            await fs.mkdir(destPath, { recursive: true });
            let movedCount = 0;
            
            for (const itemPath of paths) {
                const source = path.join(root, bucket, itemPath);
                const target = path.join(destPath, path.basename(itemPath));
                try { await fs.rename(source, target); movedCount++; } catch (err: any) { console.warn(`Failed to move ${itemPath}: ${err.message}`); }
            }
            res.json({ success: true, moved: movedCount });
        } catch (e: any) { next(e); }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async deleteObject(req: CascataRequest, res: any, next: any) {
        const storageConfig: StorageConfig = req.project.metadata?.storage_config || { provider: 'local' };
        const objectPath = req.query.path as string;

        try {
            if (storageConfig.provider === 'local') {
                const filePath = path.join(STORAGE_ROOT, req.project.slug, req.params.bucket, objectPath);
                const bucketRoot = path.join(STORAGE_ROOT, req.project.slug, req.params.bucket);
                if (!filePath.startsWith(bucketRoot)) return res.status(403).json({ error: 'Access Denied' });
                await fs.rm(filePath, { recursive: true, force: true });
                res.json({ success: true }); 
            } else {
                const key = path.join(req.params.bucket, objectPath).replace(/\\/g, '/');
                await StorageService.delete(key, storageConfig);
                res.json({ success: true });
            }
        } catch (e: any) { next(e); }
    }
}
