import AdmZip from 'adm-zip';
import path from 'path';
import fs from 'fs';
import { Pool, Client } from 'pg';
import { spawn, execSync } from 'child_process';
import axios from 'axios';
import FormData from 'form-data';
import { DatabaseService } from './DatabaseService.js';

export class ImportService {
    
    private static SAFE_MEMORY_BUFFER_LIMIT = 500 * 1024 * 1024;

    public static async validateBackup(filePath: string): Promise<any> {
        const stats = fs.statSync(filePath);
        if (stats.size > this.SAFE_MEMORY_BUFFER_LIMIT) throw new Error("File too large for validation.");

        const zip = new AdmZip(filePath);
        const manifestEntry = zip.getEntry('manifest.json');
        if (!manifestEntry) throw new Error("Arquivo inválido: manifest.json não encontrado.");
        const manifestContent = manifestEntry.getData().toString('utf8');
        return JSON.parse(manifestContent);
    }

    private static extractZipSecurely(zip: AdmZip, outputDir: string) {
        const entries = zip.getEntries();
        const resolvedDest = path.resolve(outputDir);
        for (const entry of entries) {
            if (entry.entryName.includes('..')) throw new Error('Malicious path detected');
            const destPath = path.resolve(resolvedDest, entry.entryName);
            if (!destPath.startsWith(resolvedDest)) throw new Error('Zip Slip attempt');
            
            if (entry.isDirectory) {
                fs.mkdirSync(destPath, { recursive: true });
            } else {
                const parentDir = path.dirname(destPath);
                if (!fs.existsSync(parentDir)) fs.mkdirSync(parentDir, { recursive: true });
                fs.writeFileSync(destPath, entry.getData());
            }
        }
    }

    public static async restoreProject(filePath: string, targetSlug: string, systemPool: Pool) {
        const safeSlug = targetSlug.replace(/[^a-z0-9-_]/gi, '');
        const tempDir = path.resolve(process.env.TEMP_UPLOAD_ROOT || '../temp_uploads', `restore_${safeSlug}_${Date.now()}`);
        const qdrantUrl = `http://${process.env.QDRANT_HOST || 'qdrant'}:${process.env.QDRANT_PORT || '6333'}`;
        
        try {
            console.log(`[Import] Extracting CAF to ${tempDir}...`);
            const zip = new AdmZip(filePath);
            this.extractZipSecurely(zip, tempDir);

            const manifestPath = path.join(tempDir, 'manifest.json');
            const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
            const dbName = `cascata_proj_${safeSlug.replace(/-/g, '_')}`;

            // 1. Provision SQL
            console.log(`[Import] Provisioning Database ${dbName}...`);
            await systemPool.query(`DROP DATABASE IF EXISTS "${dbName}"`);
            await systemPool.query(`CREATE DATABASE "${dbName}"`);
            await this.initBaseStructure(dbName);

            // 2. Register Metadata
            console.log(`[Import] Registering Project Registry...`);
            await this.registerProject(targetSlug, manifest.project.name, dbName, manifest.project, systemPool);

            // 3. Apply Schema & Data
            const schemaPath = path.join(tempDir, 'schema', 'structure.sql');
            if (fs.existsSync(schemaPath)) await this.executeSqlFile(dbName, schemaPath);
            const dataDir = path.join(tempDir, 'data');
            if (fs.existsSync(dataDir)) await this.bulkInsertData(dbName, dataDir);

            // 4. Restore Storage
            const storageSource = path.join(tempDir, 'storage');
            const storageTarget = path.resolve(process.env.STORAGE_ROOT || '../storage', targetSlug);
            if (fs.existsSync(storageSource)) {
                if (fs.existsSync(storageTarget)) fs.rmSync(storageTarget, { recursive: true, force: true });
                fs.renameSync(storageSource, storageTarget);
            }

            // 5. Restore Vectors (Qdrant Hybrid Restore)
            const vectorPath = path.join(tempDir, 'vector', 'snapshot.qdrant');
            if (fs.existsSync(vectorPath)) {
                console.log(`[Import] Restoring vector state to Qdrant...`);
                try {
                    // Passo A: Garantir que a coleção existe antes do restore
                    await axios.put(`${qdrantUrl}/collections/${safeSlug}`, {
                        vectors: { size: 1536, distance: 'Cosine' }
                    }).catch(() => {}); // Ignora erro se já existir

                    // Passo B: Upload e Recover via Multipart
                    const formData = new FormData();
                    formData.append('snapshot', fs.createReadStream(vectorPath));
                    
                    // Qdrant snapshots/upload endpoint
                    const uploadRes = await axios.post(`${qdrantUrl}/collections/${safeSlug}/snapshots/upload`, formData, {
                        headers: formData.getHeaders()
                    });
                    
                    const snapshotName = uploadRes.data.result.name;
                    
                    // Passo C: Recuperar do snapshot carregado
                    await axios.post(`${qdrantUrl}/collections/${safeSlug}/snapshots/recover`, {
                        location: `${qdrantUrl}/collections/${safeSlug}/snapshots/${snapshotName}`
                    });
                    
                    console.log(`[Import] Vector state rehydrated successfully.`);
                } catch (vErr: any) {
                    console.error(`[Import] Vector restore warning:`, vErr.response?.data || vErr.message);
                }
            }

            return { success: true, slug: targetSlug };

        } catch (e: any) {
            console.error('[Import] Error:', e);
            throw new Error(`Restore Failed: ${e.message}`);
        } finally {
            try { if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true }); } catch (e) {}
            try { if (fs.existsSync(filePath)) fs.unlinkSync(filePath); } catch(e) {}
        }
    }

    private static getDirectDbUrl(dbName: string): string {
        const host = process.env.DB_DIRECT_HOST || 'db';
        const port = process.env.DB_DIRECT_PORT || '5432';
        const user = process.env.DB_USER || 'cascata_admin';
        const pass = process.env.DB_PASS || 'secure_pass';
        return `postgresql://${user}:${pass}@${host}:${port}/${dbName}`;
    }

    private static async initBaseStructure(dbName: string) {
        const client = new Client({ connectionString: this.getDirectDbUrl(dbName) });
        await client.connect();
        try { await DatabaseService.initProjectDb(client); } 
        finally { await client.end(); }
    }

    private static async registerProject(slug: string, name: string, dbName: string, meta: any, systemPool: Pool) {
        await systemPool.query(`
            INSERT INTO system.projects (name, slug, db_name, jwt_secret, anon_key, service_key, metadata, status) 
            VALUES ($1, $2, $3, $4, $5, $6, $7, 'healthy')
            ON CONFLICT (slug) DO UPDATE SET
                status = 'healthy', jwt_secret = EXCLUDED.jwt_secret, anon_key = EXCLUDED.anon_key,
                service_key = EXCLUDED.service_key, metadata = EXCLUDED.metadata, updated_at = NOW()
        `, [name, slug, dbName, meta.jwt_secret, meta.anon_key, meta.service_key, { restored_from: meta.slug, restored_at: new Date(), ...meta.metadata }]);
    }

    private static async executeSqlFile(dbName: string, sqlPath: string) {
        const env = { ...process.env, PGPASSWORD: process.env.DB_PASS };
        const host = process.env.DB_DIRECT_HOST || 'db';
        const port = process.env.DB_DIRECT_PORT || '5432';
        const user = process.env.DB_USER || 'postgres';
        execSync(`psql -h ${host} -p ${port} -U ${user} -d ${dbName} -f "${sqlPath}"`, { env, stdio: 'ignore' });
    }

    private static async bulkInsertData(dbName: string, dataDir: string) {
        const files = fs.readdirSync(dataDir).filter(f => f.endsWith('.csv'));
        const env = { ...process.env, PGPASSWORD: process.env.DB_PASS };
        const host = process.env.DB_DIRECT_HOST || 'db';
        const port = process.env.DB_DIRECT_PORT || '5432';
        const user = process.env.DB_USER || 'postgres';

        for (const file of files) {
            let quotedTableName = '';
            const baseName = file.replace('.csv', '');
            if (baseName.includes('.')) {
                const parts = baseName.split('.');
                quotedTableName = parts.map(p => `"${p}"`).join('.');
            } else {
                quotedTableName = `"public"."${baseName}"`;
            }
            
            const filePath = path.join(dataDir, file);
            const copyCmd = `\\COPY ${quotedTableName} FROM STDIN WITH CSV HEADER`;
            
            await new Promise<void>((resolve, reject) => {
                const psql = spawn('psql', [
                    '-h', host, '-p', port, '-U', user, '-d', dbName,
                    '-c', `SET session_replication_role = 'replica'; ${copyCmd}`
                ], { env, stdio: ['pipe', 'ignore', 'pipe'] }); 

                const fileStream = fs.createReadStream(filePath);
                fileStream.pipe(psql.stdin);
                psql.on('close', (code) => code === 0 ? resolve() : reject(new Error(`Copy failed code ${code}`)));
            });
        }
    }
}
