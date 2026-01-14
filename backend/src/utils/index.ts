
import fs from 'fs';
import fsPromises from 'fs/promises';
import path from 'path';
import { Buffer } from 'buffer';
import { MAGIC_NUMBERS, TEMP_UPLOAD_ROOT, systemPool } from '../config/main.js';
import { CascataRequest } from '../types.js';
import pg from 'pg';
import dns from 'dns/promises';
import { URL } from 'url';

// --- SSRF SECURITY UTILS ---

const isPrivateIP = (ip: string): boolean => {
    // IPv4 Check
    if (ip.includes('.')) {
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4) return false; 

        // 0.0.0.0/8 (Current network)
        if (parts[0] === 0) return true;
        // 10.0.0.0/8 (Private)
        if (parts[0] === 10) return true;
        // 127.0.0.0/8 (Loopback)
        if (parts[0] === 127) return true;
        // 169.254.0.0/16 (Link-local / Cloud Metadata AWS/Azure/GCP)
        if (parts[0] === 169 && parts[1] === 254) return true;
        // 172.16.0.0/12 (Private)
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        // 192.168.0.0/16 (Private)
        if (parts[0] === 192 && parts[1] === 168) return true;
    } 
    // IPv6 Check
    else if (ip.includes(':')) {
        // ::1 (Loopback)
        if (ip === '::1' || ip === '::') return true;
        // fc00::/7 (Unique Local)
        if (ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) return true;
        // fe80::/10 (Link Local)
        if (ip.toLowerCase().startsWith('fe80')) return true;
    }
    
    return false;
};

/**
 * Validates a target URL against SSRF (Server-Side Request Forgery).
 * Resolves DNS and blocks private IPs and metadata services.
 */
export const validateTargetUrl = async (targetUrl: string): Promise<void> => {
    try {
        const url = new URL(targetUrl);
        const hostname = url.hostname;

        // 1. Block obvious localhost hostnames
        if (hostname === 'localhost' || hostname === '::1' || hostname === '0.0.0.0') {
            throw new Error("Blocked: localhost access denied");
        }
        
        // 2. Block internal service names (Docker DNS names)
        const internalServices = ['redis', 'db', 'backend_control', 'backend_data', 'nginx', 'nginx_controller'];
        if (internalServices.includes(hostname)) {
            throw new Error("Blocked: Internal service access denied");
        }

        // 3. DNS Resolution Check (The Real SSRF Check)
        let ips: string[] = [];
        
        // Check if hostname is already an IP
        const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
        
        if (isIp) {
            ips = [hostname];
        } else {
            try {
                // Resolve DNS
                const records = await dns.lookup(hostname, { all: true });
                ips = records.map(r => r.address);
            } catch (e) {
                // If DNS fails, it's not a valid target anyway
                throw new Error(`DNS Resolution failed for ${hostname}`);
            }
        }

        // 4. Validate all resolved IPs
        for (const ip of ips) {
            if (isPrivateIP(ip)) {
                throw new Error(`Security Violation: Host ${hostname} resolves to private IP ${ip}. Request blocked.`);
            }
        }

    } catch (e: any) {
        throw new Error(`SSRF Protection: ${e.message}`);
    }
};

// --- FILESYSTEM UTILS ---

export const getSectorForExt = (ext: string): string => {
  const map: Record<string, string[]> = {
    visual: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico', 'tiff', 'avif', 'heic', 'heif'],
    motion: ['mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv', 'm4v', 'mpg', 'mpeg', '3gp'],
    audio: ['mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a', 'wma', 'm4p', 'amr', 'mid', 'midi', 'opus'],
    docs: ['pdf', 'doc', 'docx', 'odt', 'rtf', 'txt', 'pages', 'epub', 'mobi', 'azw3'],
    structured: ['csv', 'json', 'xml', 'yaml', 'yml', 'sql', 'xls', 'xlsx', 'ods', 'tsv', 'parquet', 'avro'],
    archives: ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'iso', 'dmg', 'pkg', 'xz', 'zst'],
    exec: ['exe', 'msi', 'bin', 'app', 'deb', 'rpm', 'sh', 'bat', 'cmd', 'vbs', 'ps1'],
    scripts: ['js', 'ts', 'py', 'rb', 'php', 'go', 'rs', 'c', 'cpp', 'h', 'java', 'cs', 'swift', 'kt'],
    config: ['env', 'config', 'ini', 'xml', 'manifest', 'lock', 'gitignore', 'editorconfig', 'toml'],
    telemetry: ['log', 'dump', 'out', 'err', 'crash', 'report', 'audit'],
    messaging: ['eml', 'msg', 'vcf', 'chat', 'ics', 'pbx'],
    ui_assets: ['ttf', 'otf', 'woff', 'woff2', 'eot', 'sketch', 'fig', 'ai', 'psd', 'xd'],
    simulation: ['obj', 'stl', 'fbx', 'dwg', 'dxf', 'dae', 'blend', 'step', 'iges', 'glf', 'gltf', 'glb'],
    backup_sys: ['bak', 'sql', 'snapshot', 'dump', 'db', 'sqlite', 'sqlite3', 'rdb']
  };
  for (const sector in map) {
    if (map[sector].includes(ext)) return sector;
  }
  return 'global';
};

/**
 * Validates file signature (Magic Bytes) asynchronously.
 * Prevents reading the entire file into memory; reads only the first 4 bytes.
 */
export const validateMagicBytesAsync = async (filePath: string, ext: string): Promise<boolean> => {
    // Block obviously dangerous extensions immediately
    if (['exe', 'sh', 'php', 'pl', 'py', 'rb', 'bat', 'cmd', 'msi', 'vbs'].includes(ext)) {
        return false;
    }
    
    // If we don't have a signature for it, we trust the extension/mime (fallback)
    if (!MAGIC_NUMBERS[ext]) return true;

    let fileHandle: fsPromises.FileHandle | null = null;
    try {
        fileHandle = await fsPromises.open(filePath, 'r');
        const buffer = Buffer.alloc(4);
        await fileHandle.read(buffer, 0, 4, 0);
        
        const hex = buffer.toString('hex').toUpperCase();
        return MAGIC_NUMBERS[ext].some(sig => hex.startsWith(sig) || sig.startsWith(hex));
    } catch (e) {
        console.error(`[MagicBytes] Error validating ${filePath}:`, e);
        return false; 
    } finally {
        if (fileHandle) await fileHandle.close();
    }
};

export const parseBytes = (sizeStr: string): number => {
  if (!sizeStr) return 2 * 1024 * 1024; // 2MB Default Fallback
  const match = sizeStr.toString().match(/^(\d+(?:\.\d+)?)\s*([a-zA-Z]+)?$/);
  if (!match) return parseInt(sizeStr) || 0;
  const num = parseFloat(match[1]);
  const unit = (match[2] || 'B').toUpperCase();
  const multipliers: Record<string, number> = { 'B': 1, 'KB': 1024, 'MB': 1024 * 1024, 'GB': 1024 * 1024 * 1024 };
  return Math.floor(num * (multipliers[unit] || 1));
};

export const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

/**
 * Recursively walks a directory asynchronously.
 * Uses Promise.all for parallelism but limits concurrency implicitly by OS file descriptor limits if massive.
 * For massive directories, a queue-based approach might be better, but this is sufficient for typical use.
 */
export const walkAsync = async (dir: string, rootPath: string): Promise<any[]> => {
  let results: any[] = [];
  try {
    const list = await fsPromises.readdir(dir);
    for (const file of list) {
        const filePath = path.join(dir, file);
        const stat = await fsPromises.stat(filePath);
        const relativePath = path.relative(rootPath, filePath).replace(/\\/g, '/');
        
        results.push({
            name: file,
            type: stat.isDirectory() ? 'folder' : 'file',
            size: stat.size,
            updated_at: stat.mtime.toISOString(),
            path: relativePath
        });

        if (stat.isDirectory()) {
            const children = await walkAsync(filePath, rootPath);
            results = results.concat(children);
        }
    }
  } catch (e) {
      // Ignore errors (e.g., permission denied on specific subfolder) to keep scanning
      console.warn(`[WalkAsync] Error scanning ${dir}:`, e);
  }
  return results;
};

export const cleanTempUploads = async () => {
    try {
        const files = await fsPromises.readdir(TEMP_UPLOAD_ROOT);
        const now = Date.now();
        // Sequential check to be gentle on CPU
        for (const file of files) {
            const filePath = path.join(TEMP_UPLOAD_ROOT, file);
            try {
                const stats = await fsPromises.stat(filePath);
                if (now - stats.mtimeMs > 3600 * 1000) {
                    await fsPromises.rm(filePath, { recursive: true, force: true });
                }
            } catch (e) { /* ignore ENOENT race conditions */ }
        }
    } catch (e) {
        // If temp dir doesn't exist or other error, just ignore
    }
};

// --- DATABASE UTILS ---

export const quoteId = (identifier: string) => {
  if (typeof identifier !== 'string') throw new Error("Invalid identifier");
  return `"${identifier.replace(/"/g, '""')}"`;
};

export const queryWithRLS = async (req: CascataRequest, callback: (client: pg.PoolClient) => Promise<any>) => {
  if (!req.projectPool) throw new Error("Database connection not initialized");
  
  const client = await req.projectPool.connect();
  try {
    if (req.isSystemRequest) {
        await client.query("SELECT set_config('request.jwt.claim.role', 'service_role', true)");
    } else {
        await client.query("SET ROLE cascata_api_role");
        if (req.userRole === 'service_role') {
            await client.query("SELECT set_config('request.jwt.claim.role', 'service_role', true)");
        } else if (req.user && req.user.sub) {
            await client.query("SELECT set_config('request.jwt.claim.sub', $1, true)", [req.user.sub]);
            await client.query("SELECT set_config('request.jwt.claim.role', $1, true)", [req.userRole]);
        } else {
            await client.query("SELECT set_config('request.jwt.claim.role', 'anon', true)");
        }
    }
    const result = await callback(client);
    return result;
  } catch (e) {
    throw e;
  } finally {
    try { await client.query("RESET ROLE; DISCARD ALL"); } catch(err) { }
    client.release();
  }
};

export const waitForDatabase = async (retries = 30, delay = 1000): Promise<boolean> => {
  for (let i = 0; i < retries; i++) {
    try {
      const client = await systemPool.connect();
      client.release();
      console.log('[System] Database connected successfully.');
      return true;
    } catch (err: any) {
      if(i % 5 === 0) console.warn(`[System] Waiting for database... (${i + 1}/${retries})`);
      await new Promise(res => setTimeout(res, delay));
    }
  }
  return false;
};
