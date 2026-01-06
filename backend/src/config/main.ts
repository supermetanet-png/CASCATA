import pg from 'pg';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import dotenv from 'dotenv';

dotenv.config();

const { Pool } = pg;

// --- ROBUST PATH RESOLUTION ---
// Em vez de depender de __dirname (que muda se estamos em /src ou /dist),
// usamos process.cwd() que no Docker é sempre /app.
const APP_ROOT = path.resolve('.');

// Prioriza variáveis de ambiente definidas no Docker, fallback para estrutura local padrão
export const STORAGE_ROOT = process.env.STORAGE_ROOT || path.resolve(APP_ROOT, '../storage');
export const MIGRATIONS_ROOT = process.env.MIGRATIONS_ROOT || path.resolve(APP_ROOT, 'migrations');
export const TEMP_UPLOAD_ROOT = process.env.TEMP_UPLOAD_ROOT || path.resolve(APP_ROOT, 'temp_uploads');
export const NGINX_DYNAMIC_ROOT = process.env.NGINX_DYNAMIC_ROOT || '/etc/nginx/conf.d/dynamic';

// Debug dos caminhos no boot para facilitar diagnóstico
console.log('[Config] Root Paths:', {
    APP_ROOT,
    STORAGE_ROOT,
    MIGRATIONS_ROOT
});

// Ensure Directories Exist
const ensureDir = (dir: string) => {
    try {
        if (!fs.existsSync(dir)) {
            console.log(`[Config] Creating directory: ${dir}`);
            fs.mkdirSync(dir, { recursive: true });
        }
    } catch (e) {
        console.error(`[Config] Error creating directory ${dir}:`, e);
    }
};

ensureDir(STORAGE_ROOT);
ensureDir(NGINX_DYNAMIC_ROOT);
ensureDir(TEMP_UPLOAD_ROOT);

// --- SYSTEM DATABASE POOL ---
export const systemPool = new Pool({ 
  connectionString: process.env.SYSTEM_DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000 
});

systemPool.on('error', (err) => {
    console.error('[SystemPool] Unexpected error on idle client', err);
});

// --- MULTER CONFIG ---
// Uploads temporários antes de serem movidos para o Storage definitivo
export const upload = multer({ 
    dest: TEMP_UPLOAD_ROOT,
    limits: {
        fileSize: 100 * 1024 * 1024, // 100MB limit per file
        fieldSize: 10 * 1024 * 1024 // 10MB limit for text fields
    }
});

export const backupUpload = multer({ 
    dest: TEMP_UPLOAD_ROOT,
    limits: { fileSize: 5 * 1024 * 1024 * 1024 } // 5GB for backups
});

// --- CONSTANTS ---
export const SYS_SECRET = process.env.SYSTEM_JWT_SECRET || 'insecure_default_secret_please_change';

export const MAGIC_NUMBERS: Record<string, string[]> = {
    'jpg': ['FFD8FF'],
    'png': ['89504E47'],
    'gif': ['47494638'],
    'pdf': ['25504446'],
    'exe': ['4D5A'], 
    'zip': ['504B0304'],
    'rar': ['52617221'],
    'mp3': ['494433', 'FFF3', 'FFF2'],
    'mp4': ['000000', '66747970'],
};