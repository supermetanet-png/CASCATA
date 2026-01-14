import express, { NextFunction } from 'express';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import multer from 'multer';
import process from 'process';

// --- CONFIG & UTILS ---
import { systemPool } from './src/config/main.js';
import { waitForDatabase, cleanTempUploads } from './src/utils/index.js';

// --- SERVICES ---
import { CertificateService } from './services/CertificateService.js';
import { MigrationService } from './services/MigrationService.js';
import { QueueService } from './services/QueueService.js';
import { RateLimitService } from './services/RateLimitService.js';
import { PoolService } from './services/PoolService.js';

// --- ROUTES ---
import mainRouter from './src/routes/index.js';

// --- MIDDLEWARES ---
import { dynamicCors, hostGuard } from './src/middlewares/security.js';
import { resolveProject } from './src/middlewares/core.js';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;

// --- PATHS ---
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const MIGRATIONS_ROOT = path.resolve(__dirname, '../migrations');

// --- INITIALIZATION ---
// Inicia serviços essenciais antes de aceitar tráfego
RateLimitService.init();
PoolService.initReaper(); // Inicia limpeza automática de conexões ociosas

if (process.env.SERVICE_MODE === 'CONTROL_PLANE') {
    QueueService.init(); 
}

// --- SECURITY HEADERS (Global Hardening) ---
app.use((req, res, next) => {
  // Fixed: Use .set() instead of .setHeader() for Express Response type compatibility
  res.set('X-Content-Type-Options', 'nosniff');
  // Fixed: Use .set() instead of .setHeader() for Express Response type compatibility
  res.set('X-Frame-Options', 'SAMEORIGIN');
  // Fixed: Use .set() instead of .setHeader() for Express Response type compatibility
  res.set('X-XSS-Protection', '1; mode=block');
  // Fixed: Cast to any to access removeHeader if the Response type definition is overly restrictive
  (res as any).removeHeader('X-Powered-By'); 
  next();
});

// --- CORS & HOST GUARD ---
// Dynamic CORS is applied globally to handle preflights correctly
app.use(dynamicCors as any);

// Resolve Project Context (Must be before HostGuard for custom domains to work)
app.use(resolveProject as any);

// Host Guard blocks direct IP access or unknown domains (Stealth Mode)
app.use(hostGuard as any);

// --- HEALTH CHECK (Deep Check) ---
app.get('/', (req, res) => { res.send('Cascata Engine v9.6 (Modular) OK'); });
app.get('/health', async (req, res) => { 
    let dbStatus = 'unknown';
    try {
        await systemPool.query('SELECT 1');
        dbStatus = 'connected';
    } catch(e) { dbStatus = 'error'; }

    res.json({ 
        status: 'ok', 
        mode: process.env.SERVICE_MODE, 
        system_db: dbStatus,
        memory: process.memoryUsage(),
        uptime: process.uptime(),
        time: new Date() 
    }); 
});

// --- MOUNT ROUTES ---
// All logic is now contained within the modular routers
app.use('/api', mainRouter);

// --- GLOBAL ERROR HANDLER ---
app.use((err: any, req: any, res: any, next: NextFunction) => {
  // Log critical errors (skip 4xx)
  if (!err.code?.startsWith('2') && !err.code?.startsWith('4')) {
      console.error(`[Global Error] ${req.method} ${req.path}:`, err);
  }

  // Multer Errors
  if (err instanceof multer.MulterError) {
      return res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: err.message, code: err.code });
  }
  
  // GoTrue / Auth Specific Mappings (Critical for Frontend Compatibility)
  if (err.message === "User already registered" || err.code === 'user_already_exists') {
       return res.status(422).json({ error: "user_already_exists", error_description: "User already registered" });
  }
  if (err.message === "Invalid login credentials") {
       return res.status(400).json({ error: "invalid_grant", error_description: "Invalid login credentials" });
  }
  if (err.message === "User not found") {
       return res.status(404).json({ error: "not_found", error_description: "User not found" });
  }

  // Postgres Error Codes
  if (err.code) {
      const pgMap: Record<string, {s: number, m: string}> = {
          '23505': { s: 409, m: 'Conflict: Record exists.' },
          '23503': { s: 400, m: 'Foreign Key Violation.' },
          '42P01': { s: 404, m: 'Table Not Found.' },
          '42703': { s: 400, m: 'Invalid Column.' },
          '23502': { s: 400, m: 'Missing Required Field.' },
          '22P02': { s: 400, m: 'Invalid Type.' },
      };
      if (pgMap[err.code]) {
          return res.status(pgMap[err.code].s).json({ error: pgMap[err.code].m, code: err.code });
      }
  }

  // JSON Syntax Errors
  if (err instanceof SyntaxError && 'body' in err) {
      return res.status(400).json({ error: 'Invalid JSON Payload' });
  }

  // Default Fallback
  res.status(err.status || 500).json({ 
      error: err.message || 'Internal Server Error', 
      code: err.code || 'INTERNAL_ERROR' 
  });
});

// --- SERVER INSTANCE ---
const server = app.listen(PORT, () => {
    console.log(`[CASCATA SECURE ENGINE] Listening on port ${PORT} [PID: ${process.pid}]`);
});

// --- BOOTSTRAP LOGIC ---
(async () => {
  try {
    console.log('[System] Booting up...');
    
    // 1. Cleanup Temp Files
    cleanTempUploads();
    
    // 2. Ensure SSL Certs (Self-signed fallback if needed)
    CertificateService.ensureSystemCert().catch(e => console.error("Cert Init Error:", e));
    
    // 3. Database Wait & Migration & Global Config
    waitForDatabase(30, 2000).then(async (ready) => {
        if (ready) {
            await MigrationService.run(systemPool, MIGRATIONS_ROOT);
            
            // LOAD GLOBAL CONFIG
            try {
                const dbRes = await systemPool.query("SELECT settings FROM system.ui_settings WHERE project_slug = '_system_root_' AND table_name = 'system_config'");
                if (dbRes.rows[0]?.settings?.maxConnections) {
                    PoolService.configure(dbRes.rows[0].settings);
                    console.log(`[System] Loaded Global Connection Cap: ${dbRes.rows[0].settings.maxConnections}`);
                }
            } catch(e) { console.warn("[System] Failed to load global config, using defaults."); }

            console.log('[System] Platform Ready & Healthy.');
        } else {
            console.error('[System] CRITICAL: Main Database Unreachable.');
        }
    });
  } catch (e) { 
      console.error('[System] FATAL BOOT ERROR:', e); 
      process.exit(1);
  }
})();

// --- GRACEFUL SHUTDOWN ---
const gracefulShutdown = async (signal: string) => {
    console.log(`[System] Received ${signal}. Shutting down gracefully...`);
    
    server.close(async () => {
        console.log('[System] HTTP server closed.');
        
        try {
            await PoolService.closeAll(); // Fecha conexões dos tenants
            await systemPool.end();       // Fecha conexão do sistema
            console.log('[System] Database connections closed.');
            process.exit(0);
        } catch (e) {
            console.error('[System] Error during shutdown:', e);
            process.exit(1);
        }
    });

    // Force shutdown after 10s if hangs
    setTimeout(() => {
        console.error('[System] Forced shutdown due to timeout.');
        process.exit(1);
    }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Prevent crash on unhandled async errors
process.on('unhandledRejection', (reason, promise) => {
    console.error('[System] Unhandled Rejection at:', promise, 'reason:', reason);
    // Logging only - do not crash unless critical
});

process.on('uncaughtException', (error) => {
    console.error('[System] Uncaught Exception:', error);
    // Depending on policy, might want to restart:
    // process.exit(1); 
});
