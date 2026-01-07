
import { RequestHandler } from 'express';
import express from 'express';
import { CascataRequest } from '../types.js';
import { systemPool } from '../config/main.js';
import { parseBytes, formatBytes } from '../utils/index.js';
import { RateLimitService } from '../../services/RateLimitService.js';
import { Buffer } from 'buffer';

// --- TRUSTED BUILDERS ---
const TRUSTED_BUILDERS = [
  'https://app.flutterflow.io',
  'https://flutterflow.io',
  'https://app.appsmith.com',
  'https://editor.swagger.io',
  'https://studio.apollographql.com'
];

export const dynamicCors: RequestHandler = (req: any, res: any, next: any) => {
    const origin = req.headers.origin;
    
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,apikey,x-cascata-client,Prefer,Range,x-client-info,x-supabase-auth,content-profile,accept-profile,x-supabase-api-version,x-cascata-signature,x-cascata-event');
    res.setHeader('Access-Control-Expose-Headers', 'Content-Range, X-Total-Count, Link');

    if (origin && TRUSTED_BUILDERS.includes(origin)) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        if (req.method === 'OPTIONS') return res.status(200).end();
        return next();
    }

    if (!req.project) {
        if (req.method === 'OPTIONS') return res.status(200).end();
        return next();
    }

    const allowedOrigins = req.project.metadata?.allowed_origins || [];
    const safeOrigins = allowedOrigins.map((o: any) => typeof o === 'string' ? o : o.url);
    
    if (safeOrigins.length === 0) {
        if (origin && (origin.includes('localhost') || origin.includes('127.0.0.1'))) {
             res.setHeader('Access-Control-Allow-Origin', origin);
        }
    } 
    else {
        if (origin && safeOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        }
    }

    if (req.method === 'OPTIONS') return res.status(200).end();
    next();
};

export const hostGuard: RequestHandler = async (req: any, res: any, next: any) => {
    if (req.project) return next();
    if (req.path === '/' || req.path === '/health') return next();

    try {
        const settingsRes = await systemPool.query(
            "SELECT settings->>'domain' as domain FROM system.ui_settings WHERE project_slug = '_system_root_' AND table_name = 'domain_config'"
        );
        const systemDomain = settingsRes.rows[0]?.domain;
        const host = req.headers.host?.split(':')[0] || ''; 

        const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host); 
        const isLocal = host === 'localhost' || host === '127.0.0.1' || host === 'cascata-backend-control' || host.startsWith('172.') || host.startsWith('10.');

        if (isIp || isLocal) return next();

        if (systemDomain) {
            if (host.toLowerCase() === systemDomain.toLowerCase()) return next();
        } else {
            return next();
        }

        console.warn(`[HostGuard] 404 Stealth Block: ${req.path} via ${host}. System Domain: ${systemDomain || 'None'}`);
        return res.status(404).send('Not Found');

    } catch (e) { next(); }
};

export const controlPlaneFirewall: RequestHandler = async (req: any, res: any, next: any) => {
  if (req.method !== 'OPTIONS' && req.path.startsWith('/api/control/projects/')) {
    const slug = req.path.split('/')[4]; 
    if (slug) {
        const forwarded = req.headers['x-forwarded-for'];
        const realIp = req.headers['x-real-ip'];
        const socketIp = req.socket?.remoteAddress;
        let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
        clientIp = clientIp.replace('::ffff:', '');

        if (clientIp === '127.0.0.1' || clientIp === '::1' || clientIp.startsWith('172.') || clientIp.startsWith('10.')) {
            return next();
        }

        try {
            const result = await systemPool.query('SELECT blocklist FROM system.projects WHERE slug = $1', [slug]);
            if (result.rows.length > 0) {
                const blocklist = result.rows[0].blocklist || [];
                if (blocklist.includes(clientIp)) {
                    res.status(403).json({ error: 'Firewall: Access Denied' });
                    return;
                }
            }
        } catch (e) { }
    }
  }
  next();
};

export const dynamicBodyParser: RequestHandler = (req: any, res: any, next: any) => {
    const SYSTEM_HARD_CAP_BYTES = 50 * 1024 * 1024; 
    let limitStr = '2mb'; 

    const proj = (req as any).project;
    if (proj?.metadata?.security?.max_json_size) {
        limitStr = proj.metadata.security.max_json_size;
    } else if (req.path.includes('/edge/')) {
        limitStr = '10mb'; 
    } else if (req.path.includes('/import/')) {
        limitStr = '10mb'; 
    }

    const requestedBytes = parseBytes(limitStr);
    const safeLimit = Math.min(requestedBytes, SYSTEM_HARD_CAP_BYTES);

    // CRITICAL UPDATE: Capture Raw Body for HMAC Signature Verification
    const rawBodyBuffer = (req: any, _res: any, buf: Buffer, encoding: string) => {
        if (buf && buf.length) {
            req.rawBody = buf.toString(encoding as any || 'utf8');
        }
    };

    express.json({ limit: safeLimit, verify: rawBodyBuffer })(req, res, (err) => {
        if (err) {
            return res.status(413).json({
                error: 'Payload Too Large',
                message: `Request body exceeds the limit of ${formatBytes(safeLimit)}`,
                code: 'PAYLOAD_TOO_LARGE'
            });
        }
        express.urlencoded({ extended: true, limit: safeLimit, verify: rawBodyBuffer })(req, res, next);
    });
};

export const dynamicRateLimiter: RequestHandler = async (req: any, res: any, next: any) => {
    if (!req.project) return next();
    const forwarded = req.headers['x-forwarded-for'];
    const realIp = req.headers['x-real-ip'];
    const socketIp = req.socket?.remoteAddress;
    let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
    clientIp = clientIp.replace('::ffff:', '');
    if (clientIp === '127.0.0.1' || clientIp === '::1') return next();

    const r = req as CascataRequest;
    const result = await RateLimitService.check(r.project.slug, req.path.replace(`/api/data/${r.project.slug}`, '') || '/', req.method, r.userRole || 'anon', clientIp, systemPool);

    if (result.blocked) {
        res.setHeader('Retry-After', result.retryAfter || 60);
        res.status(429).json({ error: result.customMessage || 'Too Many Requests', retryAfter: result.retryAfter });
        return;
    }
    if (result.limit) {
        res.setHeader('X-RateLimit-Limit', result.limit);
        res.setHeader('X-RateLimit-Remaining', result.remaining || 0);
    }
    next();
};
