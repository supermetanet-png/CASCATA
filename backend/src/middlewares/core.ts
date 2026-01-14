
import { RequestHandler } from 'express';
import jwt from 'jsonwebtoken';
import pg from 'pg';
import { CascataRequest } from '../types.js';
import { systemPool, SYS_SECRET } from '../config/main.js';
import { PoolService } from '../../services/PoolService.js';
import { RateLimitService } from '../../services/RateLimitService.js';

export const resolveProject: RequestHandler = async (req: any, res: any, next: any) => {
  // CRITICAL FIX: Use originalUrl to safely bypass Control Plane routes regardless of router mounting
  if (req.originalUrl.includes('/api/control/')) return next();
  if (req.path === '/' || req.path === '/health') return next(); 
  
  const r = req as CascataRequest;
  const host = req.headers.host || '';
  
  const authHeader = req.headers['authorization'];
  const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : (req.query.token as string);
  r.isSystemRequest = false;
  
  if (bearerToken) {
    try {
      jwt.verify(bearerToken, process.env.SYSTEM_JWT_SECRET || 'fallback_secret');
      r.isSystemRequest = true;
    } catch { }
  }

  const pathParts = req.path.split('/');
  const slugFromUrl = (pathParts.length > 3 && pathParts[1] === 'api' && pathParts[2] === 'data') ? pathParts[3] : null;

  try {
    let projectResult: pg.QueryResult | undefined;
    let resolutionMethod = 'unknown';

    const projectQuery = `
        SELECT 
            id, name, slug, db_name, custom_domain, ssl_certificate_source, blocklist, metadata, status,
            pgp_sym_decrypt(jwt_secret::bytea, $1::text) as jwt_secret,
            pgp_sym_decrypt(anon_key::bytea, $1::text) as anon_key,
            pgp_sym_decrypt(service_key::bytea, $1::text) as service_key
        FROM system.projects 
    `;

    if (host && !host.includes('localhost') && !host.includes('127.0.0.1')) {
      projectResult = await systemPool.query(`${projectQuery} WHERE custom_domain = $2`, [SYS_SECRET, host]);
      if ((projectResult.rowCount ?? 0) > 0) resolutionMethod = 'domain';
    }

    if ((!projectResult || (projectResult.rowCount ?? 0) === 0) && slugFromUrl) {
      projectResult = await systemPool.query(`${projectQuery} WHERE slug = $2`, [SYS_SECRET, slugFromUrl]);
      if ((projectResult.rowCount ?? 0) > 0) resolutionMethod = 'slug';
    }

    if (!projectResult || !projectResult.rows[0]) {
      if (req.originalUrl.includes('/api/data/')) {
        res.status(404).json({ error: 'Project Context Not Found (404)' });
        return;
      }
      return next(); 
    }

    const project = projectResult.rows[0];

    if (!r.isSystemRequest) {
        const isPanic = await RateLimitService.checkPanic(project.slug);
        if (isPanic) {
            console.warn(`[PanicShield] Blocked request to ${req.url} for project ${project.slug} (REDIS)`);
            res.status(503).json({ error: 'System is currently in Panic Mode (Locked Down). Please contact administrator.' });
            return;
        }
    }

    if (project.custom_domain && resolutionMethod === 'slug') {
      const isDev = host.includes('localhost') || host.includes('127.0.0.1');
      if (!isDev && !r.isSystemRequest) {
        res.status(403).json({ 
          error: 'Domain Locking Policy: This project accepts requests only via its configured custom domain.',
          hint: `Use https://${project.custom_domain}`
        });
        return;
      }
    }

    if (resolutionMethod === 'domain' && !req.url.startsWith('/api/data/')) {
      req.url = `/api/data/${project.slug}${req.url}`;
    }

    const forwarded = req.headers['x-forwarded-for'];
    const realIp = req.headers['x-real-ip'];
    const socketIp = req.socket?.remoteAddress;
    let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
    clientIp = clientIp.replace('::ffff:', '');
    
    if (project.blocklist && project.blocklist.includes(clientIp)) {
      res.status(403).json({ error: 'Firewall: Access Denied (Blocked Origin)' });
      return;
    }

    r.project = project;

    try {
      const dbConfig = project.metadata?.db_config || {};
      
      r.projectPool = PoolService.get(project.db_name, {
          max: dbConfig.max_connections,
          idleTimeoutMillis: dbConfig.idle_timeout_seconds ? dbConfig.idle_timeout_seconds * 1000 : undefined
      });
      
    } catch (err) {
      res.status(502).json({ error: 'Database Connection Failed' });
      return;
    }

    next();
  } catch (e) {
    console.error("Internal Resolution Error", e);
    res.status(500).json({ error: 'Internal Resolution Error' });
  }
};

export const cascataAuth: RequestHandler = async (req: any, res: any, next: any) => {
  const r = req as CascataRequest;

  // CRITICAL FIX: Use originalUrl for consistent bypassing
  if (req.originalUrl.includes('/api/control/')) {
    if (req.path.endsWith('/auth/login') || req.path.endsWith('/auth/verify') || req.path.includes('/system/ssl-check')) return next();
    
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        if (req.path.includes('/export') && req.query.token) return next();
        res.status(401).json({ error: 'Missing Admin Token' }); 
        return; 
    }
    try {
      const token = authHeader.split(' ')[1];
      jwt.verify(token, process.env.SYSTEM_JWT_SECRET || 'fallback_secret');
      return next();
    } catch { 
      res.status(401).json({ error: 'Invalid Admin Token' });
      return;
    }
  }

  if (!r.project) { 
      if (req.path === '/' || req.path === '/health') return next();
      res.status(404).json({ error: 'No Project Context' }); 
      return; 
  }

  if (r.isSystemRequest) {
    r.userRole = 'service_role';
    return next();
  }

  const apiKey = (req.headers['apikey'] as string) || (req.query.apikey as string);
  const authHeader = req.headers['authorization'];
  const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : (req.query.token as string);

  if (bearerToken === r.project.service_key) {
    r.userRole = 'service_role';
    return next();
  }
  
  if (bearerToken === r.project.anon_key) {
      r.userRole = 'anon';
      return next();
  }

  if (apiKey === r.project.service_key) {
    r.userRole = 'service_role';
    return next();
  }

  if (bearerToken) {
    try {
      const decoded = jwt.verify(bearerToken, r.project.jwt_secret);
      r.user = decoded;
      r.userRole = 'authenticated';
      return next();
    } catch (e) { /* Fallback to anon */ }
  }

  if (apiKey === r.project.anon_key) {
    r.userRole = 'anon';
    return next();
  }

  if (
      req.path.includes('/auth/providers/') || 
      req.path.includes('/auth/callback') || 
      req.path.includes('/auth/v1/authorize') || 
      req.path.includes('/auth/v1/callback') ||
      req.path.includes('/auth/v1/verify') || 
      req.path.includes('/auth/passwordless/') || 
      req.path.includes('/auth/token/refresh') ||
      req.path.includes('/auth/challenge') || 
      req.path.includes('/auth/verify-challenge') 
  ) {
      r.userRole = 'anon';
      return next();
  }

  if (req.path.includes('/auth/users') || req.path.includes('/auth/token')) {
      r.userRole = 'anon';
      return next();
  }

  if (req.path.includes('/auth/v1/')) {
      r.userRole = r.userRole || 'anon';
      return next();
  }

  if (req.path.includes('/edge/')) {
      r.userRole = 'anon';
      return next();
  }

  res.status(401).json({ error: 'Unauthorized: Invalid API Key or JWT.' });
};
