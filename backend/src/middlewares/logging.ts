
import { RequestHandler } from 'express';
import { CascataRequest } from '../types.js';
import { systemPool } from '../config/main.js';
import { WebhookService } from '../../services/WebhookService.js';

export const detectSemanticAction = (method: string, path: string): string | null => {
    if (path.includes('/tables') && method === 'POST' && path.endsWith('/rows')) return 'INSERT_ROWS';
    if (path.includes('/tables') && method === 'POST') return 'CREATE_TABLE';
    if (path.includes('/tables') && method === 'DELETE' && !path.includes('/rows')) return 'DROP_TABLE';
    if (path.includes('/tables') && method === 'DELETE' && path.includes('/rows')) return 'DELETE_ROWS';
    if (path.includes('/tables') && method === 'PUT') return 'UPDATE_ROWS';
    if (path.includes('/rest/v1/') && method === 'GET') return 'REST_SELECT';
    if (path.includes('/rest/v1/') && method === 'POST') return 'REST_INSERT';
    if (path.includes('/rest/v1/') && method === 'PATCH') return 'REST_UPDATE';
    if (path.includes('/rest/v1/') && method === 'DELETE') return 'REST_DELETE';
    if (path.includes('/auth/token') && !path.includes('refresh')) return 'AUTH_LOGIN';
    if (path.includes('/auth/token/refresh')) return 'AUTH_REFRESH';
    if (path.includes('/auth/callback')) return 'AUTH_CALLBACK'; 
    if (path.includes('/auth/passwordless/start')) return 'AUTH_OTP_REQUEST'; 
    if (path.includes('/auth/passwordless/verify')) return 'AUTH_OTP_VERIFY'; 
    if (path.includes('/auth/users') && method === 'POST') return 'AUTH_REGISTER';
    if (path.includes('/storage') && method === 'POST' && path.includes('/upload')) return 'UPLOAD_FILE';
    if (path.includes('/storage') && method === 'DELETE') return 'DELETE_FILE';
    if (path.includes('/edge/')) return 'EDGE_INVOKE';
    
    // GoTrue mappings
    if (path.includes('/auth/v1/signup')) return 'GOTRUE_SIGNUP';
    if (path.includes('/auth/v1/token')) return 'GOTRUE_TOKEN';
    if (path.includes('/auth/v1/user')) return 'GOTRUE_USER';
    if (path.includes('/auth/v1/authorize')) return 'GOTRUE_OAUTH_START';
    if (path.includes('/auth/v1/callback')) return 'GOTRUE_OAUTH_CALLBACK';
    if (path.includes('/auth/v1/verify')) return 'GOTRUE_VERIFY_EMAIL';
    
    return null;
};

export const auditLogger: RequestHandler = (req: any, res: any, next: any) => {
  const start = Date.now();
  const oldJson = res.json;
  const r = req as CascataRequest;

  if (req.path.includes('/realtime')) return next();

  (res as any).json = function(data: any) {
    if (r.project) {
       const duration = Date.now() - start;
       const forwarded = req.headers['x-forwarded-for'];
       const realIp = req.headers['x-real-ip'];
       const socketIp = (req as any).socket?.remoteAddress;
       let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
       clientIp = clientIp.replace('::ffff:', '');
       const isInternal = req.headers['x-cascata-client'] === 'dashboard' || r.isSystemRequest;
       const semanticAction = detectSemanticAction(req.method, req.path);
       const geoInfo = { is_internal: isInternal, auth_status: res.statusCode >= 400 ? 'SECURITY_ALERT' : 'GRANTED', semantic_action: semanticAction };

       // Request Payload for Audit Logs (Input)
       const isUpload = req.headers['content-type']?.includes('multipart/form-data');
       const inputPayload = isUpload ? { type: 'binary_upload', file: req.file?.originalname } : req.body;

       // Security: Auto Block 401
       if (res.statusCode === 401 && r.project.metadata?.security?.auto_block_401) {
          const isSafeIp = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp.startsWith('172.') || clientIp.startsWith('10.') || clientIp.startsWith('192.168.'); 
          if (!isSafeIp && !r.project.blocklist?.includes(clientIp)) {
             systemPool.query('UPDATE system.projects SET blocklist = array_append(blocklist, $1) WHERE slug = $2', [clientIp, r.project.slug]).catch(err => console.error("Auto-block failed", err));
          }
       }

       // 1. Audit Log Insert
       systemPool.query(
        `INSERT INTO system.api_logs (project_slug, method, path, status_code, client_ip, duration_ms, user_role, payload, headers, geo_info) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [r.project.slug, req.method, req.path, res.statusCode, clientIp, duration, r.userRole || 'unauthorized', JSON.stringify(inputPayload).substring(0, 2000), JSON.stringify({ referer: req.headers.referer, userAgent: req.headers['user-agent'] }), JSON.stringify(geoInfo)]
       ).catch(() => {});
       
       // 2. Webhook Dispatch (ONLY on Success 2xx)
       // CRITICAL IMPROVEMENT: Use `data` (Response Body) instead of `req.body` (Request Body).
       // This ensures webhooks receive the generated IDs, Timestamps, and Default Values.
       if (res.statusCode >= 200 && res.statusCode < 300 && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
           let tableName = '*';
           // Extract table name from path
           if (req.path.includes('/tables/')) { 
               const parts = req.path.split('/tables/'); 
               if (parts[1]) tableName = parts[1].split('/')[0]; 
           } else if (req.path.includes('/rest/v1/')) {
               const parts = req.path.split('/rest/v1/'); 
               if (parts[1]) tableName = parts[1].split('/')[0];
           }

           // Determine Payload to Send
           // If it's a delete, the response usually contains the deleted record(s).
           // If it's an insert/update, the response contains the new record(s).
           const webhookPayload = data; 

           WebhookService.dispatch(
               r.project.slug, 
               tableName, 
               semanticAction || req.method, 
               webhookPayload, 
               systemPool, 
               r.project.jwt_secret
           );
       }
    }
    return oldJson.apply(res, arguments as any);
  }
  next();
};
