
import { Pool } from 'pg';
import crypto from 'crypto';
import { CascataRequest } from '../src/types.js';
import { PoolService } from './PoolService.js';
import { IngressEngine, IngressStep } from './IngressEngine.js';
import { Buffer } from 'buffer';

interface IngressSecurityConfig {
    verify_signature: boolean;
    header_key?: string; 
    secret?: string;     
    algorithm?: 'sha256' | 'sha1' | 'sha512';
    encoding?: 'hex' | 'base64';
    allowed_ips?: string[];
    idempotency_key?: string; // Caminho para chave única (ex: body.data.id)
}

export class IngressService {

    public static validateRequest(req: CascataRequest, config: IngressSecurityConfig, rawBody: string) {
        // 1. IP Whitelist Check
        if (config.allowed_ips && config.allowed_ips.length > 0) {
            const forwarded = req.headers['x-forwarded-for'];
            const realIp = req.headers['x-real-ip'];
            const socketIp = req.socket?.remoteAddress;
            let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
            clientIp = clientIp.replace('::ffff:', '');

            if (!config.allowed_ips.includes(clientIp)) {
                throw new Error(`Access Denied: IP ${clientIp} not in whitelist.`);
            }
        }

        // 2. HMAC Signature Check
        if (config.verify_signature) {
            if (!config.header_key || !config.secret) {
                throw new Error("Security Misconfiguration: Missing secret or header key.");
            }

            const receivedSig = req.headers[config.header_key.toLowerCase()];
            if (!receivedSig) {
                throw new Error(`Access Denied: Missing signature header [${config.header_key}].`);
            }

            const algo = config.algorithm || 'sha256';
            const encoding = config.encoding || 'hex';
            
            const hmac = crypto.createHmac(algo, config.secret);
            hmac.update(rawBody);
            const expectedSig = hmac.digest(encoding as any);

            const cleanReceived = (receivedSig as string).replace(`${algo}=`, '');
            const a = Buffer.from(cleanReceived);
            const b = Buffer.from(expectedSig);

            if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
                throw new Error("Access Denied: Invalid Signature.");
            }
        }
    }

    private static extractIdempotencyKey(req: any, path?: string): string | null {
        if (!path) return null;
        if (path.startsWith('headers.')) return req.headers[path.replace('headers.', '').toLowerCase()];
        if (path.startsWith('body.')) {
            return path.split('.').slice(1).reduce((acc: any, part: string) => acc && acc[part], req.body);
        }
        return null;
    }

    public static async handleIngress(
        projectSlug: string,
        routeSlug: string,
        req: CascataRequest,
        rawBody: string,
        systemPool: Pool
    ) {
        const start = Date.now();
        let hookId: string | null = null;
        let statusCode = 200;
        let responseBody: any = { status: 'processed' };
        let eventId: string | null = null;

        try {
            // 1. Buscar configuração
            const res = await systemPool.query(
                `SELECT h.id, h.security_config, h.flow_definition, h.is_active, p.db_name 
                 FROM system.ingress_hooks h
                 JOIN system.projects p ON p.slug = h.project_slug
                 WHERE h.project_slug = $1 AND h.route_slug = $2`,
                [projectSlug, routeSlug]
            );

            if (res.rows.length === 0) {
                statusCode = 404; throw new Error("Webhook endpoint not found.");
            }

            const hook = res.rows[0];
            hookId = hook.id;

            if (!hook.is_active) {
                statusCode = 503; throw new Error("Webhook endpoint is disabled.");
            }

            // 2. Security Gate
            this.validateRequest(req, hook.security_config || {}, rawBody);

            // 3. Idempotency Check
            const security = hook.security_config as IngressSecurityConfig;
            if (security.idempotency_key) {
                eventId = this.extractIdempotencyKey(req, security.idempotency_key);
                
                if (eventId) {
                    // Check logs for this event ID within last 24h
                    const dupCheck = await systemPool.query(
                        `SELECT 1 FROM system.ingress_logs 
                         WHERE project_slug = $1 AND hook_id = $2 AND event_id = $3 
                         AND status_code >= 200 AND status_code < 300`,
                        [projectSlug, hookId, String(eventId)]
                    );
                    
                    if (dupCheck.rowCount > 0) {
                        console.log(`[Ingress] Idempotency Hit: Event ${eventId} already processed.`);
                        return { status: 'skipped', reason: 'duplicate_event' };
                    }
                }
            }

            // 4. Executar Motor Lógico
            if (hook.flow_definition && Array.isArray(hook.flow_definition) && hook.flow_definition.length > 0) {
                
                // Conectar ao banco do Tenant (Projeto) com role de serviço (Sudo)
                const projectPool = PoolService.get(hook.db_name);
                const client = await projectPool.connect();
                
                try {
                    await client.query('BEGIN');
                    // Elevar privilégios para Service Role (Bypass RLS se necessário, é uma ação de sistema)
                    await client.query("SELECT set_config('request.jwt.claim.role', 'service_role', true)");

                    const context = {
                        body: req.body,
                        headers: req.headers,
                        query: req.query,
                        timestamp: new Date().toISOString()
                    };

                    await IngressEngine.executeFlow(hook.flow_definition, context, client);
                    
                    await client.query('COMMIT');
                } catch (err: any) {
                    await client.query('ROLLBACK');
                    throw err; // Propaga erro para o bloco catch principal
                } finally {
                    client.release();
                }
            } else {
                responseBody.message = "No flow defined, payload logged.";
            }

        } catch (e: any) {
            statusCode = statusCode === 200 ? 500 : statusCode; 
            if (e.message.includes('Access Denied')) statusCode = 403;
            responseBody = { error: e.message };
            throw e;
        } finally {
            // 5. Log & Auditoria
            if (hookId) {
                const duration = Date.now() - start;
                const ip = (req.headers['x-forwarded-for'] as string) || req.socket.remoteAddress || '';
                const safePayload = rawBody.length > 10000 ? { raw: 'truncated_too_large' } : req.body;

                systemPool.query(
                    `INSERT INTO system.ingress_logs (hook_id, project_slug, status_code, client_ip, payload, response_body, duration_ms, event_id)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
                    [hookId, projectSlug, statusCode, ip, JSON.stringify(safePayload), JSON.stringify(responseBody), duration, eventId ? String(eventId) : null]
                ).catch(err => console.error("Ingress Log Failed", err));
            }
        }

        return responseBody;
    }
}
