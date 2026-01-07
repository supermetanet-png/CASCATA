
import { NextFunction } from 'express';
import bcrypt from 'bcrypt';
import { CascataRequest } from '../types.js';
import { systemPool } from '../config/main.js';
import { AuthService } from '../../services/AuthService.js';
import { GoTrueService } from '../../services/GoTrueService.js';
import { RateLimitService, AuthSecurityConfig } from '../../services/RateLimitService.js';
import { WebhookService } from '../../services/WebhookService.js';
import { quoteId } from '../utils/index.js';
import { Buffer } from 'buffer';

export class DataAuthController {

    // Helper for security config
    private static getSecurityConfig(req: CascataRequest): AuthSecurityConfig {
        const meta = req.project?.metadata?.auth_config?.security || {};
        return {
            max_attempts: meta.max_attempts || 5,
            lockout_minutes: meta.lockout_minutes || 15,
            strategy: meta.strategy || 'hybrid'
        };
    }

    static async listUsers(req: CascataRequest, res: any, next: any) {
        if (!req.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
        try { const result = await req.projectPool!.query(`SELECT u.id, u.created_at, u.banned, u.last_sign_in_at, u.email_confirmed_at, jsonb_agg(jsonb_build_object('id', i.id, 'provider', i.provider, 'identifier', i.identifier)) as identities FROM auth.users u LEFT JOIN auth.identities i ON u.id = i.user_id GROUP BY u.id ORDER BY u.created_at DESC`); res.json(result.rows); } catch (e: any) { next(e); }
    }

    static async createUser(req: CascataRequest, res: any, next: any) {
        const { strategies, profileData } = req.body; 
        try {
            const client = await req.projectPool!.connect();
            try {
                await client.query('BEGIN');
                const userRes = await client.query('INSERT INTO auth.users (raw_user_meta_data) VALUES ($1) RETURNING id', [profileData || {}]);
                const userId = userRes.rows[0].id;
                if (strategies) {
                    for (const s of strategies) {
                        let passwordHash = s.password;
                        if (s.password) passwordHash = await bcrypt.hash(s.password, 10);
                        await client.query('INSERT INTO auth.identities (user_id, provider, identifier, password_hash) VALUES ($1, $2, $3, $4)', [userId, s.provider, s.identifier, passwordHash]);
                    }
                }
                await client.query('COMMIT');
                res.json({ success: true, id: userId });
            } finally { client.release(); }
        } catch (e: any) { next(e); }
    }

    static async legacyToken(req: CascataRequest, res: any, next: any) {
        const { provider, identifier, password } = req.body;
        const forwarded = req.headers['x-forwarded-for'];
        const realIp = req.headers['x-real-ip'];
        const socketIp = req.socket?.remoteAddress;
        let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
        clientIp = clientIp.replace('::ffff:', '');
        
        const secConfig = DataAuthController.getSecurityConfig(req);

        try {
            const lockout = await RateLimitService.checkAuthLockout(req.project.slug, clientIp, identifier, secConfig);
            if (lockout.locked) return res.status(429).json({ error: lockout.reason });

            const idRes = await req.projectPool!.query('SELECT * FROM auth.identities WHERE provider = $1 AND identifier = $2', [provider, identifier]);
            if (!idRes.rows[0]) {
                await RateLimitService.registerAuthFailure(req.project.slug, clientIp, identifier, secConfig);
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            const storedHash = idRes.rows[0].password_hash;
            let isValid = false;
            if (!storedHash.startsWith('$2')) {
                if (storedHash === password) { isValid = true; await req.projectPool!.query('UPDATE auth.identities SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(password, 10), idRes.rows[0].id]); }
            } else { isValid = await bcrypt.compare(password, storedHash); }
            
            if (!isValid) {
                await RateLimitService.registerAuthFailure(req.project.slug, clientIp, identifier, secConfig);
                return res.status(401).json({ error: 'Invalid credentials' });
            }
            
            await RateLimitService.clearAuthFailure(req.project.slug, clientIp, identifier);
            const session = await AuthService.createSession(idRes.rows[0].user_id, req.projectPool!, req.project.jwt_secret);
            res.json(session);
        } catch (e: any) { next(e); }
    }

    // --- LINK/MANAGE IDENTITIES ---
    static async linkIdentity(req: CascataRequest, res: any, next: any) {
        if (!req.isSystemRequest && req.userRole !== 'service_role') { return res.status(403).json({ error: 'Unauthorized' }); }
        const { provider, identifier, password } = req.body;
        const userId = req.params.id;
        if (!provider || !identifier) return res.status(400).json({ error: "Missing parameters" });

        try {
            let passwordHash = null;
            if (password) passwordHash = await bcrypt.hash(password, 10);

            const client = await req.projectPool!.connect();
            try {
                await client.query('BEGIN');
                const check = await client.query('SELECT id FROM auth.identities WHERE provider = $1 AND identifier = $2', [provider, identifier]);
                if (check.rows.length > 0) throw new Error("Identity already linked to a user.");
                await client.query('INSERT INTO auth.identities (user_id, provider, identifier, password_hash, created_at, last_sign_in_at) VALUES ($1, $2, $3, $4, now(), now())', [userId, provider, identifier, passwordHash]);
                await client.query('COMMIT');
                res.json({ success: true });
            } catch(e) { await client.query('ROLLBACK'); throw e; } finally { client.release(); }
        } catch (e: any) { next(e); }
    }

    static async unlinkIdentity(req: CascataRequest, res: any, next: any) {
        if (!req.isSystemRequest && req.userRole !== 'service_role') { return res.status(403).json({ error: 'Unauthorized' }); }
        try { 
            const countRes = await req.projectPool!.query('SELECT count(*) FROM auth.identities WHERE user_id = $1', [req.params.id]);
            if (parseInt(countRes.rows[0].count) <= 1) return res.status(400).json({ error: "Cannot remove the only identity linked to this user." });
            await req.projectPool!.query('DELETE FROM auth.identities WHERE id = $1 AND user_id = $2', [req.params.identityId, req.params.id]); 
            res.json({ success: true }); 
        } catch (e: any) { next(e); }
    }

    static async updateUserStatus(req: CascataRequest, res: any, next: any) {
        if (!req.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
        try { await req.projectPool!.query('UPDATE auth.users SET banned = $1 WHERE id = $2', [req.body.banned, req.params.id]); res.json({ success: true }); } catch (e: any) { next(e); }
    }

    static async deleteUser(req: CascataRequest, res: any, next: any) {
        if (!req.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
        try { await req.projectPool!.query('DELETE FROM auth.users WHERE id = $1', [req.params.id]); res.json({ success: true }); } catch (e: any) { next(e); }
    }

    // --- CONFIG & CHALLENGES ---
    static async linkConfig(req: CascataRequest, res: any, next: any) {
        const { linked_tables, authStrategies, authConfig } = req.body;
        try {
            const metaUpdates: any = {};
            if (authStrategies) metaUpdates.auth_strategies = authStrategies;
            if (authConfig) metaUpdates.auth_config = authConfig;
            if (linked_tables) metaUpdates.linked_tables = linked_tables;
            await systemPool.query(`UPDATE system.projects SET metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb WHERE slug = $2`, [JSON.stringify(metaUpdates), req.project.slug]);
            if (linked_tables && Array.isArray(linked_tables) && linked_tables.length > 0) {
                const client = await req.projectPool!.connect();
                try {
                    await client.query('BEGIN');
                    for (const table of linked_tables) {
                        await client.query(`ALTER TABLE public.${quoteId(table)} ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL`);
                        await client.query(`CREATE INDEX IF NOT EXISTS ${quoteId('idx_' + table + '_user_id')} ON public.${quoteId(table)} (user_id)`);
                    }
                    await client.query('COMMIT');
                } finally { client.release(); }
            }
            res.json({ success: true });
        } catch (e: any) { next(e); }
    }

    static async challenge(req: CascataRequest, res: any, next: any) {
        const { provider, identifier } = req.body;
        if (!provider || !identifier) return res.status(400).json({ error: 'Provider and Identifier required' });
        try {
            const strategies = req.project.metadata?.auth_strategies || {};
            const config = strategies[provider];
            if (!config || !config.enabled) return res.status(400).json({ error: `Strategy ${provider} not enabled.` });
            if (!config.webhook_url) return res.status(500).json({ error: `Webhook URL not configured for ${provider}` });
            await AuthService.initiatePasswordless(req.projectPool!, provider, identifier, config.webhook_url, req.project.jwt_secret, config.otp_config || { length: 6, charset: 'numeric' });
            res.json({ success: true, message: 'Challenge sent' });
        } catch(e: any) { next(e); }
    }

    static async verifyChallenge(req: CascataRequest, res: any, next: any) {
        const { provider, identifier, code } = req.body;
        if (!provider || !identifier || !code) return res.status(400).json({ error: 'Missing parameters' });
        try {
            const profile = await AuthService.verifyPasswordless(req.projectPool!, provider, identifier, code);
            const userId = await AuthService.upsertUser(req.projectPool!, profile);
            const session = await AuthService.createSession(userId, req.projectPool!, req.project.jwt_secret);
            res.json(session);
        } catch(e: any) { next(e); }
    }

    // --- GOTRUE COMPATIBILITY ---
    static async goTrueSignup(req: CascataRequest, res: any, next: any) {
        try {
            const response = await GoTrueService.handleSignup(req.projectPool!, req.body, req.project.jwt_secret, req.project.metadata || {});
            res.json(response);
        } catch(e: any) { next(e); }
    }

    static async goTrueToken(req: CascataRequest, res: any, next: any) {
        const forwarded = req.headers['x-forwarded-for'];
        const realIp = req.headers['x-real-ip'];
        const socketIp = req.socket?.remoteAddress;
        let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
        clientIp = clientIp.replace('::ffff:', '');
        const email = req.body.email;
        const secConfig = DataAuthController.getSecurityConfig(req);

        try {
            if (req.body.grant_type === 'password') {
                const lockout = await RateLimitService.checkAuthLockout(req.project.slug, clientIp, email, secConfig);
                if (lockout.locked) return res.status(429).json({ error: lockout.reason, error_description: lockout.reason });
            }

            const response = await GoTrueService.handleToken(req.projectPool!, req.body, req.project.jwt_secret, req.project.metadata || {});
            if (req.body.grant_type === 'password') await RateLimitService.clearAuthFailure(req.project.slug, clientIp, email);
            res.json(response);
        } catch(e: any) {
            if (req.body.grant_type === 'password') await RateLimitService.registerAuthFailure(req.project.slug, clientIp, email, secConfig);
            next(e);
        }
    }

    static async goTrueUser(req: CascataRequest, res: any, next: any) {
        if (!req.user || !req.user.sub) return res.status(401).json({ error: "unauthorized", error_description: "Missing or invalid token" });
        try { const user = await GoTrueService.handleGetUser(req.projectPool!, req.user.sub); res.json(user); } catch(e: any) { res.status(404).json({ error: "not_found", error_description: e.message }); }
    }

    static async goTrueLogout(req: CascataRequest, res: any, next: any) {
        const authHeader = req.headers.authorization;
        if (!authHeader) return res.status(401).json({ error: "unauthorized" });
        try { await GoTrueService.handleLogout(req.projectPool!, authHeader.replace('Bearer ', '').trim(), req.project.jwt_secret); res.status(204).send(); } catch(e) { res.status(500).json({ error: "server_error" }); }
    }

    static async goTrueVerify(req: CascataRequest, res: any, next: any) {
        const { token, type, redirect_to } = req.query;
        try {
            if (!token || !type) throw new Error("Missing token or type");
            const session = await GoTrueService.handleVerify(req.projectPool!, token as string, type as string, req.project.jwt_secret, req.project.metadata);
            const hash = `access_token=${session.access_token}&refresh_token=${session.refresh_token}&expires_in=${session.expires_in}&token_type=bearer&type=${type}`;
            let targetRedirect = redirect_to as string;
            
            if (!targetRedirect) {
                 const siteUrl = req.project.metadata?.auth_config?.site_url;
                 if (siteUrl) targetRedirect = siteUrl;
                 else {
                     const origins = req.project.metadata?.allowed_origins || [];
                     if (origins.length > 0) {
                         const first = origins[0];
                         targetRedirect = typeof first === 'string' ? first : first.url;
                     }
                 }
            }

            if (targetRedirect) {
                const cleanRedirect = targetRedirect.endsWith('/') ? targetRedirect.slice(0, -1) : targetRedirect;
                res.redirect(`${cleanRedirect}#${hash}`);
            } else {
                res.json(session);
            }
        } catch (e: any) { res.status(400).json({ error: e.message, error_code: 'validation_failed' }); }
    }

    static async goTrueAuthorize(req: CascataRequest, res: any, next: any) {
        const { provider, redirect_to } = req.query;
        if (!provider) return res.status(400).json({ error: 'Provider required' });
        try {
            const providerConfig = req.project.metadata?.auth_config?.providers?.[provider as string];
            if (!providerConfig || !providerConfig.client_id) return res.status(400).json({ error: `Provider ${provider} not configured.` });

            const protocol = req.headers['x-forwarded-proto'] || 'http';
            const host = req.headers.host;
            let callbackUrl = '';

            if (req.project.custom_domain && host === req.project.custom_domain) {
                callbackUrl = `${protocol}://${host}/auth/v1/callback`;
            } else {
                callbackUrl = `${protocol}://${host}/api/data/${req.project.slug}/auth/v1/callback`;
            }

            const config = { clientId: providerConfig.client_id, redirectUri: callbackUrl };
            let targetRedirect = redirect_to as string;
            if (!targetRedirect) {
                const origins = req.project.metadata?.allowed_origins || [];
                if (origins.length > 0) {
                     const first = origins[0];
                     targetRedirect = typeof first === 'string' ? first : first.url;
                }
                if (!targetRedirect && req.headers.referer) {
                    try { targetRedirect = new URL(req.headers.referer).origin; } catch(e) {}
                }
            }

            const statePayload = { redirectTo: targetRedirect || '' };
            const state = Buffer.from(JSON.stringify(statePayload)).toString('base64');
            const authUrl = AuthService.getAuthUrl(provider as string, config, state);
            res.redirect(authUrl);
        } catch (e: any) { res.status(500).json({ error: e.message }); }
    }

    static async goTrueCallback(req: CascataRequest, res: any, next: any) {
        const { code, state, error } = req.query;
        if (error) return res.status(400).json({ error: 'OAuth Error', details: error });
        if (!code) return res.status(400).json({ error: 'No code provided' });

        try {
            let finalRedirect = '';
            if (state) {
                try {
                    const decodedState = JSON.parse(Buffer.from(state as string, 'base64').toString('utf8'));
                    finalRedirect = decodedState.redirectTo;
                } catch(e) {}
            }

            if (!finalRedirect) {
                 const siteUrl = req.project.metadata?.auth_config?.site_url;
                 if (siteUrl) finalRedirect = siteUrl;
                 else {
                     const origins = req.project.metadata?.allowed_origins || [];
                     if (origins.length > 0) {
                         const first = origins[0];
                         finalRedirect = typeof first === 'string' ? first : first.url;
                     }
                 }
            }

            const provider = 'google'; // Assumption for now as it's the only one implemented in AuthService with callback
            const providerConfig = req.project.metadata?.auth_config?.providers?.[provider];
            if (!providerConfig) throw new Error("Provider config missing");

            const protocol = req.headers['x-forwarded-proto'] || 'http';
            const host = req.headers.host;
            let callbackUrl = '';
            if (req.project.custom_domain && host === req.project.custom_domain) {
                callbackUrl = `${protocol}://${host}/auth/v1/callback`;
            } else {
                callbackUrl = `${protocol}://${host}/api/data/${req.project.slug}/auth/v1/callback`;
            }

            const config = { clientId: providerConfig.client_id, clientSecret: providerConfig.client_secret, redirectUri: callbackUrl };
            const profile = await AuthService.handleCallback(provider, code as string, config);
            const userId = await AuthService.upsertUser(req.projectPool!, profile);
            const session = await AuthService.createSession(userId, req.projectPool!, req.project.jwt_secret);

            const hash = `access_token=${session.access_token}&refresh_token=${session.refresh_token}&expires_in=${session.expires_in}&token_type=bearer&type=recovery`;
            
            if (finalRedirect) {
                const cleanRedirect = finalRedirect.endsWith('/') ? finalRedirect.slice(0, -1) : finalRedirect;
                res.redirect(`${cleanRedirect}#${hash}`);
            } else {
                res.send(`<html><head><title>Login Successful</title></head><body><h3>Auth Complete</h3><script>if(window.opener){window.opener.postMessage({session:${JSON.stringify(session)},error:null},'*');window.close();}</script></body></html>`);
            }
        } catch (e: any) { res.status(500).json({ error: e.message }); }
    }
}
