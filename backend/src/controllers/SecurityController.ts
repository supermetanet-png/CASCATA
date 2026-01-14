import { NextFunction } from 'express';
import { CascataRequest } from '../types.js';
import { systemPool } from '../config/main.js';
import { RateLimitService } from '../../services/RateLimitService.js';
import { quoteId } from '../utils/index.js';

export class SecurityController {
    
    // --- PANIC & STATUS ---
    // Fix: Use any for next parameter to resolve callable signature issues
    static async getStatus(req: CascataRequest, res: any, next: any) {
        try { const panicMode = await RateLimitService.checkPanic(req.project.slug); res.json({ current_rps: 0, panic_mode: panicMode }); } catch (e: any) { next(e); }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async togglePanic(req: CascataRequest, res: any, next: any) {
        try { 
            await RateLimitService.setPanic(req.project.slug, req.body.enabled); 
            await systemPool.query("UPDATE system.projects SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{security,panic_mode}', $1) WHERE slug = $2", [JSON.stringify(req.body.enabled), req.project.slug]); 
            res.json({ success: true, panic_mode: req.body.enabled }); 
        } catch (e: any) { next(e); }
    }

    // --- RATE LIMITS ---
    // Fix: Use any for next parameter to resolve callable signature issues
    static async listRateLimits(req: CascataRequest, res: any, next: any) {
        try { const result = await systemPool.query('SELECT * FROM system.rate_limits WHERE project_slug = $1 ORDER BY created_at DESC', [req.project.slug]); res.json(result.rows); } catch (e: any) { next(e); }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async createRateLimit(req: CascataRequest, res: any, next: any) {
        const { route_pattern, method, rate_limit, burst_limit, window_seconds, message_anon, message_auth } = req.body;
        try { 
            const result = await systemPool.query("INSERT INTO system.rate_limits (project_slug, route_pattern, method, rate_limit, burst_limit, window_seconds, message_anon, message_auth) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (project_slug, route_pattern, method) DO UPDATE SET rate_limit = EXCLUDED.rate_limit, burst_limit = EXCLUDED.burst_limit, window_seconds = EXCLUDED.window_seconds, message_anon = EXCLUDED.message_anon, message_auth = EXCLUDED.message_auth, updated_at = NOW() RETURNING *", [req.project.slug, route_pattern, method, rate_limit, burst_limit, window_seconds || 1, message_anon, message_auth]); 
            RateLimitService.clearRules(req.project.slug); 
            res.json(result.rows[0]); 
        } catch (e: any) { next(e); }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async deleteRateLimit(req: CascataRequest, res: any, next: any) {
        try { 
            await systemPool.query('DELETE FROM system.rate_limits WHERE id = $1 AND project_slug = $2', [req.params.id, req.project.slug]); 
            RateLimitService.clearRules(req.project.slug); 
            res.json({ success: true }); 
        } catch (e: any) { next(e); }
    }

    // --- RLS POLICIES ---
    // Fix: Use any for next parameter to resolve callable signature issues
    static async listPolicies(req: CascataRequest, res: any, next: any) {
        try { const result = await req.projectPool!.query("SELECT * FROM pg_policies"); res.json(result.rows); } catch (e: any) { next(e); }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async createPolicy(req: CascataRequest, res: any, next: any) {
        const { name, table, command, role, using, withCheck } = req.body;
        try { 
            await req.projectPool!.query(`CREATE POLICY ${quoteId(name)} ON public.${quoteId(table)} FOR ${command} TO ${role} USING (${using}) ${withCheck ? `WITH CHECK (${withCheck})` : ''}`); 
            res.json({ success: true }); 
        } catch (e: any) { next(e); }
    }

    // Fix: Use any for next parameter to resolve callable signature issues
    static async deletePolicy(req: CascataRequest, res: any, next: any) {
        try { await req.projectPool!.query(`DROP POLICY ${quoteId(req.params.name)} ON public.${quoteId(req.params.table)}`); res.json({ success: true }); } catch (e: any) { next(e); }
    }

    // --- LOGS ---
    // Fix: Use any for next parameter to resolve callable signature issues
    static async getLogs(req: CascataRequest, res: any, next: any) {
        try { const result = await systemPool.query('SELECT * FROM system.api_logs WHERE project_slug = $1 ORDER BY created_at DESC LIMIT 100', [req.project.slug]); res.json(result.rows); } catch (e: any) { next(e); }
    }
}
