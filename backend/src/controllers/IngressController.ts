
import { NextFunction } from 'express';
import { CascataRequest } from '../types.js';
import { systemPool } from '../config/main.js';
import { IngressService } from '../../services/IngressService.js';

export class IngressController {

    static async handleIncoming(req: CascataRequest, res: any, next: any) {
        const { routeSlug } = req.params;
        
        // Middleware resolves project, but TS needs assertion
        if (!req.project) {
            return res.status(404).json({ error: 'Project context not resolved' });
        }
        const projectSlug = req.project.slug;

        try {
            // SECURITY FIX: Use the raw body buffer captured by middleware for HMAC signature.
            // JSON.stringify re-ordering keys would break signatures from providers like Stripe/GitHub.
            const rawBody = (req as any).rawBody || JSON.stringify(req.body || {});

            const result = await IngressService.handleIngress(
                projectSlug, 
                routeSlug, 
                req, 
                rawBody, 
                systemPool
            );

            res.status(200).json(result);
        } catch (e: any) {
            // Retorna erro formatado para quem chamou (o Banco/Gateway externo precisa saber que falhou)
            const status = e.message.includes('not found') ? 404 : (e.message.includes('Access Denied') ? 403 : 500);
            
            // Log security incidents but sanitize internal errors
            if (status === 500) console.error(`[Ingress] Error processing ${routeSlug}:`, e);
            
            res.status(status).json({ error: e.message });
        }
    }
    
    // CRUD para o Painel (Control Plane)
    static async listHooks(req: CascataRequest, res: any, next: any) {
        if (!req.project) return res.status(404).json({ error: 'Project not found' });
        try {
            const result = await systemPool.query(
                'SELECT * FROM system.ingress_hooks WHERE project_slug = $1 ORDER BY created_at DESC', 
                [req.project.slug]
            );
            res.json(result.rows);
        } catch (e: any) { next(e); }
    }

    static async createHook(req: CascataRequest, res: any, next: any) {
        if (!req.project) return res.status(404).json({ error: 'Project not found' });
        const { name, route_slug, security_config, flow_definition } = req.body;
        try {
            const result = await systemPool.query(
                `INSERT INTO system.ingress_hooks (project_slug, name, route_slug, security_config, flow_definition) 
                 VALUES ($1, $2, $3, $4, $5) RETURNING *`,
                [req.project.slug, name, route_slug, JSON.stringify(security_config), JSON.stringify(flow_definition || [])]
            );
            res.json(result.rows[0]);
        } catch (e: any) { next(e); }
    }

    static async updateHook(req: CascataRequest, res: any, next: any) {
        if (!req.project) return res.status(404).json({ error: 'Project not found' });
        const { name, security_config, flow_definition, is_active } = req.body;
        try {
            const fields = [];
            const values = [];
            let idx = 1;

            if (name !== undefined) { fields.push(`name = $${idx++}`); values.push(name); }
            if (security_config !== undefined) { fields.push(`security_config = $${idx++}`); values.push(JSON.stringify(security_config)); }
            if (flow_definition !== undefined) { fields.push(`flow_definition = $${idx++}`); values.push(JSON.stringify(flow_definition)); }
            if (is_active !== undefined) { fields.push(`is_active = $${idx++}`); values.push(is_active); }

            if (fields.length === 0) return res.json({ success: true });

            values.push(req.params.id);
            values.push(req.project.slug);

            const query = `UPDATE system.ingress_hooks SET ${fields.join(', ')} WHERE id = $${idx++} AND project_slug = $${idx++} RETURNING *`;
            const result = await systemPool.query(query, values);
            res.json(result.rows[0]);
        } catch (e: any) { next(e); }
    }

    static async deleteHook(req: CascataRequest, res: any, next: any) {
        if (!req.project) return res.status(404).json({ error: 'Project not found' });
        try {
            await systemPool.query('DELETE FROM system.ingress_hooks WHERE id = $1 AND project_slug = $2', [req.params.id, req.project.slug]);
            res.json({ success: true });
        } catch (e: any) { next(e); }
    }
}
