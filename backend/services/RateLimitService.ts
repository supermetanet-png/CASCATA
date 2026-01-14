
import { Redis } from 'ioredis';
import { Pool } from 'pg';

interface RateLimitRule {
    id: string;
    project_slug: string;
    route_pattern: string;
    method: string;
    rate_limit: number;
    burst_limit: number;
    window_seconds: number;
    message_anon?: string;
    message_auth?: string;
}

interface RateCheckResult {
    blocked: boolean;
    limit?: number;
    remaining?: number;
    retryAfter?: number;
    customMessage?: string;
}

export interface AuthSecurityConfig {
    max_attempts: number;      // Default: 5
    lockout_minutes: number;   // Default: 15
    strategy: 'ip' | 'email' | 'hybrid'; // Default: 'hybrid'
}

/**
 * RateLimitService
 * Implementa o algoritmo "Token Bucket" ou "Fixed Window" via Redis para controle de tráfego.
 * Também gerencia o "Panic Mode" e proteção contra Força Bruta.
 */
export class RateLimitService {
    private static redis: Redis | null = null;
    private static rulesCache = new Map<string, RateLimitRule[]>();
    private static isRedisHealthy = false;
    
    public static init() {
        try {
            this.redis = new Redis({
                host: process.env.REDIS_HOST || 'redis',
                port: parseInt(process.env.REDIS_PORT || '6379'),
                maxRetriesPerRequest: 1,
                retryStrategy: (times) => Math.min(times * 200, 5000), // Backoff suave
                enableOfflineQueue: false,
                lazyConnect: true 
            });
            
            this.redis.connect().catch((e: any) => console.warn("[RateLimit] Initial Redis connect failed (will retry):", e.message));

            this.redis.on('error', (err) => {
                this.isRedisHealthy = false;
                // Não logar stack trace completo em produção para erros de conexão repetitivos
            });
            
            this.redis.on('connect', () => {
                console.log('[RateLimit] Redis Connected & Healthy.');
                this.isRedisHealthy = true;
            });
        } catch (e) {
            console.error("[RateLimit] Fatal Redis Init Error:", e);
            this.redis = null;
        }
    }

    /**
     * Verifica se o Panic Mode está ativado para um projeto.
     * O Panic Mode bloqueia todas as requisições externas.
     */
    public static async checkPanic(slug: string): Promise<boolean> {
        if (!this.redis || !this.isRedisHealthy) return false; 
        try {
            const val = await this.redis.get(`panic:${slug}`);
            return val === 'true';
        } catch (e) {
            return false;
        }
    }

    /**
     * Ativa ou desativa o Panic Mode.
     */
    public static async setPanic(slug: string, state: boolean): Promise<void> {
        if (!this.redis || !this.isRedisHealthy) return;
        try {
            if (state) {
                await this.redis.set(`panic:${slug}`, 'true');
            } else {
                await this.redis.del(`panic:${slug}`);
            }
        } catch (e) {
            console.error("Redis Panic Set Error", e);
        }
    }

    // --- BRUTE FORCE PROTECTION (SMART LOCKOUT) ---

    private static getLockoutKeys(slug: string, ip: string, email?: string, strategy: 'ip' | 'email' | 'hybrid' = 'hybrid'): string[] {
        const keys: string[] = [];
        if (strategy === 'ip' || strategy === 'hybrid') {
            keys.push(`auth:lock:${slug}:ip:${ip}`);
        }
        if ((strategy === 'email' || strategy === 'hybrid') && email) {
            keys.push(`auth:lock:${slug}:email:${email.toLowerCase().trim()}`);
        }
        return keys;
    }

    private static getCounterKeys(slug: string, ip: string, email?: string, strategy: 'ip' | 'email' | 'hybrid' = 'hybrid'): string[] {
        const keys: string[] = [];
        if (strategy === 'ip' || strategy === 'hybrid') {
            keys.push(`auth:fail:${slug}:ip:${ip}`);
        }
        if ((strategy === 'email' || strategy === 'hybrid') && email) {
            keys.push(`auth:fail:${slug}:email:${email.toLowerCase().trim()}`);
        }
        return keys;
    }

    /**
     * Verifica se o usuário/IP está bloqueado antes de tentar login.
     */
    public static async checkAuthLockout(
        slug: string, 
        ip: string, 
        email?: string, 
        config: AuthSecurityConfig = { max_attempts: 5, lockout_minutes: 15, strategy: 'hybrid' }
    ): Promise<{ locked: boolean, reason?: string }> {
        if (!this.redis || !this.isRedisHealthy) return { locked: false };

        const lockKeys = this.getLockoutKeys(slug, ip, email, config.strategy);
        
        for (const key of lockKeys) {
            const isLocked = await this.redis.exists(key);
            if (isLocked) {
                return { locked: true, reason: 'Muitas tentativas falhas. Tente novamente em alguns minutos.' };
            }
        }
        return { locked: false };
    }

    /**
     * Registra uma falha de autenticação. Se exceder o limite, cria o bloqueio.
     */
    public static async registerAuthFailure(
        slug: string,
        ip: string,
        email?: string,
        config: AuthSecurityConfig = { max_attempts: 5, lockout_minutes: 15, strategy: 'hybrid' }
    ): Promise<void> {
        if (!this.redis || !this.isRedisHealthy) return;

        const counterKeys = this.getCounterKeys(slug, ip, email, config.strategy);
        const lockoutDurationSeconds = config.lockout_minutes * 60;
        const failureWindowSeconds = 3600; // 1 hora para acumular falhas

        for (const key of counterKeys) {
            const current = await this.redis.incr(key);
            
            // Define TTL na primeira falha
            if (current === 1) {
                await this.redis.expire(key, failureWindowSeconds);
            }

            if (current >= config.max_attempts) {
                // LOCKOUT TRIGGERED
                const lockKey = key.replace('auth:fail:', 'auth:lock:');
                await this.redis.set(lockKey, 'locked', 'EX', lockoutDurationSeconds);
                // Limpa o contador para reiniciar ciclo após lockout acabar
                await this.redis.del(key);
            }
        }
    }

    /**
     * Limpa contadores de falha após um login bem-sucedido.
     */
    public static async clearAuthFailure(
        slug: string, 
        ip: string, 
        email?: string
    ): Promise<void> {
        if (!this.redis || !this.isRedisHealthy) return;
        
        const keys = [
            `auth:fail:${slug}:ip:${ip}`,
            email ? `auth:fail:${slug}:email:${email.toLowerCase().trim()}` : null
        ].filter(Boolean) as string[];

        if (keys.length > 0) await this.redis.del(...keys);
    }

    // --- STANDARD API RATE LIMIT ---

    /**
     * Carrega regras customizadas do banco de dados (systemPool) para a memória.
     */
    public static async loadRules(projectSlug: string, systemPool: Pool) {
        try {
            const res = await systemPool.query(
                'SELECT * FROM system.rate_limits WHERE project_slug = $1', 
                [projectSlug]
            );
            this.rulesCache.set(projectSlug, res.rows);
        } catch (e) {
            console.warn(`[RateLimit] Failed to load rules for ${projectSlug} (DB busy?)`);
        }
    }

    /**
     * Verifica se uma requisição deve ser bloqueada.
     */
    public static async check(
        projectSlug: string, 
        path: string, 
        method: string, 
        userRole: string,
        ip: string,
        systemPool: Pool
    ): Promise<RateCheckResult> {
        if (!this.redis || !this.isRedisHealthy) return { blocked: false };
        
        if (!this.rulesCache.has(projectSlug)) {
            await this.loadRules(projectSlug, systemPool);
        }

        const rules = this.rulesCache.get(projectSlug) || [];
        
        // Encontra a regra mais específica (Pattern Matching simples)
        const matchedRule = rules.find((r) => {
            const methodMatch = r.method === 'ALL' || r.method === method;
            const rulePattern = r.route_pattern.replace('*', '');
            const pathMatch = r.route_pattern === '*' || path.startsWith(rulePattern);
            return methodMatch && pathMatch;
        });

        const limit = matchedRule ? matchedRule.rate_limit : 50; // Default 50 RPS
        const burst = matchedRule ? matchedRule.burst_limit : 50;
        const ruleId = matchedRule ? matchedRule.id : 'global';
        const windowSecs = matchedRule?.window_seconds || 1; 
        
        const key = `rate_limit:${projectSlug}:${ip}:${ruleId}`;

        try {
            const pipeline = this.redis.multi();
            pipeline.incr(key);
            pipeline.ttl(key);
            const results = await pipeline.exec();

            if (!results) throw new Error("Redis pipeline failed");

            const [incrErr, incrRes] = results[0];
            const [ttlErr, ttlRes] = results[1];

            if (incrErr) throw incrErr;

            const count = incrRes as number;
            const currentTtl = ttlRes as number;

            // Se for a primeira requisição, define o TTL (janela de tempo)
            if (currentTtl === -1) {
                await this.redis.expire(key, windowSecs);
            }

            const totalLimit = limit + burst;

            if (count > totalLimit) {
                let customMessage = undefined;
                if (matchedRule) {
                    if (userRole === 'anon' && matchedRule.message_anon) {
                        customMessage = matchedRule.message_anon;
                    } else if (userRole === 'authenticated' && matchedRule.message_auth) {
                        customMessage = matchedRule.message_auth;
                    }
                }
                
                const retryAfter = currentTtl > 0 ? currentTtl : windowSecs;
                return { blocked: true, limit, remaining: 0, retryAfter, customMessage };
            }

            return { blocked: false, limit, remaining: Math.max(0, totalLimit - count) };

        } catch (e) {
            // Fail open: Se o Redis falhar, permite o tráfego para não derrubar o serviço
            return { blocked: false };
        }
    }
    
    public static clearRules(slug: string) {
        this.rulesCache.delete(slug);
    }
}
