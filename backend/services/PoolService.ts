import pg from 'pg';
const { Pool } = pg;

export interface PoolConfig {
  max?: number;
  idleTimeoutMillis?: number;
  connectionTimeoutMillis?: number;
  statementTimeout?: number;
  useDirect?: boolean; // Novo: Forçar conexão direta para tarefas administrativas
}

interface PoolEntry {
    pool: pg.Pool;
    lastAccessed: number;
    activeConnections: number;
}

/**
 * PoolService v3.1 (PgBouncer Optimized)
 * Gerencia conexões otimizadas para alta escala com suporte a SCRAM-SHA-256 e KeepAlive.
 */
export class PoolService {
  private static pools = new Map<string, PoolEntry>();
  private static REAPER_INTERVAL_MS = 60 * 60 * 1000;
  private static IDLE_THRESHOLD_MS = 2 * 60 * 60 * 1000;
  
  private static GLOBAL_CONNECTION_CAP = 200; // Aumentado graças ao PgBouncer
  private static DEFAULT_STATEMENT_TIMEOUT = 15000; 

  public static configure(config: { maxConnections?: number, idleTimeout?: number, statementTimeout?: number }) {
      if (config.maxConnections) {
          this.GLOBAL_CONNECTION_CAP = config.maxConnections;
      }
      if (config.statementTimeout) {
          this.DEFAULT_STATEMENT_TIMEOUT = config.statementTimeout;
      }
  }

  public static initReaper() {
      setInterval(() => {
          this.reapZombies();
      }, this.REAPER_INTERVAL_MS);
      console.log('[PoolService] Reaper initialized.');
  }

  public static getTotalAllocatedConnections(): number {
      let total = 0;
      this.pools.forEach(entry => total += entry.activeConnections);
      return total;
  }

  private static reapZombies(forceRelease: number = 0) {
      const now = Date.now();
      let closedCount = 0;
      let releasedConnections = 0;
      const entries = Array.from(this.pools.entries()).sort((a, b) => a[1].lastAccessed - b[1].lastAccessed);

      for (const [key, entry] of entries) {
          const isIdle = (now - entry.lastAccessed > this.IDLE_THRESHOLD_MS);
          if (isIdle || (forceRelease > 0 && releasedConnections < forceRelease)) {
              try {
                  entry.pool.end().catch(e => console.error(e));
                  this.pools.delete(key);
                  closedCount++;
                  releasedConnections += entry.activeConnections;
              } catch (e) {}
          }
      }
      if (closedCount > 0) console.log(`[PoolService] Reaped ${closedCount} pools.`);
  }

  public static get(dbName: string, config?: PoolConfig): pg.Pool {
    const key = `${dbName}_${config?.useDirect ? 'direct' : 'pool'}`;
    
    if (this.pools.has(key)) {
      const entry = this.pools.get(key)!;
      entry.lastAccessed = Date.now();
      return entry.pool;
    }

    const requestedMax = config?.max || 10;
    
    // Connection Cap Logic
    const currentTotal = this.getTotalAllocatedConnections();
    if (currentTotal + requestedMax > this.GLOBAL_CONNECTION_CAP) {
        this.reapZombies(requestedMax);
    }

    // --- INFRASTRUCTURE ROUTING ---
    // Se useDirect=true, vai direto no container 'db' (5432).
    // Se não, vai no 'pgbouncer' (6432) para escalar.
    const usePooler = !config?.useDirect;
    
    const host = usePooler ? (process.env.DB_POOL_HOST || 'pgbouncer') : (process.env.DB_DIRECT_HOST || 'db');
    const port = usePooler ? (process.env.DB_POOL_PORT || '6432') : (process.env.DB_DIRECT_PORT || '5432');
    
    const user = process.env.DB_USER || 'cascata_admin';
    const pass = process.env.DB_PASS || 'secure_pass';

    const dbUrl = `postgresql://${user}:${pass}@${host}:${port}/${dbName}`;

    const statementTimeout = config?.statementTimeout || this.DEFAULT_STATEMENT_TIMEOUT;

    // Identifica a conexão no pg_stat_activity
    const appName = `cascata-${process.env.SERVICE_MODE || 'api'}-${usePooler ? 'pool' : 'direct'}`;

    const poolConfig = {
      connectionString: dbUrl,
      max: requestedMax,
      idleTimeoutMillis: config?.idleTimeoutMillis || 60000,
      connectionTimeoutMillis: config?.connectionTimeoutMillis || 10000, // Aumentado para evitar timeouts prematuros no handshake
      keepAlive: true,
      application_name: appName,
      // SSL mode settings if needed in future, currently internal network is trusted
    };

    console.log(`[PoolService] Init ${key} -> ${host}:${port} (${appName})`);

    const pool = new Pool(poolConfig);

    // Apply Timeouts
    pool.on('connect', (client) => {
        client.query(`SET statement_timeout TO ${statementTimeout}`).catch(() => {});
    });

    pool.on('error', (err) => {
      console.error(`[PoolService] Error on ${key}:`, err.message);
    });

    this.pools.set(key, { 
        pool, 
        lastAccessed: Date.now(),
        activeConnections: requestedMax 
    });
    
    return pool;
  }

  public static async reload(dbName: string, config?: PoolConfig) {
      await this.close(dbName);
      this.get(dbName, config);
  }

  public static async close(dbName: string) {
    // Tenta fechar ambas as variantes (direct e pool)
    const keys = [`${dbName}_pool`, `${dbName}_direct`];
    for (const key of keys) {
        if (this.pools.has(key)) {
            try { await this.pools.get(key)!.pool.end(); } catch (e) {}
            this.pools.delete(key);
        }
    }
  }

  public static async closeAll() {
      const promises = Array.from(this.pools.keys()).map(key => {
          const entry = this.pools.get(key);
          return entry ? entry.pool.end() : Promise.resolve();
      });
      await Promise.all(promises);
      this.pools.clear();
  }
}
