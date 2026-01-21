import pg from 'pg';
const { Pool } = pg;

export interface PoolConfig {
  max?: number;
  idleTimeoutMillis?: number;
  connectionTimeoutMillis?: number;
  statementTimeout?: number;
  useDirect?: boolean; // Força conexão direta (bypass PgBouncer)
  connectionString?: string; // NOVO: Permite conexão externa (RDS, VPS Dedicada)
}

interface PoolEntry {
    pool: pg.Pool;
    lastAccessed: number;
    activeConnections: number;
    isExternal: boolean;
}

/**
 * PoolService v4.0 (Elite Scaling Edition)
 * Suporta:
 * 1. Conexões Internas (PgBouncer)
 * 2. Conexões Externas (Project Ejection / BYOD)
 * 3. Gerenciamento LRU estrito para milhares de tenants.
 */
export class PoolService {
  private static pools = new Map<string, PoolEntry>();
  private static REAPER_INTERVAL_MS = 30 * 1000; // Check a cada 30s
  private static IDLE_THRESHOLD_MS = 5 * 60 * 1000; // 5 minutos de inatividade
  
  // Limite global de pools simultâneos na memória do Node.js
  // Se passar disso, fechamos os mais antigos (LRU) mesmo que não estejam expirados.
  private static MAX_ACTIVE_POOLS = 500; 
  private static DEFAULT_STATEMENT_TIMEOUT = 15000; 

  public static configure(config: { maxConnections?: number, idleTimeout?: number, statementTimeout?: number }) {
      if (config.statementTimeout) {
          this.DEFAULT_STATEMENT_TIMEOUT = config.statementTimeout;
      }
      // Nota: maxConnections global é tratado pelo PgBouncer, aqui controlamos objetos Pool na memória
  }

  public static initReaper() {
      setInterval(() => {
          this.reapZombies();
      }, this.REAPER_INTERVAL_MS);
      console.log('[PoolService] Smart Reaper initialized.');
  }

  public static getTotalActivePools(): number {
      return this.pools.size;
  }

  /**
   * Remove pools inativos ou força remoção se estivermos acima do limite de memória (LRU).
   */
  private static reapZombies() {
      const now = Date.now();
      let closedCount = 0;
      
      // Ordena por último acesso (LRU)
      const entries = Array.from(this.pools.entries()).sort((a, b) => a[1].lastAccessed - b[1].lastAccessed);

      // 1. Remove expirados por tempo
      for (const [key, entry] of entries) {
          if (now - entry.lastAccessed > this.IDLE_THRESHOLD_MS) {
              this.gracefulClose(key, entry);
              closedCount++;
          }
      }

      // 2. Hard Cap: Se ainda tiver muitos pools, fecha os mais antigos
      if (this.pools.size > this.MAX_ACTIVE_POOLS) {
          const toRemove = this.pools.size - this.MAX_ACTIVE_POOLS;
          console.warn(`[PoolService] Hard Cap Reached (${this.pools.size}). Ejecting ${toRemove} oldest pools.`);
          
          // Recalcula entries pois alguns podem ter sido removidos no passo 1
          const remainingEntries = Array.from(this.pools.entries()).sort((a, b) => a[1].lastAccessed - b[1].lastAccessed);
          
          for (let i = 0; i < toRemove; i++) {
              if (remainingEntries[i]) {
                  this.gracefulClose(remainingEntries[i][0], remainingEntries[i][1]);
                  closedCount++;
              }
          }
      }

      if (closedCount > 0) console.log(`[PoolService] Reaped ${closedCount} pools.`);
  }

  private static gracefulClose(key: string, entry: PoolEntry) {
      try {
          entry.pool.end().catch(e => console.error(`[PoolService] Error closing ${key}:`, e.message));
          this.pools.delete(key);
      } catch (e) {}
  }

  /**
   * Obtém ou cria um Pool de conexões.
   * Suporta lógica de "Project Ejection" via connectionString explícita.
   */
  public static get(dbIdentifier: string, config?: PoolConfig): pg.Pool {
    // Se connectionString for fornecida, usamos ela como parte da chave única
    // Isso permite múltiplos pools para o mesmo projeto (ex: Read Replica vs Write Master)
    const uniqueKey = config?.connectionString 
        ? `ext_${dbIdentifier}_${Buffer.from(config.connectionString).toString('base64').slice(0, 10)}`
        : `${dbIdentifier}_${config?.useDirect ? 'direct' : 'pool'}`;
    
    if (this.pools.has(uniqueKey)) {
      const entry = this.pools.get(uniqueKey)!;
      entry.lastAccessed = Date.now();
      return entry.pool;
    }

    // --- CONSTRUÇÃO DA URL ---
    let dbUrl: string;
    let isExternal = false;

    if (config?.connectionString) {
        // MODO BYOD: Banco Externo (RDS, Supabase, VPS Dedicada)
        dbUrl = config.connectionString;
        isExternal = true;
    } else {
        // MODO NATIVO: Infraestrutura Interna
        const usePooler = !config?.useDirect;
        const host = usePooler ? (process.env.DB_POOL_HOST || 'pgbouncer') : (process.env.DB_DIRECT_HOST || 'db');
        const port = usePooler ? (process.env.DB_POOL_PORT || '6432') : (process.env.DB_DIRECT_PORT || '5432');
        const user = process.env.DB_USER || 'cascata_admin';
        const pass = process.env.DB_PASS || 'secure_pass';
        dbUrl = `postgresql://${user}:${pass}@${host}:${port}/${dbIdentifier}`;
    }

    const requestedMax = config?.max || 10;
    const statementTimeout = config?.statementTimeout || this.DEFAULT_STATEMENT_TIMEOUT;
    const appName = `cascata-${process.env.SERVICE_MODE || 'api'}-${isExternal ? 'ext' : 'int'}`;

    // Configuração Otimizada do Pool
    const poolConfig = {
      connectionString: dbUrl,
      max: requestedMax,
      idleTimeoutMillis: config?.idleTimeoutMillis || 60000,
      connectionTimeoutMillis: config?.connectionTimeoutMillis || 5000, // Fail fast
      keepAlive: true,
      application_name: appName,
      ssl: isExternal ? { rejectUnauthorized: false } : false // Auto-enable SSL para externos
    };

    console.log(`[PoolService] Init ${uniqueKey} (${appName})`);

    const pool = new Pool(poolConfig);

    // Hardening de Sessão
    pool.on('connect', (client) => {
        client.query(`SET statement_timeout TO ${statementTimeout}`).catch(() => {});
    });

    pool.on('error', (err) => {
      console.error(`[PoolService] Error on ${uniqueKey}:`, err.message);
      // Se o banco cair, removemos do cache para forçar reconexão limpa na próxima
      if (this.pools.has(uniqueKey)) {
          this.pools.delete(uniqueKey);
      }
    });

    this.pools.set(uniqueKey, { 
        pool, 
        lastAccessed: Date.now(),
        activeConnections: requestedMax,
        isExternal
    });
    
    // Trigger Reaper se estivermos no limite
    if (this.pools.size > this.MAX_ACTIVE_POOLS) {
        this.reapZombies();
    }
    
    return pool;
  }

  public static async reload(dbName: string) {
      await this.close(dbName);
      // O próximo .get() recriará o pool
  }

  public static async close(dbIdentifier: string) {
    // Fecha todas as variantes conhecidas
    const keys = Array.from(this.pools.keys()).filter(k => k.includes(dbIdentifier));
    for (const key of keys) {
        const entry = this.pools.get(key);
        if (entry) {
            try { await entry.pool.end(); } catch (e) {}
            this.pools.delete(key);
        }
    }
  }

  public static async closeAll() {
      const promises = Array.from(this.pools.values()).map(entry => entry.pool.end().catch(() => {}));
      await Promise.all(promises);
      this.pools.clear();
  }
}