
import pg from 'pg';
const { Pool } = pg;

export interface PoolConfig {
  max?: number;
  idleTimeoutMillis?: number;
  connectionTimeoutMillis?: number;
}

/**
 * PoolService
 * Responsável por gerenciar o ciclo de vida das conexões com bancos de dados de projetos (Tenants).
 * Mantém um cache de pools ativos para evitar overhead de conexão (handshake SSL/TCP) a cada requisição.
 */
export class PoolService {
  private static pools = new Map<string, pg.Pool>();

  /**
   * Obtém um pool de conexão para um banco de dados específico.
   * Se o pool já existir, retorna a instância em cache.
   * Se não, cria uma nova conexão com as configurações fornecidas.
   * 
   * @param dbName Nome do banco de dados do projeto (ex: cascata_proj_xyz)
   * @param config Configurações opcionais de performance (max connections, timeout)
   */
  public static get(dbName: string, config?: PoolConfig): pg.Pool {
    if (this.pools.has(dbName)) {
      // TODO: Futuramente implementar lógica para recriar pool se a config mudar drasticamente
      return this.pools.get(dbName)!;
    }

    const baseUrl = process.env.SYSTEM_DATABASE_URL || '';
    let dbUrl = '';
    
    // Tratamento robusto para connection strings
    if (baseUrl.includes(' ')) {
       throw new Error("Invalid connection string format in env SYSTEM_DATABASE_URL");
    } else {
       // Substitui o nome do banco na URL de conexão
       dbUrl = baseUrl.replace(/\/[^\/?]+(\?.*)?$/, `/${dbName}$1`);
    }

    const poolConfig = {
      connectionString: dbUrl,
      max: config?.max || 15, // Default: 15 conexões
      idleTimeoutMillis: config?.idleTimeoutMillis || 120000, // Default: 2 minutos
      connectionTimeoutMillis: config?.connectionTimeoutMillis || 5000, // Default: 5s
    };

    console.log(`[PoolService] Initializing pool for ${dbName} (Max: ${poolConfig.max}, Idle: ${poolConfig.idleTimeoutMillis}ms)`);

    const pool = new Pool(poolConfig);

    pool.on('error', (err) => {
      console.error(`[PoolService] Erro inesperado no banco ${dbName}:`, err.message);
      // Se o erro for fatal, removemos do cache para forçar reconexão na próxima chamada
      this.pools.delete(dbName);
    });

    this.pools.set(dbName, pool);
    return pool;
  }

  /**
   * Encerra um pool de conexão e o remove do cache.
   * Deve ser chamado quando um projeto é excluído ou pausado.
   */
  public static async close(dbName: string) {
    if (this.pools.has(dbName)) {
      console.log(`[PoolService] Closing pool for ${dbName}`);
      try {
        await this.pools.get(dbName)?.end();
      } catch (e) {
        console.warn(`[PoolService] Error closing pool ${dbName}`, e);
      }
      this.pools.delete(dbName);
    }
  }

  /**
   * Encerra todos os pools ativos. Útil para Graceful Shutdown do servidor.
   */
  public static async closeAll() {
      const promises = Array.from(this.pools.keys()).map(key => this.close(key));
      await Promise.all(promises);
  }
}
