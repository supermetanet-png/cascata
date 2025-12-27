import vm from 'vm';
import { Pool } from 'pg';

export class EdgeService {
    
    /**
     * Executa uma função server-side (Edge Function) em um ambiente sandbox.
     * 
     * @param code O código JS da função
     * @param context Objeto com dados da requisição (body, query, headers, user)
     * @param envVars Variáveis de ambiente configuradas para a função
     * @param projectPool Pool de conexão do projeto (para permitir acesso ao banco)
     * @param timeoutMs Tempo limite de execução em milissegundos
     */
    public static async execute(
        code: string,
        context: any,
        envVars: Record<string, string>,
        projectPool: Pool,
        timeoutMs: number = 5000
    ): Promise<{ status: number, body: any }> {
        
        // 1. Prepare Sandbox Environment
        // ATENÇÃO: 'vm' não é uma sandbox de segurança completa.
        // TODO: Migrar para 'isolated-vm' na fase de Hardening.
        const sandbox = {
            req: context,
            res: {
                status: 200,
                body: null,
                json: (data: any) => { sandbox.res.body = data; },
                send: (data: any) => { sandbox.res.body = data; },
                setStatus: (code: number) => { sandbox.res.status = code; }
            },
            env: envVars,
            console: {
                log: (...args: any[]) => console.log(`[EDGE LOG]`, ...args),
                error: (...args: any[]) => console.error(`[EDGE ERR]`, ...args),
            },
            fetch: global.fetch, // Permite chamadas HTTP externas
            
            // Helper de Banco de Dados (Limitado)
            db: {
                query: async (sql: string, params: any[] = []) => {
                    // CUIDADO: Pool Exhaustion Risk
                    // Na próxima fase, adicionar Circuit Breaker aqui
                    const client = await projectPool.connect();
                    try {
                        const result = await client.query(sql, params);
                        return result.rows;
                    } finally {
                        client.release();
                    }
                }
            }
        };

        vm.createContext(sandbox);

        // 2. Wrap Code (Async IIFE)
        const wrappedCode = `
            (async () => {
                try {
                    ${code}
                } catch(e) {
                    res.setStatus(500);
                    res.json({ error: e.message });
                }
            })();
        `;

        // 3. Execute
        const script = new vm.Script(wrappedCode);
        await script.runInContext(sandbox, {
            timeout: timeoutMs,
            displayErrors: true
        });

        // 4. Wait for Async Result (Polling Simples)
        // Como o vm.runInContext não espera promises pendentes criadas dentro dele,
        // precisamos verificar se o usuário chamou res.json() ou res.send().
        let waited = 0;
        while (sandbox.res.body === null && waited < timeoutMs) {
            await new Promise(r => setTimeout(r, 50));
            waited += 50;
        }

        return {
            status: sandbox.res.status,
            body: sandbox.res.body || { error: "Function timed out or returned no data" }
        };
    }
}