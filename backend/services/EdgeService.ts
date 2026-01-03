import ivm from 'isolated-vm';
import { Pool } from 'pg';
import crypto from 'crypto';
import { Buffer } from 'buffer';

export class EdgeService {
    
    /**
     * Executa uma função server-side (Edge Function) em um ambiente V8 ISOLADO.
     * Segurança: Usa isolated-vm para prevenir acesso ao process.env, fs e rede não autorizada.
     * 
     * @param code O código JS da função
     * @param context Objeto com dados da requisição (body, query, headers, user)
     * @param envVars Variáveis de ambiente configuradas para a função (Globais + Locais)
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
        
        // 1. Criação da Isolate (Heap separado, 256MB limite para "Power Mode")
        const isolate = new ivm.Isolate({ memoryLimit: 256 });
        const scriptContext = await isolate.createContext();
        const jail = scriptContext.global;

        try {
            // 2. Injeção de Globais Seguras
            await jail.set('global', jail.derefInto());
            
            // Console Proxy (Logs identificados)
            await jail.set('console', new ivm.Reference({
                log: new ivm.Callback((...args: any[]) => {
                    console.log(`[EDGE LOG]`, ...args);
                }),
                error: new ivm.Callback((...args: any[]) => {
                    console.error(`[EDGE ERR]`, ...args);
                }),
                warn: new ivm.Callback((...args: any[]) => {
                    console.warn(`[EDGE WARN]`, ...args);
                })
            }));

            // Injeta Variáveis de Ambiente (Secrets + Env)
            await jail.set('env', new ivm.ExternalCopy(envVars).copyInto());

            // Injeta Contexto da Requisição
            await jail.set('req', new ivm.ExternalCopy(context).copyInto());

            // --- POWER UPGRADES (Polyfills) ---

            // Crypto (UUID & Random)
            await jail.set('_crypto_proxy', new ivm.Reference({
                randomUUID: () => crypto.randomUUID(),
                randomBytes: (size: number) => {
                    const buf = crypto.randomBytes(size);
                    return new ivm.ExternalCopy(buf.toString('hex')).copyInto(); // Return hex for simplicity in sandbox
                }
            }));

            // Base64 Helpers (Nativos do Node, injetados para performance)
            await jail.set('_encoding_proxy', new ivm.Reference({
                btoa: (str: string) => Buffer.from(str).toString('base64'),
                atob: (str: string) => Buffer.from(str, 'base64').toString('binary')
            }));

            // 3. Helper de Banco de Dados (Proxy Assíncrono Seguro)
            await jail.set('db', new ivm.Reference({
                query: new ivm.Reference(async (sql: string, params: any[]) => {
                    const client = await projectPool.connect();
                    try {
                        const result = await client.query(sql, params);
                        // Serializa para garantir que tipos complexos (Date) passem pela barreira da VM
                        return new ivm.ExternalCopy(JSON.parse(JSON.stringify(result.rows))).copyInto();
                    } catch (e: any) {
                        throw new Error(e.message);
                    } finally {
                        client.release();
                    }
                })
            }));

            // Injeta fetch (Full Proxy)
            await jail.set('fetch', new ivm.Reference(async (url: string, initStr: any) => {
                let init = {};
                try { init = initStr ? JSON.parse(initStr) : {}; } catch(e) {}
                
                // Add Timeout controller for fetch
                const controller = new AbortController();
                const id = setTimeout(() => controller.abort(), timeoutMs - 500); // Abort slightly before VM kill

                try {
                    const response = await fetch(url, { ...init, signal: controller.signal });
                    clearTimeout(id);
                    
                    const text = await response.text();
                    const headers: Record<string, string> = {};
                    response.headers.forEach((v, k) => headers[k] = v);

                    return new ivm.ExternalCopy({
                        status: response.status,
                        statusText: response.statusText,
                        headers: headers,
                        text: text, // Pass raw text, let VM parse JSON
                    }).copyInto();
                } catch (e: any) {
                    clearTimeout(id);
                    throw new Error(`Fetch Error: ${e.message}`);
                }
            }));

            // 4. Compilação e Execução (Wrapper com Polyfills)
            const wrappedCode = `
                (async () => {
                    // --- POLYFILLS ---
                    const crypto = {
                        randomUUID: () => _crypto_proxy.applySync(undefined, [], { result: { copy: true } }),
                        randomHex: (size) => _crypto_proxy.applySync(undefined, ['randomBytes', size], { result: { copy: true } })
                    };
                    global.crypto = crypto;
                    
                    global.btoa = (s) => _encoding_proxy.applySync(undefined, ['btoa', s], { result: { copy: true } });
                    global.atob = (s) => _encoding_proxy.applySync(undefined, ['atob', s], { result: { copy: true } });

                    // DB Wrapper
                    const dbProxy = {
                        query: async (sql, params) => {
                            return await db.get('query').apply(undefined, [sql, params || []], { arguments: { copy: true }, result: { promise: true } });
                        }
                    };
                    
                    // Fetch Wrapper
                    const fetchProxy = async (url, init) => {
                        // Serialize init to pass simple object
                        const initStr = init ? JSON.stringify(init) : undefined;
                        const res = await fetch.apply(undefined, [url, initStr], { arguments: { copy: true }, result: { promise: true } });
                        return {
                            status: res.status,
                            statusText: res.statusText,
                            headers: res.headers,
                            text: async () => res.text,
                            json: async () => JSON.parse(res.text)
                        };
                    };

                    // Expose to User Scope
                    const userDb = dbProxy; // Legacy compat
                    const $db = dbProxy;    // Modern alias
                    const $fetch = fetchProxy; 
                    
                    // User Code Execution Container
                    const runUserCode = async () => {
                        // User script defines 'export default async function(req) { ... }' or just executes
                        // We support a simple 'return' style or module style simulation
                        const module = { exports: {} };
                        const exports = module.exports;
                        
                        ${code}

                        if (module.exports && typeof module.exports.default === 'function') {
                            return await module.exports.default(req);
                        }
                        // Fallback for simple scripts returning raw
                        return module.exports;
                    };

                    try {
                        const result = await runUserCode();
                        return JSON.stringify(result === undefined ? null : result);
                    } catch (e) {
                        return JSON.stringify({ error: e.message, stack: e.stack, isError: true });
                    }
                })()
            `;

            const script = await isolate.compileScript(wrappedCode);
            
            const resultStr = await script.run(scriptContext, { 
                timeout: timeoutMs,
                promise: true 
            });

            // Clean parsing
            let result;
            try {
                result = JSON.parse(resultStr);
            } catch (e) {
                // If user code returned a non-JSON primitive string, handle gracefully
                result = resultStr; 
            }

            if (result && result.isError) {
                return { status: 500, body: { error: result.error, stack: result.stack } };
            }

            return {
                status: 200,
                body: result
            };

        } catch (e: any) {
            console.error("Edge Execution Security Error:", e.message);
            
            if (e.message.includes('isolate is disposed')) {
                return { status: 504, body: { error: `Execution Timed Out (Limit: ${timeoutMs / 1000}s)` } };
            }
            if (e.message.includes('memory limit')) {
                return { status: 507, body: { error: "Memory Limit Exceeded (256MB)" } };
            }
            
            return { status: 500, body: { error: `Runtime Error: ${e.message}` } };
        } finally {
            try {
                scriptContext.release();
                if (!isolate.isDisposed) isolate.dispose();
            } catch(cleanupErr) { /* ignore cleanup errors */ }
        }
    }
}