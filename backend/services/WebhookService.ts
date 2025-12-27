import { Pool } from 'pg';
import crypto from 'crypto';

interface WebhookPayload {
    event_type: 'INSERT' | 'UPDATE' | 'DELETE';
    table: string;
    schema: string;
    record: any;
    old_record?: any;
    timestamp: string;
}

export class WebhookService {
    
    /**
     * Dispara webhooks configurados para um evento específico.
     * @param projectSlug O slug do projeto
     * @param tableName Nome da tabela afetada
     * @param eventType Tipo do evento
     * @param payload Dados do registro
     * @param systemPool Pool de conexão do sistema (para buscar configs)
     * @param projectSecret Chave JWT do projeto (usada para assinar o payload se não houver secret específico)
     */
    public static async dispatch(
        projectSlug: string,
        tableName: string,
        eventType: string,
        payloadData: any,
        systemPool: Pool,
        projectSecret: string
    ) {
        // Executa em background para não travar a resposta da API (Fire-and-forget)
        setImmediate(async () => {
            try {
                // 1. Buscar webhooks ativos para este projeto e tabela
                const res = await systemPool.query(
                    `SELECT target_url, secret_header, event_type 
                     FROM system.webhooks 
                     WHERE project_slug = $1 
                     AND is_active = true 
                     AND (table_name = '*' OR table_name = $2)
                     AND (event_type = '*' OR event_type = $3)`,
                    [projectSlug, tableName, eventType]
                );

                if (res.rows.length === 0) return;

                const fullPayload: WebhookPayload = {
                    event_type: eventType as any,
                    table: tableName,
                    schema: 'public',
                    record: payloadData,
                    timestamp: new Date().toISOString()
                };

                // 2. Disparar para cada target
                const promises = res.rows.map(async (hook) => {
                    const signature = crypto
                        .createHmac('sha256', hook.secret_header || projectSecret)
                        .update(JSON.stringify(fullPayload))
                        .digest('hex');

                    try {
                        const response = await fetch(hook.target_url, {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                                'X-Cascata-Signature': signature,
                                'X-Cascata-Event': eventType,
                                'X-Cascata-Table': tableName,
                                'User-Agent': 'Cascata-Webhook-Engine/1.0'
                            },
                            body: JSON.stringify(fullPayload)
                        });

                        if (!response.ok) {
                            console.warn(`[Webhook] Failed to deliver to ${hook.target_url}: ${response.status}`);
                        }
                    } catch (err: any) {
                        console.error(`[Webhook] Network error for ${hook.target_url}: ${err.message}`);
                    }
                });

                await Promise.all(promises);

            } catch (e) {
                console.error('[WebhookService] Dispatch Error:', e);
            }
        });
    }
}