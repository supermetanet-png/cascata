
import { Pool } from 'pg';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import crypto from 'crypto';

interface FcmConfig {
    project_id: string;
    client_email: string;
    private_key: string;
}

export class PushService {
    
    /**
     * Registra ou atualiza um dispositivo para um usuário.
     * Implementa lógica de Upsert e "Last Active".
     */
    public static async registerDevice(
        pool: Pool, 
        userId: string, 
        token: string, 
        platform: string = 'other',
        appVersion?: string
    ) {
        // Remove o token se ele já pertencia a OUTRO usuário (troca de conta no mesmo device)
        await pool.query(`DELETE FROM auth.user_devices WHERE token = $1 AND user_id != $2`, [token, userId]);

        // Upsert no device para o usuário atual
        await pool.query(`
            INSERT INTO auth.user_devices (user_id, token, platform, app_version, last_active_at, is_active)
            VALUES ($1, $2, $3, $4, NOW(), true)
            ON CONFLICT (user_id, token) 
            DO UPDATE SET 
                last_active_at = NOW(), 
                is_active = true,
                app_version = EXCLUDED.app_version,
                platform = EXCLUDED.platform
        `, [userId, token, platform, appVersion]);
        
        return { success: true };
    }

    /**
     * Remove um token específico (Logout)
     */
    public static async unregisterDevice(pool: Pool, token: string) {
        await pool.query(`DELETE FROM auth.user_devices WHERE token = $1`, [token]);
        return { success: true };
    }

    /**
     * Obtém um token de acesso OAuth2 para o FCM HTTP v1 API.
     * Fazemos isso manualmente para evitar a dependência gigante do 'googleapis'.
     */
    private static getAccessToken(config: FcmConfig): string {
        const now = Math.floor(Date.now() / 1000);
        const claim = {
            iss: config.client_email,
            scope: "https://www.googleapis.com/auth/firebase.messaging",
            aud: "https://oauth2.googleapis.com/token",
            exp: now + 3600,
            iat: now
        };

        return jwt.sign(claim, config.private_key, { algorithm: 'RS256' });
    }

    /**
     * Envia notificação para um usuário específico (Multicast para todos os seus devices).
     */
    public static async sendToUser(
        pool: Pool,
        systemPool: Pool, // Para logar histórico
        projectSlug: string,
        userId: string,
        notification: { title: string, body: string, image?: string, data?: any },
        fcmConfig: FcmConfig
    ) {
        // 1. Buscar devices ativos do usuário
        const devicesRes = await pool.query(
            `SELECT token, platform FROM auth.user_devices WHERE user_id = $1 AND is_active = true`,
            [userId]
        );

        if (devicesRes.rows.length === 0) return { success: false, reason: 'no_devices' };

        // 2. Preparar Autenticação Google
        // Para JWT do Google, precisamos trocar o JWT assinado por um Access Token real
        // Nota: Em produção de alta escala, devemos cachear este token.
        const signedJwt = this.getAccessToken(fcmConfig);
        
        const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion: signedJwt
        });
        const googleAccessToken = tokenRes.data.access_token;

        // 3. Disparar para cada device (FCM HTTP v1 não suporta multicast nativo num único request, tem que ser loop ou batch)
        // Usaremos Promise.all para paralelismo.
        const results = await Promise.all(devicesRes.rows.map(async (device) => {
            const messagePayload: any = {
                message: {
                    token: device.token,
                    notification: {
                        title: notification.title,
                        body: notification.body,
                        image: notification.image
                    },
                    data: notification.data || {}
                }
            };

            // Configurações Específicas por Plataforma (Opcional, mas recomendado para produção)
            if (device.platform === 'android') {
                messagePayload.message.android = { priority: 'high' };
            } else if (device.platform === 'ios') {
                messagePayload.message.apns = { payload: { aps: { contentAvailable: true } } };
            }

            try {
                const res = await axios.post(
                    `https://fcm.googleapis.com/v1/projects/${fcmConfig.project_id}/messages:send`,
                    messagePayload,
                    {
                        headers: {
                            'Authorization': `Bearer ${googleAccessToken}`,
                            'Content-Type': 'application/json'
                        }
                    }
                );
                return { token: device.token, status: 'sent', id: res.data.name };
            } catch (e: any) {
                // Self-Healing: Se o token for inválido, remova-o.
                if (e.response?.data?.error?.details?.[0]?.errorCode === 'UNREGISTERED' || 
                    e.response?.status === 404) {
                    await this.unregisterDevice(pool, device.token);
                    return { token: device.token, status: 'invalid_token_removed' };
                }
                return { token: device.token, status: 'error', error: e.message };
            }
        }));

        // 4. Logar Histórico (Resumido)
        const successCount = results.filter(r => r.status === 'sent').length;
        const failCount = results.length - successCount;

        await systemPool.query(
            `INSERT INTO system.notification_history (project_slug, user_id, status, provider_response)
             VALUES ($1, $2, $3, $4)`,
            [projectSlug, userId, failCount === 0 ? 'completed' : 'partial', JSON.stringify({ results })]
        );

        return { success: true, results };
    }

    /**
     * Método chamado pelo Trigger Engine quando um evento de banco ocorre.
     */
    public static async processEventTrigger(
        projectSlug: string,
        pool: Pool,
        systemPool: Pool,
        event: any, // Payload do notify_changes
        fcmCredentials: any // JSON do Firebase Service Account
    ) {
        if (!fcmCredentials) return; // Sem config, sem push.

        // 1. Buscar Regras para esta tabela e evento
        const rulesRes = await systemPool.query(
            `SELECT * FROM system.notification_rules 
             WHERE project_slug = $1 
             AND trigger_table = $2 
             AND (trigger_event = $3 OR trigger_event = 'ALL')
             AND active = true`,
            [projectSlug, event.table, event.action]
        );

        if (rulesRes.rows.length === 0) return;

        // 2. Processar cada regra
        // Precisamos dos dados da linha. O evento 'notify_changes' do Cascata só traz o ID.
        // É mais seguro buscar o registro atual no banco para garantir integridade e acesso aos dados completos para o template.
        let record: any = null;
        
        if (event.action !== 'DELETE') {
            const recRes = await pool.query(`SELECT * FROM public."${event.table}" WHERE id = $1`, [event.record_id]);
            record = recRes.rows[0];
        } else {
            // Em caso de DELETE, não temos o record. Push em DELETE normalmente usa dados antigos se disponíveis no payload, 
            // mas nosso trigger atual é leve. Para V1, ignoramos rules que dependem de dados do record em DELETE.
            return; 
        }

        if (!record) return;

        for (const rule of rulesRes.rows) {
            // 2.1 Verificar Condições (Filtro simples)
            if (rule.conditions && Array.isArray(rule.conditions)) {
                let match = true;
                for (const cond of rule.conditions) {
                    const val = record[cond.field];
                    if (cond.op === 'eq' && val != cond.value) match = false;
                    if (cond.op === 'neq' && val == cond.value) match = false;
                    // Adicionar mais ops conforme necessidade
                }
                if (!match) continue;
            }

            // 2.2 Identificar Destinatário
            // O campo recipient_column diz qual coluna tem o ID do usuário (ex: 'user_id' ou 'owner_id')
            const userId = record[rule.recipient_column];
            if (!userId) continue;

            // 2.3 Templating (Substituição de variáveis {{ variavel }})
            let title = rule.title_template;
            let body = rule.body_template;

            Object.keys(record).forEach(key => {
                const val = record[key] !== null ? String(record[key]) : '';
                title = title.replace(new RegExp(`{{${key}}}`, 'g'), val);
                body = body.replace(new RegExp(`{{${key}}}`, 'g'), val);
            });

            // 2.4 Enviar
            // Transformar credenciais JSON em config
            const fcmConfig: FcmConfig = {
                project_id: fcmCredentials.project_id,
                client_email: fcmCredentials.client_email,
                private_key: fcmCredentials.private_key
            };

            await this.sendToUser(pool, systemPool, projectSlug, userId, { title, body, data: rule.data_payload }, fcmConfig);
        }
    }
}
