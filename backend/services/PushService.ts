
import { Pool } from 'pg';
import jwt from 'jsonwebtoken';
import axios from 'axios';
import { QueueService } from './QueueService.js';

interface FcmConfig {
    project_id: string;
    client_email: string;
    private_key: string;
}

export class PushService {
    
    /**
     * Registra ou atualiza um dispositivo para um usuário.
     */
    public static async registerDevice(
        pool: Pool, 
        userId: string, 
        token: string, 
        platform: string = 'other',
        appVersion?: string
    ) {
        await pool.query(`DELETE FROM auth.user_devices WHERE token = $1 AND user_id != $2`, [token, userId]);

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

    public static async unregisterDevice(pool: Pool, token: string) {
        await pool.query(`DELETE FROM auth.user_devices WHERE token = $1`, [token]);
        return { success: true };
    }

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
     * PRODUCER: Enfileira o job de notificação.
     * Retorna imediatamente (Non-blocking).
     */
    public static async sendToUser(
        pool: Pool, // Used only to check connection params for the worker
        systemPool: Pool,
        projectSlug: string,
        userId: string,
        notification: { title: string, body: string, image?: string, data?: any },
        fcmConfig: FcmConfig,
        dbConnectionInfo?: { dbName: string, externalDbUrl?: string }
    ) {
        // Enfileira o Job no BullMQ (DragonflyDB)
        await QueueService.addPushJob({
            projectSlug,
            userId,
            notification,
            fcmConfig,
            dbName: dbConnectionInfo?.dbName || `cascata_db_${projectSlug.replace(/-/g, '_')}`, // Fallback prediction
            externalDbUrl: dbConnectionInfo?.externalDbUrl
        });

        return { success: true, status: 'queued' };
    }

    /**
     * CONSUMER: Executa o envio real para o Google FCM.
     * Chamado apenas pelo QueueService Worker.
     */
    public static async processDelivery(
        pool: Pool,
        systemPool: Pool,
        projectSlug: string,
        userId: string,
        notification: { title: string, body: string, image?: string, data?: any },
        fcmConfig: FcmConfig
    ) {
        // 1. Buscar devices ativos
        const devicesRes = await pool.query(
            `SELECT token, platform FROM auth.user_devices WHERE user_id = $1 AND is_active = true`,
            [userId]
        );

        if (devicesRes.rows.length === 0) return { success: false, reason: 'no_devices' };

        // 2. Auth Google
        const signedJwt = this.getAccessToken(fcmConfig);
        const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion: signedJwt
        });
        const googleAccessToken = tokenRes.data.access_token;

        // 3. Disparar (Batch logic handled by Promise.all for now)
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
                // Self-Healing
                if (e.response?.data?.error?.details?.[0]?.errorCode === 'UNREGISTERED' || 
                    e.response?.status === 404) {
                    await this.unregisterDevice(pool, device.token);
                    return { token: device.token, status: 'invalid_token_removed' };
                }
                return { token: device.token, status: 'error', error: e.message };
            }
        }));

        // 4. Log
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
     * Trigger Engine
     */
    public static async processEventTrigger(
        projectSlug: string,
        pool: Pool,
        systemPool: Pool,
        event: any,
        fcmCredentials: any,
        dbConnectionInfo?: { dbName: string, externalDbUrl?: string }
    ) {
        if (!fcmCredentials) return;

        const rulesRes = await systemPool.query(
            `SELECT * FROM system.notification_rules 
             WHERE project_slug = $1 
             AND trigger_table = $2 
             AND (trigger_event = $3 OR trigger_event = 'ALL')
             AND active = true`,
            [projectSlug, event.table, event.action]
        );

        if (rulesRes.rows.length === 0) return;

        let record: any = null;
        if (event.action !== 'DELETE') {
            const recRes = await pool.query(`SELECT * FROM public."${event.table}" WHERE id = $1`, [event.record_id]);
            record = recRes.rows[0];
        } else {
            return; 
        }

        if (!record) return;

        for (const rule of rulesRes.rows) {
            // Check Conditions
            if (rule.conditions && Array.isArray(rule.conditions)) {
                let match = true;
                for (const cond of rule.conditions) {
                    const val = record[cond.field];
                    // Simple logic engine
                    if (cond.op === 'eq' && val != cond.value) match = false;
                    if (cond.op === 'neq' && val == cond.value) match = false;
                }
                if (!match) continue;
            }

            const userId = record[rule.recipient_column];
            if (!userId) continue;

            let title = rule.title_template;
            let body = rule.body_template;

            Object.keys(record).forEach(key => {
                const val = record[key] !== null ? String(record[key]) : '';
                title = title.replace(new RegExp(`{{${key}}}`, 'g'), val);
                body = body.replace(new RegExp(`{{${key}}}`, 'g'), val);
            });

            const fcmConfig: FcmConfig = {
                project_id: fcmCredentials.project_id,
                client_email: fcmCredentials.client_email,
                private_key: fcmCredentials.private_key
            };

            // ASYNC CALL: Enqueues the job instead of waiting
            await this.sendToUser(pool, systemPool, projectSlug, userId, { title, body, data: rule.data_payload }, fcmConfig, dbConnectionInfo);
        }
    }
}
