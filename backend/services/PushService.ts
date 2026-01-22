
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
    
    public static async registerDevice(pool: Pool, userId: string, token: string, platform: string = 'other', appVersion?: string) {
        await pool.query(`DELETE FROM auth.user_devices WHERE token = $1 AND user_id != $2`, [token, userId]);
        await pool.query(`
            INSERT INTO auth.user_devices (user_id, token, platform, app_version, last_active_at, is_active)
            VALUES ($1, $2, $3, $4, NOW(), true)
            ON CONFLICT (user_id, token) 
            DO UPDATE SET last_active_at = NOW(), is_active = true, app_version = EXCLUDED.app_version
        `, [userId, token, platform, appVersion]);
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
     * PRODUCER: Adiciona na fila do DragonflyDB
     */
    public static async sendToUser(pool: Pool, systemPool: Pool, projectSlug: string, userId: string, notification: any, fcmConfig: FcmConfig) {
        // Encontra info do banco para o worker saber onde conectar
        const dbName = `cascata_db_${projectSlug.replace(/-/g, '_')}`;
        
        await QueueService.addPushJob({
            projectSlug,
            userId,
            notification,
            fcmConfig,
            dbName
        });

        return { success: true, status: 'queued' };
    }

    /**
     * CONSUMER: Processamento real executado pelo Worker
     */
    public static async processDelivery(pool: Pool, systemPool: Pool, projectSlug: string, userId: string, notification: any, fcmConfig: FcmConfig) {
        const devicesRes = await pool.query(`SELECT token, platform FROM auth.user_devices WHERE user_id = $1 AND is_active = true`, [userId]);
        if (devicesRes.rows.length === 0) return { success: false, reason: 'no_devices' };

        const signedJwt = this.getAccessToken(fcmConfig);
        const tokenRes = await axios.post('https://oauth2.googleapis.com/token', {
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion: signedJwt
        });
        const googleAccessToken = tokenRes.data.access_token;

        const results = await Promise.all(devicesRes.rows.map(async (device) => {
            const messagePayload = {
                message: {
                    token: device.token,
                    notification: { title: notification.title, body: notification.body },
                    data: notification.data || {}
                }
            };
            try {
                await axios.post(`https://fcm.googleapis.com/v1/projects/${fcmConfig.project_id}/messages:send`, messagePayload, {
                    headers: { 'Authorization': `Bearer ${googleAccessToken}` }
                });
                return { token: device.token, status: 'sent' };
            } catch (e: any) {
                if (e.response?.status === 404 || e.response?.status === 410) {
                    await pool.query(`DELETE FROM auth.user_devices WHERE token = $1`, [device.token]);
                }
                return { token: device.token, status: 'error' };
            }
        }));

        await systemPool.query(`INSERT INTO system.notification_history (project_slug, user_id, status, provider_response) VALUES ($1, $2, $3, $4)`, 
            [projectSlug, userId, 'completed', JSON.stringify({ results })]);

        return { success: true, results };
    }

    public static async processEventTrigger(projectSlug: string, pool: Pool, systemPool: Pool, event: any, fcmCredentials: any) {
        if (!fcmCredentials) return;

        const rulesRes = await systemPool.query(
            `SELECT * FROM system.notification_rules 
             WHERE project_slug = $1 AND trigger_table = $2 AND (trigger_event = $3 OR trigger_event = 'ALL') AND active = true`,
            [projectSlug, event.table, event.action]
        );

        if (rulesRes.rows.length === 0) return;

        const recRes = await pool.query(`SELECT * FROM public."${event.table}" WHERE id = $1`, [event.record_id]);
        const record = recRes.rows[0];
        if (!record) return;

        for (const rule of rulesRes.rows) {
            const userId = record[rule.recipient_column];
            if (!userId) continue;

            let title = rule.title_template;
            let body = rule.body_template;
            Object.keys(record).forEach(key => {
                const val = record[key] !== null ? String(record[key]) : '';
                title = title.replace(new RegExp(`{{${key}}}`, 'g'), val);
                body = body.replace(new RegExp(`{{${key}}}`, 'g'), val);
            });

            await this.sendToUser(pool, systemPool, projectSlug, userId, { title, body, data: rule.data_payload }, fcmCredentials);
        }
    }
}
