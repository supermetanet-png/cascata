
import { Queue, Worker, Job } from 'bullmq';
import crypto from 'crypto';
import axios from 'axios';
import { URL } from 'url';
import dns from 'dns/promises';
import { PushService } from './PushService.js';
import { systemPool } from '../config/main.js';
import { PoolService } from './PoolService.js';

const REDIS_CONFIG = {
    connection: {
        host: process.env.REDIS_HOST || 'dragonfly',
        port: parseInt(process.env.REDIS_PORT || '6379')
    }
};

export class QueueService {
    private static webhookQueue: Queue;
    private static webhookWorker: Worker;
    
    private static pushQueue: Queue;
    private static pushWorker: Worker;

    // SSRF Protection (Security)
    private static isPrivateIP(ip: string): boolean {
        if (ip.includes('.')) {
            const parts = ip.split('.').map(Number);
            if (parts.length !== 4) return false; 
            if (parts[0] === 0) return true;
            if (parts[0] === 10) return true;
            if (parts[0] === 127) return true;
            if (parts[0] === 169 && parts[1] === 254) return true;
            if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
            if (parts[0] === 192 && parts[1] === 168) return true;
        } 
        else if (ip.includes(':')) {
            if (ip === '::1' || ip === '::') return true;
            if (ip.toLowerCase().startsWith('fc') || ip.toLowerCase().startsWith('fd')) return true;
            if (ip.toLowerCase().startsWith('fe80')) return true;
        }
        return false;
    }

    private static async validateTarget(targetUrl: string): Promise<void> {
        try {
            const url = new URL(targetUrl);
            const hostname = url.hostname;

            if (hostname === 'localhost' || hostname === '::1' || hostname === '0.0.0.0') {
                throw new Error("Blocked: localhost access denied");
            }
            
            const internalServices = ['redis', 'db', 'backend_control', 'backend_data', 'nginx', 'nginx_controller', 'dragonfly'];
            if (internalServices.includes(hostname)) {
                throw new Error("Blocked: Internal service access denied");
            }

            let ips: string[] = [];
            const isIp = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname) || hostname.includes(':');
            
            if (isIp) {
                ips = [hostname];
            } else {
                try {
                    const records = await dns.lookup(hostname, { all: true });
                    ips = records.map(r => r.address);
                } catch (e) {
                    throw new Error(`DNS Resolution failed for ${hostname}`);
                }
            }

            for (const ip of ips) {
                if (this.isPrivateIP(ip)) {
                    throw new Error(`Security Violation: Host ${hostname} resolves to private IP ${ip}. Webhook blocked.`);
                }
            }

        } catch (e: any) {
            throw new Error(`SSRF Protection: ${e.message}`);
        }
    }

    public static init() {
        console.log('[QueueService] Initializing BullMQ Queues (DragonflyDB)...');

        // --- 1. WEBHOOK QUEUE ---
        this.webhookQueue = new Queue('cascata-webhooks', {
            ...REDIS_CONFIG,
            defaultJobOptions: {
                removeOnComplete: { age: 3600 * 24, count: 1000 },
                removeOnFail: { age: 3600 * 24 * 7, count: 5000 }
            }
        });

        this.webhookWorker = new Worker('cascata-webhooks', async (job: Job) => {
            const { targetUrl, payload, secret, eventType, tableName, fallbackUrl } = job.data;
            
            await this.validateTarget(targetUrl);

            const signature = crypto
                .createHmac('sha256', secret)
                .update(JSON.stringify(payload))
                .digest('hex');

            try {
                console.log(`[Queue:Webhook] Processing job ${job.id} -> ${targetUrl}`);
                
                await axios.post(targetUrl, payload, {
                    headers: {
                        'Content-Type': 'application/json',
                        'X-Cascata-Signature': signature,
                        'X-Cascata-Event': eventType,
                        'X-Cascata-Table': tableName,
                        'User-Agent': 'Cascata-Webhook-Engine/2.2'
                    },
                    timeout: 10000 
                });
                
                return { status: 'sent', timestamp: new Date() };

            } catch (error: any) {
                const isLastAttempt = job.attemptsMade >= (job.opts.attempts || 1) - 1;
                const errorMsg = error.response ? `HTTP ${error.response.status}: ${JSON.stringify(error.response.data)}` : error.message;

                console.error(`[Queue:Webhook] Failed job ${job.id}: ${errorMsg}`);

                if (isLastAttempt && fallbackUrl) {
                    try {
                        await this.validateTarget(fallbackUrl);
                        await axios.post(fallbackUrl, {
                            alert: "Webhook Delivery Failed (Final)",
                            original_target: targetUrl,
                            error: errorMsg,
                            event: eventType
                        }, { timeout: 5000 });
                    } catch (fbError) { /* ignore */ }
                }
                throw error; 
            }
        }, REDIS_CONFIG);

        // --- 2. PUSH NOTIFICATION QUEUE (NEW) ---
        this.pushQueue = new Queue('cascata-push', {
            ...REDIS_CONFIG,
            defaultJobOptions: {
                removeOnComplete: 100, // Keep last 100
                removeOnFail: 500
            }
        });

        this.pushWorker = new Worker('cascata-push', async (job: Job) => {
            const { projectSlug, userId, notification, fcmConfig, dbName, externalDbUrl } = job.data;
            
            try {
                console.log(`[Queue:Push] Processing push for User ${userId} (Project: ${projectSlug})`);
                
                // Get Pool dynamically inside the worker
                // NOTE: In strict microservices, Workers might not have direct DB access, 
                // but Cascata is a Monolith/Hybrid, so we share the PoolService.
                const pool = PoolService.get(dbName, { connectionString: externalDbUrl });

                const result = await PushService.processDelivery(
                    pool,
                    systemPool,
                    projectSlug,
                    userId,
                    notification,
                    fcmConfig
                );

                if (!result.success && result.reason !== 'no_devices') {
                    throw new Error(`Push failed: ${JSON.stringify(result)}`);
                }

                return result;

            } catch (error: any) {
                console.error(`[Queue:Push] Failed job ${job.id}:`, error.message);
                throw error;
            }
        }, { 
            ...REDIS_CONFIG, 
            concurrency: 50 // High concurrency for push notifications
        });
    }

    public static async addWebhookJob(data: any) {
        if (!this.webhookQueue) this.init();
        const attempts = data.retryPolicy === 'none' ? 1 : (data.retryPolicy === 'linear' ? 5 : 10);
        await this.webhookQueue.add('dispatch', data, { attempts });
    }

    public static async addPushJob(data: any) {
        if (!this.pushQueue) this.init();
        // Push jobs are usually fire-and-forget, but we retry on network errors
        await this.pushQueue.add('send', data, { 
            attempts: 3, 
            backoff: { type: 'exponential', delay: 1000 } 
        });
    }

    public static async getMetrics() {
        if (!this.webhookQueue) return { waiting: 0, active: 0, failed: 0, completed: 0 };
        return await this.webhookQueue.getJobCounts('waiting', 'active', 'failed', 'completed');
    }
}
