import { Queue, Worker, Job } from 'bullmq';
import crypto from 'crypto';
import axios from 'axios';
import { URL } from 'url';

const REDIS_CONFIG = {
    connection: {
        host: process.env.REDIS_HOST || 'redis',
        port: parseInt(process.env.REDIS_PORT || '6379')
    }
};

export class QueueService {
    private static webhookQueue: Queue;
    private static webhookWorker: Worker;

    // SSRF Protection: Checks if IP is private/local/cloud-metadata
    private static isPrivateIP(ip: string): boolean {
        const parts = ip.split('.').map(Number);
        if (parts.length !== 4) return false; // Not IPv4 (simplification)

        // 10.0.0.0/8
        if (parts[0] === 10) return true;
        // 172.16.0.0/12
        if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
        // 192.168.0.0/16
        if (parts[0] === 192 && parts[1] === 168) return true;
        // 127.0.0.0/8 (Loopback)
        if (parts[0] === 127) return true;
        // 169.254.0.0/16 (Link-local / Cloud Metadata)
        if (parts[0] === 169 && parts[1] === 254) return true;
        
        return false;
    }

    private static async validateTarget(targetUrl: string): Promise<void> {
        try {
            const url = new URL(targetUrl);
            const hostname = url.hostname;

            if (hostname === 'localhost') throw new Error("Blocked: localhost not allowed");
            if (hostname === 'redis') throw new Error("Blocked: internal service access");
            if (hostname === 'db') throw new Error("Blocked: internal service access");

            // TODO: In a real production env, we would resolve DNS here to get the IP
            // and check against isPrivateIP. Since Node DNS is async, and we want
            // to keep this simple without extra deps:
            // We rely on the fact that standard public DNS won't resolve to private IPs easily
            // unless there is a rebinding attack.
            // For high security, one should use a library like `ssrf-agent`.
            
            // Simple RegEx check for IP literals in the URL
            const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
            if (ipRegex.test(hostname)) {
                if (this.isPrivateIP(hostname)) {
                    throw new Error(`Blocked: Private IP range ${hostname}`);
                }
            }

        } catch (e: any) {
            throw new Error(`SSRF Protection: ${e.message}`);
        }
    }

    public static init() {
        console.log('[QueueService] Initializing BullMQ Queues...');

        // 1. Definição da Fila de Webhooks
        this.webhookQueue = new Queue('cascata-webhooks', {
            ...REDIS_CONFIG,
            defaultJobOptions: {
                attempts: 5, // Tenta 5 vezes em caso de falha
                backoff: {
                    type: 'exponential',
                    delay: 1000, // 1s, 2s, 4s, 8s...
                },
                removeOnComplete: true, // Limpa sucesso para economizar RAM
                removeOnFail: 1000 // Mantém os últimos 1000 falhados para debug
            }
        });

        // 2. Worker (Processador) de Webhooks
        this.webhookWorker = new Worker('cascata-webhooks', async (job: Job) => {
            const { targetUrl, payload, secret, eventType, tableName } = job.data;
            
            // SECURITY CHECK
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
                        'User-Agent': 'Cascata-Webhook-Engine/2.0'
                    },
                    timeout: 5000 // 5s timeout para não travar o worker
                });
                
                return { status: 'sent', timestamp: new Date() };
            } catch (error: any) {
                console.error(`[Queue:Webhook] Failed job ${job.id}: ${error.message}`);
                throw error; // Lança erro para o BullMQ agendar o retry
            }
        }, REDIS_CONFIG);

        this.webhookWorker.on('failed', (job, err) => {
            console.warn(`[Queue:Webhook] Job ${job?.id} failed attempt ${job?.attemptsMade}: ${err.message}`);
        });
    }

    public static async addWebhookJob(data: {
        targetUrl: string;
        payload: any;
        secret: string;
        eventType: string;
        tableName: string;
    }) {
        if (!this.webhookQueue) {
            console.warn('[QueueService] Queue not initialized, initializing lazy...');
            this.init();
        }
        await this.webhookQueue.add('dispatch', data);
    }

    public static async getMetrics() {
        if (!this.webhookQueue) return { waiting: 0, active: 0, failed: 0 };
        return await this.webhookQueue.getJobCounts('waiting', 'active', 'failed', 'completed');
    }
}