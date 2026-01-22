
import { Queue, Worker, Job } from 'bullmq';
import crypto from 'crypto';
import axios from 'axios';
import { URL } from 'url';
import dns from 'dns/promises';
import { systemPool } from '../src/config/main.js';
import { PoolService } from './PoolService.js';

const REDIS_CONFIG = {
    connection: {
        host: process.env.REDIS_HOST || 'dragonfly',
        port: parseInt(process.env.REDIS_PORT || '6379')
    }
};

export class QueueService {
    private static webhookQueue: Queue;
    private static pushQueue: Queue;
    private static pushWorker: Worker;

    private static async validateTarget(targetUrl: string): Promise<void> {
        try {
            const url = new URL(targetUrl);
            const hostname = url.hostname;
            if (hostname === 'localhost' || hostname === 'db' || hostname === 'dragonfly') {
                throw new Error("Internal access blocked");
            }
        } catch (e: any) { throw new Error(`Security Violation: ${e.message}`); }
    }

    public static init() {
        console.log('[QueueService] Initializing Queues with DragonflyDB...');

        this.webhookQueue = new Queue('cascata-webhooks', {
            ...REDIS_CONFIG,
            defaultJobOptions: { attempts: 5, backoff: { type: 'exponential', delay: 1000 } }
        });

        // 2. PUSH NOTIFICATION QUEUE
        this.pushQueue = new Queue('cascata-push', {
            ...REDIS_CONFIG,
            defaultJobOptions: { removeOnComplete: 100, removeOnFail: 500 }
        });

        this.pushWorker = new Worker('cascata-push', async (job: Job) => {
            const { projectSlug, userId, notification, fcmConfig, dbName, externalDbUrl } = job.data;
            try {
                const pool = PoolService.get(dbName, { connectionString: externalDbUrl });
                
                // CIRCULAR DEPENDENCY FIX: Dynamic Import
                const { PushService } = await import('./PushService.js');

                return await PushService.processDelivery(
                    pool,
                    systemPool,
                    projectSlug,
                    userId,
                    notification,
                    fcmConfig
                );
            } catch (error: any) {
                console.error(`[Queue:Push] Error:`, error.message);
                throw error;
            }
        }, { ...REDIS_CONFIG, concurrency: 50 });
    }

    public static async addPushJob(data: any) {
        if (!this.pushQueue) this.init();
        await this.pushQueue.add('send', data, { attempts: 3, backoff: { type: 'fixed', delay: 2000 } });
    }

    public static async addWebhookJob(data: any) {
        if (!this.webhookQueue) this.init();
        await this.webhookQueue.add('dispatch', data);
    }
}
