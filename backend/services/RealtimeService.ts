import { Response, Request } from 'express';
import { Client } from 'pg';
import { systemPool } from '../src/config/main.js';

interface ClientConnection {
    id: string;
    res: any;
    tableFilter?: string;
}

export class RealtimeService {
    private static subscribers = new Map<string, Set<ClientConnection>>();
    private static listeners = new Map<string, Client>();
    
    private static MAX_CLIENTS_PER_PROJECT = 5000; // Escala Elite

    public static async handleConnection(req: any, res: any) {
        const slug = req.params.slug;
        const { table } = req.query;

        // Recupera contexto do projeto (injetado pelo middleware resolveProject)
        const project = req.project;

        if (!project) {
            res.status(404).json({ error: 'Project context missing.' });
            return;
        }

        const currentCount = this.subscribers.get(slug)?.size || 0;
        if (currentCount >= this.MAX_CLIENTS_PER_PROJECT) {
            res.status(429).json({ error: 'Too many realtime connections.' });
            return;
        }

        const headers = {
            'Content-Type': 'text/event-stream',
            'Connection': 'keep-alive',
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no'
        };
        res.writeHead(200, headers);

        const clientId = Date.now().toString(36) + Math.random().toString(36).substr(2);
        res.write(`data: ${JSON.stringify({ type: 'connected', clientId })}\n\n`);

        // Inicializa Listener do PostgreSQL se não existir
        if (!this.listeners.has(slug)) {
            await this.setupProjectListener(project);
        }

        if (!this.subscribers.has(slug)) {
            this.subscribers.set(slug, new Set());
        }
        
        const connection: ClientConnection = {
            id: clientId,
            res,
            tableFilter: table as string
        };
        
        this.subscribers.get(slug)!.add(connection);

        // Keep-alive para evitar timeout de load balancers (AWS ALB / Nginx)
        const heartbeat = setInterval(() => {
            if (!res.writableEnded) res.write(': ping\n\n');
        }, 15000);

        req.on('close', () => {
            clearInterval(heartbeat);
            this.subscribers.get(slug)?.delete(connection);
            if (this.subscribers.get(slug)?.size === 0) {
                this.teardownProjectListener(slug);
            }
        });
    }

    private static async setupProjectListener(project: any) {
        const slug = project.slug;
        console.log(`[Realtime] Starting Listener for ${slug}...`);
        
        try {
            let connectionString: string;

            // Lógica de Resolução de Conexão (Híbrida)
            if (project.metadata?.external_db_url) {
                console.log(`[Realtime] ${slug} is EJECTED. Connecting to external infrastructure.`);
                connectionString = project.metadata.external_db_url;
            } else {
                // Modo Nativo (Docker Local)
                const dbName = project.db_name;
                const host = process.env.DB_DIRECT_HOST || 'db';
                const port = process.env.DB_DIRECT_PORT || '5432';
                const user = process.env.DB_USER || 'cascata_admin';
                const pass = process.env.DB_PASS || 'secure_pass';
                connectionString = `postgresql://${user}:${pass}@${host}:${port}/${dbName}`;
            }

            // CRITICAL: Force Direct Connection for LISTEN/NOTIFY.
            // PgBouncer "Transaction Mode" quebra LISTEN/NOTIFY, então usamos Client direto.
            const listenerClient = new Client({ 
                connectionString, 
                keepAlive: true,
                ssl: project.metadata?.external_db_url ? { rejectUnauthorized: false } : false
            });
            
            await listenerClient.connect();
            await listenerClient.query('LISTEN cascata_events');

            listenerClient.on('notification', (msg) => {
                if (msg.channel === 'cascata_events' && msg.payload) {
                    this.broadcast(slug, JSON.parse(msg.payload));
                }
            });

            listenerClient.on('error', (err) => {
                console.error(`[Realtime] Listener Error ${slug}:`, err.message);
                this.teardownProjectListener(slug);
            });

            this.listeners.set(slug, listenerClient);

        } catch (e: any) {
            console.error(`[Realtime] Failed to setup listener for ${slug}`, e.message);
        }
    }

    public static teardownProjectListener(slug: string) {
        const client = this.listeners.get(slug);
        if (client) {
            console.log(`[Realtime] Closing Listener for ${slug}`);
            client.end().catch(() => {});
            this.listeners.delete(slug);
        }
    }

    private static broadcast(slug: string, payload: any) {
        const clients = this.subscribers.get(slug);
        if (!clients) return;
        const message = `data: ${JSON.stringify(payload)}\n\n`;
        clients.forEach(client => {
            if (!client.res.writableEnded) {
                if (!client.tableFilter || client.tableFilter === payload.table) {
                    client.res.write(message);
                }
            }
        });
    }
}