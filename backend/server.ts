import express, { Request, RequestHandler } from 'express';
import cors from 'cors';
import pg from 'pg';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import crypto from 'crypto';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { Buffer } from 'buffer';

// IMPORT SERVICES
import { BackupService } from './services/BackupService.js';
import { ImportService } from './services/ImportService.js';
import { DatabaseService } from './services/DatabaseService.js';
import { AuthService } from './services/AuthService.js';
import { WebhookService } from './services/WebhookService.js';
import { PoolService } from './services/PoolService.js';
import { RateLimitService } from './services/RateLimitService.js';
import { CertificateService } from './services/CertificateService.js';
import { MigrationService } from './services/MigrationService.js';
import { EdgeService } from './services/EdgeService.js';
import { QueueService } from './services/QueueService.js';
import { RealtimeService } from './services/RealtimeService.js';
import { OpenApiService } from './services/OpenApiService.js';
import { AiService } from './services/AiService.js';

dotenv.config();

// --- TYPE EXTENSIONS ---
interface CascataRequest extends Request {
  project?: any;
  projectPool?: pg.Pool;
  user?: any;
  userRole?: 'service_role' | 'authenticated' | 'anon';
  isSystemRequest?: boolean;
  file?: any;
  files?: any;
  body: any;
  params: any;
  query: any;
  path: string;
  method: string;
}

const app = express();

app.use(cors()); 
app.use(express.json({ limit: '100mb' }) as any);
app.use(express.urlencoded({ extended: true }) as any);

// --- SECURITY: HARDENING HEADERS ---
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.removeHeader('X-Powered-By'); 
  next();
});

const { Pool } = pg;
const PORT = process.env.PORT || 3000;
const SYS_SECRET = process.env.SYSTEM_JWT_SECRET || 'insecure_default_secret_please_change';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const STORAGE_ROOT = path.resolve(__dirname, '../storage');
const MIGRATIONS_ROOT = path.resolve(__dirname, '../migrations');
const NGINX_DYNAMIC_ROOT = '/etc/nginx/conf.d/dynamic';
const TEMP_UPLOAD_ROOT = path.resolve(__dirname, '../temp_uploads');

try {
  if (!fs.existsSync(STORAGE_ROOT)) fs.mkdirSync(STORAGE_ROOT, { recursive: true });
  if (!fs.existsSync(NGINX_DYNAMIC_ROOT)) fs.mkdirSync(NGINX_DYNAMIC_ROOT, { recursive: true });
  if (!fs.existsSync(TEMP_UPLOAD_ROOT)) fs.mkdirSync(TEMP_UPLOAD_ROOT, { recursive: true });
} catch (e) { console.error('[System] Root dir create error:', e); }

const upload = multer({ dest: path.join(__dirname, '../uploads') });
const backupUpload = multer({ 
    dest: TEMP_UPLOAD_ROOT,
    limits: { fileSize: 5 * 1024 * 1024 * 1024 } 
});

const generateKey = () => crypto.randomBytes(32).toString('hex');

// --- 1. SYSTEM CONTROL PLANE POOL ---
const systemPool = new Pool({ 
  connectionString: process.env.SYSTEM_DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30000 
});

systemPool.on('error', (err) => {
    console.error('[SystemPool] Unexpected error on idle client', err);
});

// Initialize Services
RateLimitService.init();
if (process.env.SERVICE_MODE === 'CONTROL_PLANE') {
    QueueService.init(); 
}

// --- MIDDLEWARES DE INFRAESTRUTURA ---

const controlPlaneFirewall: RequestHandler = async (req: any, res: any, next: any) => {
  if (req.method !== 'OPTIONS' && req.path.startsWith('/api/control/projects/')) {
    const slug = req.path.split('/')[4]; 
    if (slug) {
        const forwarded = req.headers['x-forwarded-for'];
        const realIp = req.headers['x-real-ip'];
        const socketIp = req.socket?.remoteAddress;
        let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
        clientIp = clientIp.replace('::ffff:', '');

        if (clientIp === '127.0.0.1' || clientIp === '::1' || clientIp.startsWith('172.') || clientIp.startsWith('10.')) {
            return next();
        }

        try {
            const result = await systemPool.query('SELECT blocklist FROM system.projects WHERE slug = $1', [slug]);
            if (result.rows.length > 0) {
                const blocklist = result.rows[0].blocklist || [];
                if (blocklist.includes(clientIp)) {
                    res.status(403).json({ error: 'Firewall: Access Denied' });
                    return;
                }
            }
        } catch (e) { }
    }
  }
  next();
};

const resolveProject: RequestHandler = async (req: any, res: any, next: any) => {
  if (req.path.startsWith('/api/control/')) return next();
  if (req.path === '/' || req.path === '/health') return next(); 
  
  const r = req as CascataRequest;
  const host = req.headers.host || '';
  
  const authHeader = req.headers['authorization'];
  const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : (req.query.token as string);
  r.isSystemRequest = false;
  
  if (bearerToken) {
    try {
      jwt.verify(bearerToken, process.env.SYSTEM_JWT_SECRET || 'fallback_secret');
      r.isSystemRequest = true;
    } catch { }
  }

  const apiKey = (req.headers['apikey'] as string) || (req.query.apikey as string);
  const pathParts = req.path.split('/');
  const slugFromUrl = (pathParts.length > 3 && pathParts[1] === 'api' && pathParts[2] === 'data') ? pathParts[3] : null;

  try {
    let projectResult: pg.QueryResult | undefined;
    let resolutionMethod = 'unknown';

    // DECRYPT KEYS ON READ
    const projectQuery = `
        SELECT 
            id, name, slug, db_name, custom_domain, ssl_certificate_source, blocklist, metadata, status,
            pgp_sym_decrypt(jwt_secret::bytea, $2) as jwt_secret,
            pgp_sym_decrypt(anon_key::bytea, $2) as anon_key,
            pgp_sym_decrypt(service_key::bytea, $2) as service_key
        FROM system.projects 
    `;

    if (host && !host.includes('localhost') && !host.includes('127.0.0.1')) {
      projectResult = await systemPool.query(`${projectQuery} WHERE custom_domain = $1`, [host, SYS_SECRET]);
      if ((projectResult.rowCount ?? 0) > 0) resolutionMethod = 'domain';
    }

    if ((!projectResult || (projectResult.rowCount ?? 0) === 0) && slugFromUrl) {
      projectResult = await systemPool.query(`${projectQuery} WHERE slug = $1`, [slugFromUrl, SYS_SECRET]);
      if ((projectResult.rowCount ?? 0) > 0) resolutionMethod = 'slug';
    }

    if (!projectResult || !projectResult.rows[0]) {
      if (req.path.startsWith('/api/data/')) {
        res.status(404).json({ error: 'Project Context Not Found (404)' });
        return;
      }
      return next(); 
    }

    const project = projectResult.rows[0];

    if (!r.isSystemRequest) {
        const isPanic = await RateLimitService.checkPanic(project.slug);
        if (isPanic) {
            console.warn(`[PanicShield] Blocked request to ${req.url} for project ${project.slug} (REDIS)`);
            res.status(503).json({ error: 'System is currently in Panic Mode (Locked Down). Please contact administrator.' });
            return;
        }
    }

    if (project.custom_domain && resolutionMethod === 'slug') {
      const isDev = host.includes('localhost') || host.includes('127.0.0.1');
      if (!isDev && !r.isSystemRequest) {
        res.status(403).json({ 
          error: 'Domain Locking Policy: This project accepts requests only via its configured custom domain.',
          hint: 'Use the custom domain API endpoint.'
        });
        return;
      }
    }

    if (resolutionMethod === 'domain' && !req.url.startsWith('/api/data/')) {
      req.url = `/api/data/${project.slug}${req.url}`;
    }

    const forwarded = req.headers['x-forwarded-for'];
    const realIp = req.headers['x-real-ip'];
    const socketIp = req.socket?.remoteAddress;
    let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
    clientIp = clientIp.replace('::ffff:', '');
    
    if (project.blocklist && project.blocklist.includes(clientIp)) {
      res.status(403).json({ error: 'Firewall: Access Denied (Blocked Origin)' });
      return;
    }

    r.project = project;

    try {
      r.projectPool = PoolService.get(project.db_name);
    } catch (err) {
      res.status(502).json({ error: 'Database Connection Failed' });
      return;
    }

    next();
  } catch (e) {
    res.status(500).json({ error: 'Internal Resolution Error' });
  }
};

const dynamicRateLimiter: RequestHandler = async (req: any, res: any, next: any) => {
    if (!req.project) return next();
    const forwarded = req.headers['x-forwarded-for'];
    const realIp = req.headers['x-real-ip'];
    const socketIp = req.socket?.remoteAddress;
    let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
    clientIp = clientIp.replace('::ffff:', '');
    if (clientIp === '127.0.0.1' || clientIp === '::1') return next();

    const r = req as CascataRequest;
    const result = await RateLimitService.check(r.project.slug, req.path.replace(`/api/data/${r.project.slug}`, '') || '/', req.method, r.userRole || 'anon', clientIp, systemPool);

    if (result.blocked) {
        res.setHeader('Retry-After', result.retryAfter || 60);
        res.status(429).json({ error: result.customMessage || 'Too Many Requests', retryAfter: result.retryAfter });
        return;
    }
    if (result.limit) {
        res.setHeader('X-RateLimit-Limit', result.limit);
        res.setHeader('X-RateLimit-Remaining', result.remaining || 0);
    }
    next();
};

const cascataAuth: RequestHandler = async (req: any, res: any, next: any) => {
  const r = req as CascataRequest;

  if (req.path.startsWith('/api/control/')) {
    if (req.path.endsWith('/auth/login') || req.path.endsWith('/auth/verify') || req.path.includes('/system/ssl-check')) return next();
    
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        if (req.path.includes('/export') && req.query.token) return next();
        res.status(401).json({ error: 'Missing Admin Token' }); 
        return; 
    }
    try {
      const token = authHeader.split(' ')[1];
      jwt.verify(token, process.env.SYSTEM_JWT_SECRET || 'fallback_secret');
      return next();
    } catch { 
      res.status(401).json({ error: 'Invalid Admin Token' });
      return;
    }
  }

  if (!r.project) { 
      if (req.path === '/' || req.path === '/health') return next();
      res.status(404).json({ error: 'No Project Context' }); 
      return; 
  }

  if (r.isSystemRequest) {
    r.userRole = 'service_role';
    return next();
  }

  const apiKey = (req.headers['apikey'] as string) || (req.query.apikey as string);
  const authHeader = req.headers['authorization'];
  const bearerToken = authHeader?.startsWith('Bearer ') ? authHeader.split(' ')[1] : (req.query.token as string);

  if (apiKey === r.project.service_key || bearerToken === r.project.service_key) {
    r.userRole = 'service_role';
    return next();
  }

  if (bearerToken) {
    try {
      const decoded = jwt.verify(bearerToken, r.project.jwt_secret);
      r.user = decoded;
      r.userRole = 'authenticated';
      return next();
    } catch (e) { /* Fallback to anon */ }
  }

  if (apiKey === r.project.anon_key) {
    r.userRole = 'anon';
    return next();
  }

  if (req.path.includes('/auth/providers/') || req.path.includes('/auth/callback') || req.path.includes('/auth/passwordless/') || req.path.includes('/auth/token/refresh')) {
      r.userRole = 'anon';
      return next();
  }

  if (req.path.includes('/auth/users') || req.path.includes('/auth/token')) {
      r.userRole = 'anon';
      return next();
  }

  if (req.path.includes('/edge/')) {
      r.userRole = 'anon';
      return next();
  }

  res.status(401).json({ error: 'Unauthorized: Invalid API Key or JWT.' });
};

const detectSemanticAction = (method: string, path: string): string | null => {
    if (path.includes('/tables') && method === 'POST' && path.endsWith('/rows')) return 'INSERT_ROWS';
    if (path.includes('/tables') && method === 'POST') return 'CREATE_TABLE';
    if (path.includes('/tables') && method === 'DELETE' && !path.includes('/rows')) return 'DROP_TABLE';
    if (path.includes('/tables') && method === 'DELETE' && path.includes('/rows')) return 'DELETE_ROWS';
    if (path.includes('/tables') && method === 'PUT') return 'UPDATE_ROWS';
    if (path.includes('/auth/token') && !path.includes('refresh')) return 'AUTH_LOGIN';
    if (path.includes('/auth/token/refresh')) return 'AUTH_REFRESH';
    if (path.includes('/auth/callback')) return 'AUTH_CALLBACK'; 
    if (path.includes('/auth/passwordless/start')) return 'AUTH_OTP_REQUEST'; 
    if (path.includes('/auth/passwordless/verify')) return 'AUTH_OTP_VERIFY'; 
    if (path.includes('/auth/users') && method === 'POST') return 'AUTH_REGISTER';
    if (path.includes('/storage') && method === 'POST' && path.includes('/upload')) return 'UPLOAD_FILE';
    if (path.includes('/storage') && method === 'DELETE') return 'DELETE_FILE';
    if (path.includes('/edge/')) return 'EDGE_INVOKE';
    return null;
};

const auditLogger: RequestHandler = (req: any, res: any, next: any) => {
  const start = Date.now();
  const oldJson = res.json;
  const r = req as CascataRequest;

  if (req.path.includes('/realtime')) return next();

  (res as any).json = function(data: any) {
    if (r.project) {
       const duration = Date.now() - start;
       const isUpload = req.headers['content-type']?.includes('multipart/form-data');
       const payload = isUpload ? { type: 'binary_upload' } : req.body;
       const forwarded = req.headers['x-forwarded-for'];
       const realIp = req.headers['x-real-ip'];
       const socketIp = (req as any).socket?.remoteAddress;
       let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
       clientIp = clientIp.replace('::ffff:', '');
       const isInternal = req.headers['x-cascata-client'] === 'dashboard' || r.isSystemRequest;
       const semanticAction = detectSemanticAction(req.method, req.path);
       const geoInfo = { is_internal: isInternal, auth_status: res.statusCode >= 400 ? 'SECURITY_ALERT' : 'GRANTED', semantic_action: semanticAction };

       if (res.statusCode === 401 && r.project.metadata?.security?.auto_block_401) {
          const isSafeIp = clientIp === '127.0.0.1' || clientIp === '::1' || clientIp.startsWith('172.') || clientIp.startsWith('10.') || clientIp.startsWith('192.168.'); 
          if (!isSafeIp && !r.project.blocklist?.includes(clientIp)) {
             systemPool.query('UPDATE system.projects SET blocklist = array_append(blocklist, $1) WHERE slug = $2', [clientIp, r.project.slug]).catch(err => console.error("Auto-block failed", err));
          }
       }

       systemPool.query(
        `INSERT INTO system.api_logs (project_slug, method, path, status_code, client_ip, duration_ms, user_role, payload, headers, geo_info) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
        [r.project.slug, req.method, req.path, res.statusCode, clientIp, duration, r.userRole || 'unauthorized', JSON.stringify(payload).substring(0, 2000), JSON.stringify({ referer: req.headers.referer, userAgent: req.headers['user-agent'] }), JSON.stringify(geoInfo)]
       ).catch(() => {});
       
       if (res.statusCode >= 200 && res.statusCode < 300 && ['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
           let tableName = '*';
           if (req.path.includes('/tables/')) { const parts = req.path.split('/tables/'); if (parts[1]) tableName = parts[1].split('/')[0]; }
           WebhookService.dispatch(r.project.slug, tableName, semanticAction || req.method, payload, systemPool, r.project.jwt_secret);
       }
    }
    return oldJson.apply(res, arguments as any);
  }
  next();
};

const cleanTempUploads = () => {
    const tempDir = process.env.TEMP_UPLOAD_ROOT || path.resolve(__dirname, '../temp_uploads');
    if (fs.existsSync(tempDir)) {
        const files = fs.readdirSync(tempDir);
        const now = Date.now();
        files.forEach(file => {
            const filePath = path.join(tempDir, file);
            try { if (now - fs.statSync(filePath).mtimeMs > 3600 * 1000) fs.rmSync(filePath, { recursive: true, force: true }); } catch (e) { }
        });
    }
};

const quoteId = (identifier: string) => {
  if (typeof identifier !== 'string') throw new Error("Invalid identifier");
  return `"${identifier.replace(/"/g, '""')}"`;
};

// --- CRITICAL SECURITY: ROLE SWITCHING & RLS ---
const queryWithRLS = async (req: CascataRequest, callback: (client: pg.PoolClient) => Promise<any>) => {
  if (!req.projectPool) throw new Error("Database connection not initialized");
  
  const client = await req.projectPool.connect();
  try {
    if (req.isSystemRequest) {
        // Dashboard/Admin Access: Uses original connection (superuser/admin owner)
        // No role switch needed, allowing DDL (CREATE TABLE) and direct access.
        await client.query("SELECT set_config('request.jwt.claim.role', 'service_role', true)");
    } else {
        // Public API Access: Force Sandbox
        // Switch to the restricted role that CANNOT create tables or drop objects
        await client.query("SET ROLE cascata_api_role");
        
        // RLS Context
        if (req.userRole === 'service_role') {
            await client.query("SELECT set_config('request.jwt.claim.role', 'service_role', true)");
        } else if (req.user && req.user.sub) {
            await client.query("SELECT set_config('request.jwt.claim.sub', $1, true)", [req.user.sub]);
            await client.query("SELECT set_config('request.jwt.claim.role', $1, true)", [req.userRole]);
        } else {
            await client.query("SELECT set_config('request.jwt.claim.role', 'anon', true)");
        }
    }
    const result = await callback(client);
    return result;
  } catch (e) {
    throw e;
  } finally {
    // Reset session before returning to pool
    try { await client.query("RESET ROLE; DISCARD ALL"); } catch(err) { }
    client.release();
  }
};

const waitForDatabase = async (retries = 30, delay = 1000): Promise<boolean> => {
  for (let i = 0; i < retries; i++) {
    try {
      const client = await systemPool.connect();
      client.release();
      console.log('[System] Database connected successfully.');
      return true;
    } catch (err: any) {
      if(i % 5 === 0) console.warn(`[System] Waiting for database... (${i + 1}/${retries})`);
      await new Promise(res => setTimeout(res, delay));
    }
  }
  return false;
};

app.use(resolveProject as any);
app.use(controlPlaneFirewall as any);
app.use(dynamicRateLimiter as any); 
app.use(auditLogger as any); 
app.use(cascataAuth as any);

// Health Check
app.get('/', (req, res) => { res.send('Cascata Engine OK'); });
app.get('/health', (req, res) => { res.json({ status: 'ok', time: new Date() }); });

app.get('/api/data/:slug/realtime', (req, res) => RealtimeService.handleConnection(req, res));

// --- DATA ROUTES WITH RLS ENFORCEMENT ---

app.get('/api/data/:slug/tables/:tableName/data', async (req: any, res: any) => {
    const r = req as CascataRequest;
    try {
        const safeTable = quoteId(req.params.tableName);
        const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
        const offset = parseInt(req.query.offset) || 0;
        
        const result = await queryWithRLS(r, async (client) => {
            return await client.query(`SELECT * FROM public.${safeTable} LIMIT $1 OFFSET $2`, [limit, offset]);
        });
        res.json(result.rows);
    } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// Insert
app.post('/api/data/:slug/tables/:tableName/rows', async (req: any, res: any) => {
    const r = req as CascataRequest;
    try {
        const safeTable = quoteId(req.params.tableName);
        const { data } = req.body;
        if (!data) throw new Error("No data provided");
        
        const rows = Array.isArray(data) ? data : [data];
        if (rows.length === 0) return res.json([]);

        const keys = Object.keys(rows[0]);
        const columns = keys.map(quoteId).join(', ');
        const valuesPlaceholder = rows.map((_, i) => 
            `(${keys.map((_, j) => `$${i * keys.length + j + 1}`).join(', ')})`
        ).join(', ');
        const flatValues = rows.flatMap(row => keys.map(k => row[k]));

        const result = await queryWithRLS(r, async (client) => {
            return await client.query(
                `INSERT INTO public.${safeTable} (${columns}) VALUES ${valuesPlaceholder} RETURNING *`,
                flatValues
            );
        });
        res.status(201).json(result.rows);
    } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// Update
app.put('/api/data/:slug/tables/:tableName/rows', async (req: any, res: any) => {
    const r = req as CascataRequest;
    try {
        const safeTable = quoteId(req.params.tableName);
        const { data, pkColumn, pkValue } = req.body;
        
        if (!data || !pkColumn || pkValue === undefined) throw new Error("Missing data or PK");

        const updates = Object.keys(data).map((k, i) => `${quoteId(k)} = $${i + 1}`).join(', ');
        const values = Object.values(data);
        const pkValIndex = values.length + 1;

        const result = await queryWithRLS(r, async (client) => {
            return await client.query(
                `UPDATE public.${safeTable} SET ${updates} WHERE ${quoteId(pkColumn)} = $${pkValIndex} RETURNING *`,
                [...values, pkValue]
            );
        });
        res.json(result.rows);
    } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// Delete
app.delete('/api/data/:slug/tables/:tableName/rows', async (req: any, res: any) => {
    const r = req as CascataRequest;
    try {
        const safeTable = quoteId(req.params.tableName);
        const { ids, pkColumn } = req.body;
        
        if (!ids || !Array.isArray(ids) || !pkColumn) throw new Error("Invalid delete request");

        const result = await queryWithRLS(r, async (client) => {
            return await client.query(
                `DELETE FROM public.${safeTable} WHERE ${quoteId(pkColumn)} = ANY($1) RETURNING *`,
                [ids]
            );
        });
        res.json(result.rows);
    } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// Schema Info (Tables)
app.get('/api/data/:slug/tables', async (req: any, res: any) => {
    const r = req as CascataRequest;
    try {
        const result = await queryWithRLS(r, async (client) => {
            return await client.query(`
                SELECT table_name as name, table_schema as schema 
                FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
                AND table_name NOT LIKE '_deleted_%'
            `);
        });
        res.json(result.rows);
    } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// Schema Info (Columns)
app.get('/api/data/:slug/tables/:tableName/columns', async (req: any, res: any) => {
    const r = req as CascataRequest;
    try {
        const result = await queryWithRLS(r, async (client) => {
            return await client.query(`
                SELECT column_name as name, data_type as type, is_nullable, column_default as "defaultValue"
                FROM information_schema.columns 
                WHERE table_schema = 'public' AND table_name = $1
            `, [req.params.tableName]);
        });
        res.json(result.rows);
    } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// Create Table
app.post('/api/data/:slug/tables', async (req: any, res: any) => {
    const r = req as CascataRequest;
    // Only dashboard/admin can create tables
    if (!r.isSystemRequest) { res.status(403).json({ error: 'Only Dashboard can create tables.' }); return; }

    const { name, columns } = req.body;
    if (!name || !columns) { res.status(400).json({ error: 'Missing table def' }); return; }

    try {
        const safeName = quoteId(name);
        const colDefs = columns.map((c: any) => {
            let def = `${quoteId(c.name)} ${c.type}`;
            if (c.primaryKey) def += ' PRIMARY KEY';
            if (!c.nullable && !c.primaryKey) def += ' NOT NULL';
            if (c.default) def += ` DEFAULT ${c.default}`;
            if (c.isUnique) def += ' UNIQUE';
            if (c.foreignKey) def += ` REFERENCES ${quoteId(c.foreignKey.table)}(${quoteId(c.foreignKey.column)})`;
            return def;
        }).join(', ');

        const sql = `CREATE TABLE public.${safeName} (${colDefs});`;
        
        // No need for queryWithRLS as we checked isSystemRequest above, and only admin can DDL
        await r.projectPool!.query(sql);
        
        // Enable RLS by default
        await r.projectPool!.query(`ALTER TABLE public.${safeName} ENABLE ROW LEVEL SECURITY`);
        
        // Add trigger
        await r.projectPool!.query(`
            CREATE TRIGGER ${name}_changes
            AFTER INSERT OR UPDATE OR DELETE ON public.${safeName}
            FOR EACH ROW EXECUTE FUNCTION public.notify_changes();
        `);

        res.json({ success: true });
    } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// --- CONTROL PLANE: PROJECTS (With Encryption) ---
app.get('/api/control/projects', async (req: any, res: any) => {
  try {
    const result = await systemPool.query(`
        SELECT 
            id, name, slug, db_name, custom_domain, ssl_certificate_source, blocklist, metadata, status, created_at,
            pgp_sym_decrypt(jwt_secret::bytea, $1) as jwt_secret,
            pgp_sym_decrypt(anon_key::bytea, $1) as anon_key,
            pgp_sym_decrypt(service_key::bytea, $1) as service_key
        FROM system.projects ORDER BY created_at DESC
    `, [SYS_SECRET]);
    res.json(result.rows);
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.post('/api/control/projects', async (req: any, res: any) => {
  const { name, slug } = req.body;
  const safeSlug = slug.toLowerCase().replace(/[^a-z0-9-]/g, '');
  const dbName = `cascata_db_${safeSlug.replace(/-/g, '_')}`;
  
  let tempClient: pg.Client | null = null;

  try {
    const keys = { anon: generateKey(), service: generateKey(), jwt: generateKey() };
    
    // Insert with Encryption
    const insertRes = await systemPool.query(
      `INSERT INTO system.projects (name, slug, db_name, anon_key, service_key, jwt_secret, metadata) 
       VALUES ($1, $2, $3, pgp_sym_encrypt($4, $7), pgp_sym_encrypt($5, $7), pgp_sym_encrypt($6, $7), '{}') RETURNING *`,
      [name, safeSlug, dbName, keys.anon, keys.service, keys.jwt, SYS_SECRET]
    );

    await systemPool.query(`CREATE DATABASE ${quoteId(dbName)}`);

    const baseUrl = process.env.SYSTEM_DATABASE_URL || '';
    const newDbUrl = baseUrl.replace(/\/[^\/?]+(\?.*)?$/, `/${dbName}$1`);
    
    tempClient = new pg.Client({ connectionString: newDbUrl });
    await tempClient.connect();

    await DatabaseService.initProjectDb(tempClient);

    res.json({ ...insertRes.rows[0], anon_key: keys.anon, service_key: keys.service, jwt_secret: keys.jwt });
  } catch (e: any) {
    if (tempClient) await tempClient.end();
    await systemPool.query('DELETE FROM system.projects WHERE slug = $1', [safeSlug]).catch(() => {});
    res.status(500).json({ error: e.message });
  } finally {
    if (tempClient) await tempClient.end();
  }
});

// Key Rotation (With Encryption)
app.post('/api/control/projects/:slug/rotate-keys', async (req: any, res: any) => {
  const { type } = req.body;
  const newKey = generateKey();
  let column = '';
  if (type === 'anon') column = 'anon_key';
  else if (type === 'service') column = 'service_key';
  else if (type === 'jwt') column = 'jwt_secret';
  else { res.status(400).json({ error: 'Invalid key type' }); return; }

  try {
    await systemPool.query(
      `UPDATE system.projects SET ${column} = pgp_sym_encrypt($1, $3) WHERE slug = $2`,
      [newKey, req.params.slug, SYS_SECRET]
    );
    res.json({ success: true, type, newKey: 'HIDDEN_IN_RESPONSE' });
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// ... (Other standard routes like auth/login, etc. assumed present or added here if needed for completeness)
app.post('/api/control/auth/login', async (req: any, res: any) => {
  const { email, password } = req.body;
  try {
    const result = await systemPool.query('SELECT * FROM system.admin_users WHERE email = $1', [email]);
    const user = result.rows[0];
    if (user && user.password_hash === password) {
      const token = jwt.sign({ sub: user.id, role: 'superadmin' }, process.env.SYSTEM_JWT_SECRET!, { expiresIn: '12h' });
      res.json({ token });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  } catch (e: any) { res.status(500).json({ error: e.message }); }
});

// STARTUP SEQUENCE
(async () => {
  try {
    console.log('[System] Starting Cascata Secure Engine v8.0 (Hardened)...');
    cleanTempUploads();
    app.listen(PORT, () => console.log(`[CASCATA SECURE ENGINE] Listening on port ${PORT}`));
    CertificateService.ensureSystemCert().catch(e => console.error("Cert Init Error:", e));
    waitForDatabase(30, 2000).then(async (ready) => {
        if (ready) await MigrationService.run(systemPool, MIGRATIONS_ROOT);
        else console.error('[System] CRITICAL: Main Database Unreachable.');
    });
  } catch (e) { console.error('[System] FATAL BOOT ERROR:', e); }
})();