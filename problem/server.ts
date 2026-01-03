import express, { Request, RequestHandler, NextFunction } from 'express';
import pg from 'pg';
import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';
import crypto from 'crypto';
import multer from 'multer';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';
import { Buffer } from 'buffer';
import bcrypt from 'bcrypt'; 

// IMPORT SERVICES
import { BackupService } from './services/BackupService.js';
import { ImportService } from './services/ImportService.js';
import { DatabaseService } from './services/DatabaseService.js';
import { AuthService } from './services/AuthService.js';
import { WebhookService } from './services/WebhookService.js';
import { PoolService } from './services/PoolService.js';
import { RateLimitService, AuthSecurityConfig } from './services/RateLimitService.js';
import { CertificateService } from './services/CertificateService.js';
import { MigrationService } from './services/MigrationService.js';
import { EdgeService } from './services/EdgeService.js';
import { QueueService } from './services/QueueService.js';
import { RealtimeService } from './services/RealtimeService.js';
import { OpenApiService } from './services/OpenApiService.js';
import { AiService } from './services/AiService.js';
import { PostgrestService } from './services/PostgrestService.js';
import { GoTrueService } from './services/GoTrueService.js';

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

// --- SECURITY: HARDENING HEADERS ---
// Aplicado antes de tudo para garantir resposta segura até em erros 4xx
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

// --- MULTER CONFIGURATION ---
const upload = multer({ 
    dest: path.join(__dirname, '../uploads'),
    limits: {
        fileSize: 100 * 1024 * 1024, // 100MB limit per file
        fieldSize: 10 * 1024 * 1024 // 10MB limit for text fields
    }
});

const backupUpload = multer({ 
    dest: TEMP_UPLOAD_ROOT,
    limits: { fileSize: 5 * 1024 * 1024 * 1024 } // 5GB for backups
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

// --- UTILS: STORAGE & SECURITY ---

const getSectorForExt = (ext: string): string => {
  const map: Record<string, string[]> = {
    visual: ['jpg', 'jpeg', 'png', 'gif', 'webp', 'svg', 'bmp', 'ico', 'tiff', 'avif', 'heic', 'heif'],
    motion: ['mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv', 'm4v', 'mpg', 'mpeg', '3gp'],
    audio: ['mp3', 'wav', 'flac', 'aac', 'ogg', 'm4a', 'wma', 'm4p', 'amr', 'mid', 'midi', 'opus'],
    docs: ['pdf', 'doc', 'docx', 'odt', 'rtf', 'txt', 'pages', 'epub', 'mobi', 'azw3'],
    structured: ['csv', 'json', 'xml', 'yaml', 'yml', 'sql', 'xls', 'xlsx', 'ods', 'tsv', 'parquet', 'avro'],
    archives: ['zip', 'rar', '7z', 'tar', 'gz', 'bz2', 'iso', 'dmg', 'pkg', 'xz', 'zst'],
    exec: ['exe', 'msi', 'bin', 'app', 'deb', 'rpm', 'sh', 'bat', 'cmd', 'vbs', 'ps1'],
    scripts: ['js', 'ts', 'py', 'rb', 'php', 'go', 'rs', 'c', 'cpp', 'h', 'java', 'cs', 'swift', 'kt'],
    config: ['env', 'config', 'ini', 'xml', 'manifest', 'lock', 'gitignore', 'editorconfig', 'toml'],
    telemetry: ['log', 'dump', 'out', 'err', 'crash', 'report', 'audit'],
    messaging: ['eml', 'msg', 'vcf', 'chat', 'ics', 'pbx'],
    ui_assets: ['ttf', 'otf', 'woff', 'woff2', 'eot', 'sketch', 'fig', 'ai', 'psd', 'xd'],
    simulation: ['obj', 'stl', 'fbx', 'dwg', 'dxf', 'dae', 'blend', 'step', 'iges', 'glf', 'gltf', 'glb'],
    backup_sys: ['bak', 'sql', 'snapshot', 'dump', 'db', 'sqlite', 'sqlite3', 'rdb']
  };
  for (const sector in map) {
    if (map[sector].includes(ext)) return sector;
  }
  return 'global';
};

const MAGIC_NUMBERS: Record<string, string[]> = {
    'jpg': ['FFD8FF'],
    'png': ['89504E47'],
    'gif': ['47494638'],
    'pdf': ['25504446'],
    'exe': ['4D5A'], 
    'zip': ['504B0304'],
    'rar': ['52617221'],
    'mp3': ['494433', 'FFF3', 'FFF2'],
    'mp4': ['000000', '66747970'],
};

const validateMagicBytes = (filePath: string, ext: string): boolean => {
    if (['exe', 'sh', 'php', 'pl', 'py', 'rb', 'bat', 'cmd', 'msi', 'vbs'].includes(ext)) {
        return false;
    }
    if (!MAGIC_NUMBERS[ext]) return true;
    try {
        const buffer = Buffer.alloc(4);
        const fd = fs.openSync(filePath, 'r');
        fs.readSync(fd, buffer, 0, 4, 0);
        fs.closeSync(fd);
        const hex = buffer.toString('hex').toUpperCase();
        return MAGIC_NUMBERS[ext].some(sig => hex.startsWith(sig) || sig.startsWith(hex));
    } catch (e) {
        return false; 
    }
};

const parseBytes = (sizeStr: string): number => {
  if (!sizeStr) return 2 * 1024 * 1024; // 2MB Fallback
  const match = sizeStr.toString().match(/^(\d+(?:\.\d+)?)\s*([a-zA-Z]+)?$/);
  if (!match) return parseInt(sizeStr) || 0;
  const num = parseFloat(match[1]);
  const unit = (match[2] || 'B').toUpperCase();
  const multipliers: Record<string, number> = { 'B': 1, 'KB': 1024, 'MB': 1024 * 1024, 'GB': 1024 * 1024 * 1024 };
  return Math.floor(num * (multipliers[unit] || 1));
};

const formatBytes = (bytes: number) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
};

const walk = (dir: string, rootPath: string, fileList: any[] = []) => {
  try {
    const files = fs.readdirSync(dir);
    files.forEach((file) => {
      const filePath = path.join(dir, file);
      const stat = fs.statSync(filePath);
      const relativePath = path.relative(rootPath, filePath).replace(/\\/g, '/');
      fileList.push({
        name: file,
        type: stat.isDirectory() ? 'folder' : 'file',
        size: stat.size,
        updated_at: stat.mtime.toISOString(),
        path: relativePath
      });
      if (stat.isDirectory()) {
        walk(filePath, rootPath, fileList);
      }
    });
  } catch (e) {
  }
  return fileList;
};

// --- MIDDLEWARES DE INFRAESTRUTURA ---

const dynamicCors: RequestHandler = (req: any, res: any, next: any) => {
    const origin = req.headers.origin;
    
    // Always allow credentials and common methods
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
    
    // CORRECTION: Added 'x-supabase-api-version' to allowed headers list.
    // This fixes the "Request header field x-supabase-api-version is not allowed" error.
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type,Authorization,apikey,x-cascata-client,Prefer,Range,x-client-info,x-supabase-auth,content-profile,accept-profile,x-supabase-api-version,x-cascata-signature,x-cascata-event');
    
    // Expose headers for PostgREST pagination
    res.setHeader('Access-Control-Expose-Headers', 'Content-Range, X-Total-Count, Link');

    // 1. If project is NOT yet resolved (early CORS), reflect origin to allow error responses to pass CORS
    if (!req.project) {
        if (origin) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        }
        if (req.method === 'OPTIONS') {
            return res.status(200).end();
        }
        return next();
    }

    // 2. Project Resolved: Apply Strict Metadata Rules if configured
    const allowedOrigins = req.project.metadata?.allowed_origins || [];
    const safeOrigins = allowedOrigins.map((o: any) => typeof o === 'string' ? o : o.url);
    
    if (safeOrigins.length === 0) {
        // Public Mode: Reflect Origin
        if (origin) res.setHeader('Access-Control-Allow-Origin', origin);
    } 
    else {
        // Strict Mode: Check Whitelist
        if (origin && safeOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        } else {
            // Blocked origin: Don't set header (Browser will block)
        }
    }

    if (req.method === 'OPTIONS') {
         return res.status(200).end();
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

  const pathParts = req.path.split('/');
  const slugFromUrl = (pathParts.length > 3 && pathParts[1] === 'api' && pathParts[2] === 'data') ? pathParts[3] : null;

  try {
    let projectResult: pg.QueryResult | undefined;
    let resolutionMethod = 'unknown';

    // FIX: Using explicit parameter order and type casting for pgp_sym_decrypt.
    // $1 = SYS_SECRET (used in Select list) ::text to be safe
    // $2 = Dynamic identifier (used in Where clause)
    const projectQuery = `
        SELECT 
            id, name, slug, db_name, custom_domain, ssl_certificate_source, blocklist, metadata, status,
            pgp_sym_decrypt(jwt_secret::bytea, $1::text) as jwt_secret,
            pgp_sym_decrypt(anon_key::bytea, $1::text) as anon_key,
            pgp_sym_decrypt(service_key::bytea, $1::text) as service_key
        FROM system.projects 
    `;

    if (host && !host.includes('localhost') && !host.includes('127.0.0.1')) {
      // PARAM ORDER: [SECRET, HOST]
      projectResult = await systemPool.query(`${projectQuery} WHERE custom_domain = $2`, [SYS_SECRET, host]);
      if ((projectResult.rowCount ?? 0) > 0) resolutionMethod = 'domain';
    }

    if ((!projectResult || (projectResult.rowCount ?? 0) === 0) && slugFromUrl) {
      // PARAM ORDER: [SECRET, SLUG]
      projectResult = await systemPool.query(`${projectQuery} WHERE slug = $2`, [SYS_SECRET, slugFromUrl]);
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
          hint: `Use https://${project.custom_domain}`
        });
        return;
      }
    }

    // Rewrite URL if accessing via Custom Domain so the Express Router can match /api/data/:slug
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
    console.error("Internal Resolution Error", e);
    res.status(500).json({ error: 'Internal Resolution Error' });
  }
};

const hostGuard: RequestHandler = async (req: any, res: any, next: any) => {
    // SECURITY: Se o projeto foi resolvido (por domínio customizado ou slug), PULA o guard.
    if (req.project) return next();
    
    if (req.path === '/' || req.path === '/health') return next();

    try {
        const settingsRes = await systemPool.query(
            "SELECT settings->>'domain' as domain FROM system.ui_settings WHERE project_slug = '_system_root_' AND table_name = 'domain_config'"
        );
        const systemDomain = settingsRes.rows[0]?.domain;
        const host = req.headers.host?.split(':')[0] || ''; 

        const isIp = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(host); 
        const isLocal = host === 'localhost' || host === '127.0.0.1' || host === 'cascata-backend-control' || host.startsWith('172.') || host.startsWith('10.');

        if (isIp || isLocal) return next();

        if (systemDomain) {
            if (host.toLowerCase() === systemDomain.toLowerCase()) return next();
        } else {
            return next();
        }

        console.warn(`[HostGuard] 404 Stealth Block: ${req.path} via ${host}. System Domain: ${systemDomain || 'None'}`);
        return res.status(404).send('Not Found');

    } catch (e) { next(); }
};

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

// --- DYNAMIC BODY PARSER (HARDENING) ---
// Substitui o middleware global express.json() para evitar DoS e "Noisy Neighbor"
const dynamicBodyParser: RequestHandler = (req, res, next) => {
    // SYSTEM HARD CAP: 50MB
    // Proteção final para a RAM do container, independente do que o usuário configurar no DB.
    // Uploads via Storage usam Stream (Multer), então isso afeta apenas JSON/Text puro.
    const SYSTEM_HARD_CAP_BYTES = 50 * 1024 * 1024; 
    
    let limitStr = '2mb'; // Default Conservador

    // Se temos um projeto resolvido, buscamos a configuração de segurança dele
    const proj = (req as any).project;
    if (proj?.metadata?.security?.max_json_size) {
        limitStr = proj.metadata.security.max_json_size;
    } 
    // Defaults inteligentes baseados no tipo de rota
    else if (req.path.includes('/edge/')) {
        limitStr = '10mb'; // Edge functions precisam de mais payload (ex: webhooks externos)
    } else if (req.path.includes('/import/')) {
        limitStr = '10mb'; // Manifestos de importação
    }

    const requestedBytes = parseBytes(limitStr);
    const safeLimit = Math.min(requestedBytes, SYSTEM_HARD_CAP_BYTES);

    // Aplica o parser com o limite calculado
    express.json({ limit: safeLimit })(req, res, (err) => {
        if (err) {
            return res.status(413).json({
                error: 'Payload Too Large',
                message: `Request body exceeds the limit of ${formatBytes(safeLimit)}`,
                code: 'PAYLOAD_TOO_LARGE'
            });
        }
        // Aplica também para form-urlencoded (HTML forms padrão)
        express.urlencoded({ extended: true, limit: safeLimit })(req, res, next);
    });
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

  // SUPABASE COMPATIBILITY: Check if Bearer token IS actually the Service Key or Anon Key
  if (bearerToken === r.project.service_key) {
    r.userRole = 'service_role';
    return next();
  }
  
  if (bearerToken === r.project.anon_key) {
      r.userRole = 'anon';
      return next();
  }

  if (apiKey === r.project.service_key) {
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

  // --- ALLOW PUBLIC ROUTES ---
  // Ensure authorize and callback are accessible without strict JWT (they handle their own logic)
  if (
      req.path.includes('/auth/providers/') || 
      req.path.includes('/auth/callback') || 
      req.path.includes('/auth/v1/authorize') || 
      req.path.includes('/auth/v1/callback') ||  
      req.path.includes('/auth/passwordless/') || 
      req.path.includes('/auth/token/refresh') ||
      req.path.includes('/auth/challenge') || // NEW
      req.path.includes('/auth/verify-challenge') // NEW
  ) {
      r.userRole = 'anon';
      return next();
  }

  if (req.path.includes('/auth/users') || req.path.includes('/auth/token')) {
      r.userRole = 'anon';
      return next();
  }

  // --- GOTRUE COMPATIBILITY (Public Access Fix) ---
  if (req.path.includes('/auth/v1/')) {
      r.userRole = r.userRole || 'anon';
      return next();
  }

  if (req.path.includes('/edge/')) {
      r.userRole = 'anon';
      return next();
  }

  // --- POSTGREST COMPATIBILITY CHECK ---
  res.status(401).json({ error: 'Unauthorized: Invalid API Key or JWT.' });
};

const detectSemanticAction = (method: string, path: string): string | null => {
    if (path.includes('/tables') && method === 'POST' && path.endsWith('/rows')) return 'INSERT_ROWS';
    if (path.includes('/tables') && method === 'POST') return 'CREATE_TABLE';
    if (path.includes('/tables') && method === 'DELETE' && !path.includes('/rows')) return 'DROP_TABLE';
    if (path.includes('/tables') && method === 'DELETE' && path.includes('/rows')) return 'DELETE_ROWS';
    if (path.includes('/tables') && method === 'PUT') return 'UPDATE_ROWS';
    if (path.includes('/rest/v1/') && method === 'GET') return 'REST_SELECT';
    if (path.includes('/rest/v1/') && method === 'POST') return 'REST_INSERT';
    if (path.includes('/rest/v1/') && method === 'PATCH') return 'REST_UPDATE';
    if (path.includes('/rest/v1/') && method === 'DELETE') return 'REST_DELETE';
    if (path.includes('/auth/token') && !path.includes('refresh')) return 'AUTH_LOGIN';
    if (path.includes('/auth/token/refresh')) return 'AUTH_REFRESH';
    if (path.includes('/auth/callback')) return 'AUTH_CALLBACK'; 
    if (path.includes('/auth/challenge')) return 'AUTH_CHALLENGE'; 
    if (path.includes('/auth/verify-challenge')) return 'AUTH_VERIFY';
    if (path.includes('/auth/users') && method === 'POST') return 'AUTH_REGISTER';
    if (path.includes('/storage') && method === 'POST' && path.includes('/upload')) return 'UPLOAD_FILE';
    if (path.includes('/storage') && method === 'DELETE') return 'DELETE_FILE';
    if (path.includes('/edge/')) return 'EDGE_INVOKE';
    
    // GoTrue mappings
    if (path.includes('/auth/v1/signup')) return 'GOTRUE_SIGNUP';
    if (path.includes('/auth/v1/token')) return 'GOTRUE_TOKEN';
    if (path.includes('/auth/v1/user')) return 'GOTRUE_USER';
    if (path.includes('/auth/v1/authorize')) return 'GOTRUE_OAUTH_START';
    if (path.includes('/auth/v1/callback')) return 'GOTRUE_OAUTH_CALLBACK';
    
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
        await client.query("SELECT set_config('request.jwt.claim.role', 'service_role', true)");
    } else {
        await client.query("SET ROLE cascata_api_role");
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

// APPLY MIDDLEWARES
// Order is critical for security and performance
app.use(dynamicCors as any);    // 1. CORS Preflight (Must handle OPTIONS even before body parsing)
app.use(resolveProject as any); // 2. Identify Project (Needed to know WHICH body limit to apply)
app.use(hostGuard as any);      // 3. Block unknown hostnames
app.use(controlPlaneFirewall as any); // 4. Protect Control Plane
app.use(dynamicBodyParser as any);    // 5. Intelligent Body Parsing (Uses project metadata from step 2)
app.use(dynamicRateLimiter as any);   // 6. Rate Limit (Needs project context)
app.use(auditLogger as any);          // 7. Audit (Needs parsed body for logs)
app.use(cascataAuth as any);          // 8. Auth/Role Resolution

// Health Check
app.get('/', (req, res) => { res.send('Cascata Engine OK'); });
app.get('/health', (req, res) => { res.json({ status: 'ok', time: new Date() }); });

app.get('/api/data/:slug/realtime', (req, res) => RealtimeService.handleConnection(req, res));

// --- DATA PLANE: TABLES ---

app.get('/api/data/:slug/tables/:tableName/data', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    try {
        const safeTable = quoteId(req.params.tableName);
        const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
        const offset = parseInt(req.query.offset) || 0;
        const result = await queryWithRLS(r, async (client) => {
            return await client.query(`SELECT * FROM public.${safeTable} LIMIT $1 OFFSET $2`, [limit, offset]);
        });
        res.json(result.rows);
    } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/tables/:tableName/rows', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    try {
        const safeTable = quoteId(req.params.tableName);
        const { data } = req.body;
        if (!data) throw new Error("No data provided");
        const rows = Array.isArray(data) ? data : [data];
        if (rows.length === 0) return res.json([]);
        const keys = Object.keys(rows[0]);
        const columns = keys.map(quoteId).join(', ');
        const valuesPlaceholder = rows.map((_, i) => `(${keys.map((_, j) => `$${i * keys.length + j + 1}`).join(', ')})`).join(', ');
        const flatValues = rows.flatMap(row => keys.map(k => row[k]));
        const result = await queryWithRLS(r, async (client) => {
            return await client.query(`INSERT INTO public.${safeTable} (${columns}) VALUES ${valuesPlaceholder} RETURNING *`, flatValues);
        });
        res.status(201).json(result.rows);
    } catch (e: any) { next(e); }
});

app.put('/api/data/:slug/tables/:tableName/rows', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    try {
        const safeTable = quoteId(req.params.tableName);
        const { data, pkColumn, pkValue } = req.body;
        if (!data || !pkColumn || pkValue === undefined) throw new Error("Missing data or PK");
        const updates = Object.keys(data).map((k, i) => `${quoteId(k)} = $${i + 1}`).join(', ');
        const values = Object.values(data);
        const pkValIndex = values.length + 1;
        const result = await queryWithRLS(r, async (client) => {
            return await client.query(`UPDATE public.${safeTable} SET ${updates} WHERE ${quoteId(pkColumn)} = $${pkValIndex} RETURNING *`, [...values, pkValue]);
        });
        res.json(result.rows);
    } catch (e: any) { next(e); }
});

app.delete('/api/data/:slug/tables/:tableName/rows', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    try {
        const safeTable = quoteId(req.params.tableName);
        const { ids, pkColumn } = req.body;
        if (!ids || !Array.isArray(ids) || !pkColumn) throw new Error("Invalid delete request");
        const result = await queryWithRLS(r, async (client) => {
            return await client.query(`DELETE FROM public.${safeTable} WHERE ${quoteId(pkColumn)} = ANY($1) RETURNING *`, [ids]);
        });
        res.json(result.rows);
    } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/tables', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    try {
        const result = await queryWithRLS(r, async (client) => {
            return await client.query(`SELECT table_name as name, table_schema as schema FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE' AND table_name NOT LIKE '_deleted_%'`);
        });
        res.json(result.rows);
    } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/tables/:tableName/columns', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    try {
        const result = await queryWithRLS(r, async (client) => {
            return await client.query(`SELECT column_name as name, data_type as type, is_nullable, column_default as "defaultValue", EXISTS (SELECT 1 FROM information_schema.key_column_usage kcu WHERE kcu.table_name = $1 AND kcu.column_name = c.column_name) as "isPrimaryKey" FROM information_schema.columns c WHERE table_schema = 'public' AND table_name = $1`, [req.params.tableName]);
        });
        res.json(result.rows);
    } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/tables', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    if (!r.isSystemRequest) { res.status(403).json({ error: 'Only Dashboard can create tables.' }); return; }
    const { name, columns, description } = req.body;
    if (!name || !columns) { res.status(400).json({ error: 'Missing table def' }); return; }
    try {
        if (r.projectPool) await DatabaseService.validateTableDefinition(r.projectPool, name, columns);
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
        await r.projectPool!.query(sql);
        await r.projectPool!.query(`ALTER TABLE public.${safeName} ENABLE ROW LEVEL SECURITY`);
        await r.projectPool!.query(`CREATE TRIGGER ${name}_changes AFTER INSERT OR UPDATE OR DELETE ON public.${safeName} FOR EACH ROW EXECUTE FUNCTION public.notify_changes();`);
        if (description) await r.projectPool!.query(`COMMENT ON TABLE public.${safeName} IS $1`, [description]);
        res.json({ success: true });
    } catch (e: any) { next(e); }
});

app.delete('/api/data/:slug/tables/:table', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  if (!r.isSystemRequest) { res.status(403).json({ error: 'Only Dashboard can delete tables.' }); return; }
  const { mode } = req.body;
  try {
    if (mode === 'CASCADE' || mode === 'RESTRICT') {
        const cascadeSql = mode === 'CASCADE' ? 'CASCADE' : '';
        await r.projectPool!.query(`DROP TABLE public.${quoteId(req.params.table)} ${cascadeSql}`);
    } else {
        const deletedName = `_deleted_${Date.now()}_${req.params.table}`;
        await r.projectPool!.query(`ALTER TABLE public.${quoteId(req.params.table)} RENAME TO ${quoteId(deletedName)}`);
    }
    res.json({ success: true });
  } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/recycle-bin', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  if (!r.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
  try {
    const result = await r.projectPool!.query("SELECT table_name as name FROM information_schema.tables WHERE table_schema = 'public' AND table_name LIKE '_deleted_%'");
    res.json(result.rows);
  } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/recycle-bin/:table/restore', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  if (!r.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
  try {
    const originalName = req.params.table.replace(/^_deleted_\d+_/, '');
    await r.projectPool!.query(`ALTER TABLE public.${quoteId(req.params.table)} RENAME TO ${quoteId(originalName)}`);
    res.json({ success: true, restoredName: originalName });
  } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/query', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  if (r.userRole !== 'service_role') { res.status(403).json({ error: 'Only Service Role can execute raw SQL' }); return; }
  try {
    const start = Date.now();
    const result = await r.projectPool!.query(req.body.sql);
    res.json({ rows: result.rows, rowCount: result.rowCount, command: result.command, duration: Date.now() - start });
  } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/stats', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  if (!r.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
  try {
    const [tables, users, size] = await Promise.all([
      r.projectPool!.query("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public' AND table_name NOT LIKE '_deleted_%'"),
      r.projectPool!.query("SELECT count(*) FROM auth.users"),
      r.projectPool!.query("SELECT pg_size_pretty(pg_database_size(current_database()))")
    ]);
    res.json({ tables: parseInt(tables.rows[0].count), users: parseInt(users.rows[0].count), size: size.rows[0].pg_size_pretty });
  } catch (e: any) { next(e); }
});

// --- ASSETS, FUNCTIONS & HISTORY ---

app.get('/api/data/:slug/assets', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  try { const result = await systemPool.query('SELECT * FROM system.assets WHERE project_slug = $1', [r.project.slug]); res.json(result.rows); } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/assets', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const { id, name, type, parent_id, metadata } = req.body;
  try {
    let assetId = id;
    const safeParentId = (parent_id === 'root' || parent_id === '') ? null : parent_id;

    if (id) {
       // Update Logic: Handles renaming and moving
       let query = 'UPDATE system.assets SET name=$1, metadata=$2 WHERE id=$3 RETURNING *';
       let params = [name, metadata, id];

       if (parent_id !== undefined) {
           query = 'UPDATE system.assets SET name=$1, metadata=$2, parent_id=$4 WHERE id=$3 RETURNING *';
           params = [name, metadata, id, safeParentId];
       }

       const upd = await systemPool.query(query, params);
       assetId = upd.rows[0].id;
       res.json(upd.rows[0]);
    } else {
       const ins = await systemPool.query('INSERT INTO system.assets (project_slug, name, type, parent_id, metadata) VALUES ($1, $2, $3, $4, $5) RETURNING *', [r.project.slug, name, type, safeParentId, metadata]);
       assetId = ins.rows[0].id;
       res.json(ins.rows[0]);
    }

    if (metadata?.sql) {
        systemPool.query('INSERT INTO system.asset_history (asset_id, project_slug, content, metadata, created_by) VALUES ($1, $2, $3, $4, $5)', [assetId, r.project.slug, metadata.sql, metadata, r.userRole]);
    }
  } catch (e: any) { next(e); }
});

app.delete('/api/data/:slug/assets/:id', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(req.params.id)) {
      return res.json({ success: true, message: "Native asset ignored from system delete" });
  }
  try { await systemPool.query('DELETE FROM system.assets WHERE id=$1', [req.params.id]); res.json({ success: true }); } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/assets/:id/history', async (req: any, res: any, next: NextFunction) => {
    try {
        const result = await systemPool.query('SELECT id, created_at, created_by, metadata FROM system.asset_history WHERE asset_id = $1 ORDER BY created_at DESC LIMIT 50', [req.params.id]);
        res.json(result.rows);
    } catch (e: any) { next(e); }
});

// --- RPC EXECUTION ---

const handleRpcExecution = async (req: CascataRequest, res: any, next: NextFunction) => {
    const params = req.body || {};
    const placeholders = Object.keys(params).map((_, i) => `$${i + 1}`).join(', ');
    const values = Object.values(params);
    try {
        const rows = await queryWithRLS(req, async (client) => {
            const result = await client.query(`SELECT * FROM public.${quoteId(req.params.name)}(${placeholders})`, values);
            return result.rows;
        });
        res.json(rows);
    } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/rpc/:name', async (req: any, res: any, next: NextFunction) => {
    handleRpcExecution(req as CascataRequest, res, next);
});

// PostgREST RPC Compatibility Route
app.post('/api/data/:slug/rest/v1/rpc/:name', async (req: any, res: any, next: NextFunction) => {
    handleRpcExecution(req as CascataRequest, res, next);
});

app.get('/api/data/:slug/functions', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  try { 
      const result = await r.projectPool!.query(`
        SELECT routine_name as name 
        FROM information_schema.routines 
        WHERE routine_schema = 'public' 
        AND routine_name NOT LIKE 'uuid_%' 
        AND routine_name NOT LIKE 'pgp_%'
        AND routine_name NOT LIKE 'armor%'
        AND routine_name NOT LIKE 'crypt%'
        AND routine_name NOT LIKE 'digest%'
        AND routine_name NOT LIKE 'hmac%'
        AND routine_name NOT LIKE 'gen_random%'
        AND routine_name NOT LIKE 'gen_salt%'
        AND routine_name NOT LIKE 'encrypt%'
        AND routine_name NOT LIKE 'decrypt%'
        AND routine_name NOT IN ('notify_changes', 'dearmor')
      `); 
      res.json(result.rows); 
  } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/triggers', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  try { const result = await r.projectPool!.query("SELECT trigger_name as name FROM information_schema.triggers"); res.json(result.rows); } catch (e: any) { next(e); }
});

// --- INTROSPECTION (ENHANCED WITH ARGS) ---

app.get('/api/data/:slug/rpc/:name/definition', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    if (!r.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
    try {
        const defResult = await r.projectPool!.query(
            "SELECT pg_get_functiondef(oid) as def FROM pg_proc WHERE proname = $1 AND pronamespace = (SELECT oid FROM pg_namespace WHERE nspname = 'public')",
            [req.params.name]
        );
        const argsResult = await r.projectPool!.query(`
            SELECT parameter_name as name, data_type as type, ordinal_position
            FROM information_schema.parameters
            WHERE specific_name = (
                SELECT specific_name 
                FROM information_schema.routines 
                WHERE routine_name = $1 AND routine_schema = 'public' LIMIT 1
            )
            ORDER BY ordinal_position ASC
        `, [req.params.name]);

        if (defResult.rows.length === 0) return res.status(404).json({ error: 'Function not found' });
        
        res.json({ definition: defResult.rows[0].def, args: argsResult.rows });
    } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/trigger/:name/definition', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    if (!r.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
    try {
        const result = await r.projectPool!.query(
            "SELECT pg_get_triggerdef(oid) as def FROM pg_trigger WHERE tgname = $1",
            [req.params.name]
        );
        if (result.rows.length === 0) return res.status(404).json({ error: 'Trigger not found' });
        res.json({ definition: result.rows[0].def });
    } catch (e: any) { next(e); }
});

app.delete('/api/data/:slug/rpc/:name', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    if (!r.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
    try {
        await r.projectPool!.query(`DROP FUNCTION IF EXISTS public.${quoteId(req.params.name)} CASCADE`);
        res.json({ success: true });
    } catch (e: any) { next(e); }
});

app.delete('/api/data/:slug/trigger/:name', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    if (!r.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
    try {
        const tableRes = await r.projectPool!.query("SELECT event_object_table FROM information_schema.triggers WHERE trigger_name = $1", [req.params.name]);
        if (tableRes.rows.length === 0) return res.status(404).json({ error: 'Trigger not found' });
        const tableName = tableRes.rows[0].event_object_table;
        await r.projectPool!.query(`DROP TRIGGER IF EXISTS ${quoteId(req.params.name)} ON public.${quoteId(tableName)} CASCADE`);
        res.json({ success: true });
    } catch (e: any) { next(e); }
});

// --- DATA PLANE: AUTH ---
app.get('/api/data/:slug/auth/users', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  if (!r.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
  try { const result = await r.projectPool!.query(`SELECT u.id, u.created_at, u.banned, u.last_sign_in_at, jsonb_agg(jsonb_build_object('id', i.id, 'provider', i.provider, 'identifier', i.identifier)) as identities FROM auth.users u LEFT JOIN auth.identities i ON u.id = i.user_id GROUP BY u.id ORDER BY u.created_at DESC`); res.json(result.rows); } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/auth/users', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const { strategies, profileData } = req.body; 
  try {
    const client = await r.projectPool!.connect();
    try {
        await client.query('BEGIN');
        const userRes = await client.query('INSERT INTO auth.users (raw_user_meta_data) VALUES ($1) RETURNING id', [profileData || {}]);
        const userId = userRes.rows[0].id;
        if (strategies) {
            for (const s of strategies) {
                let passwordHash = s.password;
                if (s.password) passwordHash = await bcrypt.hash(s.password, 10);
                await client.query('INSERT INTO auth.identities (user_id, provider, identifier, password_hash) VALUES ($1, $2, $3, $4)', [userId, s.provider, s.identifier, passwordHash]);
            }
        }
        await client.query('COMMIT');
        res.json({ success: true, id: userId });
    } finally { client.release(); }
  } catch (e: any) { next(e); }
});

// --- NEW ROUTE: Identity Linking (Phase 4) ---
app.post('/api/data/:slug/auth/users/:id/identities', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    if (!r.isSystemRequest && r.userRole !== 'service_role') { 
        return res.status(403).json({ error: 'Unauthorized' }); 
    }
    const { provider, identifier, password } = req.body;
    const userId = req.params.id;

    if (!provider || !identifier) return res.status(400).json({ error: "Missing parameters" });

    try {
        let passwordHash = null;
        if (password) {
            passwordHash = await bcrypt.hash(password, 10);
        }

        // Link Identity by Upserting User (AuthService handles identity logic)
        // But here we want explicit linking, so we use SQL directly to append identity
        const client = await r.projectPool!.connect();
        try {
            await client.query('BEGIN');
            
            // Check if identity already exists
            const check = await client.query('SELECT id FROM auth.identities WHERE provider = $1 AND identifier = $2', [provider, identifier]);
            if (check.rows.length > 0) {
                throw new Error("Identity already linked to a user.");
            }

            await client.query(
                `INSERT INTO auth.identities (user_id, provider, identifier, password_hash, created_at, last_sign_in_at)
                 VALUES ($1, $2, $3, $4, now(), now())`,
                [userId, provider, identifier, passwordHash]
            );
            
            await client.query('COMMIT');
            res.json({ success: true });
        } catch(e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }
    } catch (e: any) { next(e); }
});

app.delete('/api/data/:slug/auth/users/:id/strategies/:identityId', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    if (!r.isSystemRequest && r.userRole !== 'service_role') { return res.status(403).json({ error: 'Unauthorized' }); }
    try { 
        // Prevent deleting the last identity
        const countRes = await r.projectPool!.query('SELECT count(*) FROM auth.identities WHERE user_id = $1', [req.params.id]);
        if (parseInt(countRes.rows[0].count) <= 1) {
            return res.status(400).json({ error: "Cannot remove the only identity linked to this user." });
        }
        await r.projectPool!.query('DELETE FROM auth.identities WHERE id = $1 AND user_id = $2', [req.params.identityId, req.params.id]); 
        res.json({ success: true }); 
    } catch (e: any) { next(e); }
});

app.patch('/api/data/:slug/auth/users/:id/status', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    if (!r.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
    try { await r.projectPool!.query('UPDATE auth.users SET banned = $1 WHERE id = $2', [req.body.banned, req.params.id]); res.json({ success: true }); } catch (e: any) { next(e); }
});

app.delete('/api/data/:slug/auth/users/:id', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    if (!r.isSystemRequest) { res.status(403).json({ error: 'Unauthorized' }); return; }
    try { await r.projectPool!.query('DELETE FROM auth.users WHERE id = $1', [req.params.id]); res.json({ success: true }); } catch (e: any) { next(e); }
});

// --- BRUTE FORCE PROTECTION WRAPPER ---
// Helper to extract Auth Security Config from project metadata
const getAuthSecurityConfig = (req: CascataRequest): AuthSecurityConfig => {
    const meta = req.project?.metadata?.auth_config?.security || {};
    return {
        max_attempts: meta.max_attempts || 5,
        lockout_minutes: meta.lockout_minutes || 15,
        strategy: meta.strategy || 'hybrid'
    };
};

// LEGACY AUTH (Used by Dashboard)
app.post('/api/data/:slug/auth/token', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    const { provider, identifier, password } = req.body;
    
    // 1. IP & Email for Lockout Check
    const forwarded = req.headers['x-forwarded-for'];
    const realIp = req.headers['x-real-ip'];
    const socketIp = req.socket?.remoteAddress;
    let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
    clientIp = clientIp.replace('::ffff:', '');
    
    const secConfig = getAuthSecurityConfig(r);

    try {
        // 2. CHECK LOCKOUT
        const lockout = await RateLimitService.checkAuthLockout(r.project.slug, clientIp, identifier, secConfig);
        if (lockout.locked) {
            return res.status(429).json({ error: lockout.reason });
        }

        const idRes = await r.projectPool!.query('SELECT * FROM auth.identities WHERE provider = $1 AND identifier = $2', [provider, identifier]);
        if (!idRes.rows[0]) {
            // Register Failure (Invalid User)
            await RateLimitService.registerAuthFailure(r.project.slug, clientIp, identifier, secConfig);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        const storedHash = idRes.rows[0].password_hash;
        let isValid = false;
        if (!storedHash.startsWith('$2')) {
            if (storedHash === password) { isValid = true; await r.projectPool!.query('UPDATE auth.identities SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(password, 10), idRes.rows[0].id]); }
        } else { isValid = await bcrypt.compare(password, storedHash); }
        
        if (!isValid) {
            // Register Failure (Bad Password)
            await RateLimitService.registerAuthFailure(r.project.slug, clientIp, identifier, secConfig);
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        
        // Success: Clear Failures
        await RateLimitService.clearAuthFailure(r.project.slug, clientIp, identifier);

        const session = await AuthService.createSession(idRes.rows[0].user_id, r.projectPool!, r.project.jwt_secret);
        res.json(session);
    } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/auth/link', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const { linked_tables, authStrategies, authConfig } = req.body;
  try {
    const metaUpdates: any = {};
    if (authStrategies) metaUpdates.auth_strategies = authStrategies;
    if (authConfig) metaUpdates.auth_config = authConfig;
    if (linked_tables) metaUpdates.linked_tables = linked_tables;
    await systemPool.query(`UPDATE system.projects SET metadata = COALESCE(metadata, '{}'::jsonb) || $1::jsonb WHERE slug = $2`, [JSON.stringify(metaUpdates), r.project.slug]);
    if (linked_tables && Array.isArray(linked_tables) && linked_tables.length > 0) {
        const client = await r.projectPool!.connect();
        try {
            await client.query('BEGIN');
            for (const table of linked_tables) {
                await client.query(`ALTER TABLE public.${quoteId(table)} ADD COLUMN IF NOT EXISTS user_id UUID REFERENCES auth.users(id) ON DELETE SET NULL`);
                await client.query(`CREATE INDEX IF NOT EXISTS ${quoteId('idx_' + table + '_user_id')} ON public.${quoteId(table)} (user_id)`);
            }
            await client.query('COMMIT');
        } finally { client.release(); }
    }
    res.json({ success: true });
  } catch (e: any) { next(e); }
});

// --- CLOSED LOOP OTP ROUTES (NEW PHASE 4) ---

// 1. Initiate Challenge (Send OTP)
app.post('/api/data/:slug/auth/challenge', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    const { provider, identifier } = req.body;
    
    if (!provider || !identifier) return res.status(400).json({ error: 'Provider and Identifier required' });

    try {
        const strategies = r.project.metadata?.auth_strategies || {};
        const config = strategies[provider];
        
        if (!config || !config.enabled) {
            return res.status(400).json({ error: `Strategy ${provider} not enabled.` });
        }

        const webhookUrl = config.webhook_url;
        if (!webhookUrl) return res.status(500).json({ error: `Webhook URL not configured for ${provider}` });

        const otpConfig = config.otp_config || { length: 6, charset: 'numeric' };

        await AuthService.initiatePasswordless(
            r.projectPool!,
            provider,
            identifier,
            webhookUrl,
            r.project.jwt_secret, // Use JWT secret as signature key for webhook
            otpConfig
        );

        res.json({ success: true, message: 'Challenge sent' });
    } catch(e: any) {
        next(e);
    }
});

// 2. Verify Challenge (Validate OTP & Create Session)
app.post('/api/data/:slug/auth/verify-challenge', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    const { provider, identifier, code } = req.body;

    if (!provider || !identifier || !code) return res.status(400).json({ error: 'Missing parameters' });

    try {
        // 1. Verify Code
        const profile = await AuthService.verifyPasswordless(
            r.projectPool!,
            provider,
            identifier,
            code
        );

        // 2. Upsert User (Link or Create)
        const userId = await AuthService.upsertUser(r.projectPool!, profile);

        // 3. Create Session
        const session = await AuthService.createSession(userId, r.projectPool!, r.project.jwt_secret);

        res.json(session);
    } catch(e: any) {
        next(e);
    }
});


// --- NEW GOTRUE/SUPABASE COMPATIBILITY LAYER ---

// 1. Signup
app.post('/api/data/:slug/auth/v1/signup', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    try {
        const response = await GoTrueService.handleSignup(
            r.projectPool!, 
            req.body, 
            r.project.jwt_secret
        );
        res.json(response);
    } catch(e: any) {
        next(e); // Passa para o error handler formatado
    }
});

// 2. Token (Login / Refresh) with BRUTE FORCE PROTECTION
app.post('/api/data/:slug/auth/v1/token', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    
    // IP extraction for Brute Force
    const forwarded = req.headers['x-forwarded-for'];
    const realIp = req.headers['x-real-ip'];
    const socketIp = req.socket?.remoteAddress;
    let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
    clientIp = clientIp.replace('::ffff:', '');
    
    const email = req.body.email;
    const secConfig = getAuthSecurityConfig(r);

    try {
        // Only enforce lockout on password grants
        if (req.body.grant_type === 'password') {
            const lockout = await RateLimitService.checkAuthLockout(r.project.slug, clientIp, email, secConfig);
            if (lockout.locked) {
                return res.status(429).json({ error: lockout.reason, error_description: lockout.reason });
            }
        }

        const response = await GoTrueService.handleToken(
            r.projectPool!, 
            req.body, 
            r.project.jwt_secret,
            r.project.metadata || {} // Pass metadata as projectConfig
        );
        
        // Success: Clear Failures
        if (req.body.grant_type === 'password') {
            await RateLimitService.clearAuthFailure(r.project.slug, clientIp, email);
        }

        res.json(response);
    } catch(e: any) {
        // Failure: Register Attempt
        if (req.body.grant_type === 'password') {
            await RateLimitService.registerAuthFailure(r.project.slug, clientIp, email, secConfig);
        }
        next(e);
    }
});

// 3. User Details
app.get('/api/data/:slug/auth/v1/user', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    if (!r.user || !r.user.sub) {
        return res.status(401).json({ error: "unauthorized", error_description: "Missing or invalid token" });
    }
    try {
        const user = await GoTrueService.handleGetUser(r.projectPool!, r.user.sub);
        res.json(user);
    } catch(e: any) {
        res.status(404).json({ error: "not_found", error_description: e.message });
    }
});

// 4. Logout (Real Revocation)
app.post('/api/data/:slug/auth/v1/logout', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: "unauthorized" });

    const token = authHeader.replace('Bearer ', '').trim();
    
    try {
        await GoTrueService.handleLogout(r.projectPool!, token, r.project.jwt_secret);
        res.status(204).send();
    } catch(e) {
        res.status(500).json({ error: "server_error" });
    }
});

// --- NEW OAUTH ROUTES (Google) ---

// 5. Authorize (Start OAuth Flow)
app.get('/api/data/:slug/auth/v1/authorize', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    const { provider, redirect_to } = req.query;

    if (!provider) return res.status(400).json({ error: 'Provider required' });

    try {
        const providerConfig = r.project.metadata?.auth_config?.providers?.[provider as string];
        if (!providerConfig || !providerConfig.client_id) {
             return res.status(400).json({ error: `Provider ${provider} not configured.` });
        }

        const protocol = req.headers['x-forwarded-proto'] || 'http';
        const host = req.headers.host;
        let callbackUrl = '';

        if (r.project.custom_domain && host === r.project.custom_domain) {
            callbackUrl = `${protocol}://${host}/auth/v1/callback`;
        } else {
            callbackUrl = `${protocol}://${host}/api/data/${r.project.slug}/auth/v1/callback`;
        }

        const config = {
            clientId: providerConfig.client_id,
            redirectUri: callbackUrl
        };

        // CORRECTION: Intelligent Redirect Fallback
        // Se o cliente (FlutterFlow) não enviou redirect_to, tentamos adivinhar baseado nas configurações do projeto.
        let targetRedirect = redirect_to as string;
        
        if (!targetRedirect) {
            // 1. Tenta pegar a primeira "Allowed Origin" configurada no painel
            const origins = r.project.metadata?.allowed_origins || [];
            if (origins.length > 0) {
                 const first = origins[0];
                 targetRedirect = typeof first === 'string' ? first : first.url;
            }
            
            // 2. Se ainda não tiver, tenta usar o Referer do request (quem clicou no botão)
            if (!targetRedirect && req.headers.referer) {
                try {
                    // Limpa o referer para pegar apenas a origem
                    const refUrl = new URL(req.headers.referer);
                    targetRedirect = refUrl.origin;
                } catch(e) {}
            }
        }

        // State is used to persist the final redirect_to URL
        const statePayload = { redirectTo: targetRedirect || '' };
        const state = Buffer.from(JSON.stringify(statePayload)).toString('base64');

        const authUrl = AuthService.getAuthUrl(provider as string, config, state);
        res.redirect(authUrl);

    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

// 6. Callback (Finish OAuth Flow)
app.get('/api/data/:slug/auth/v1/callback', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    const { code, state, error } = req.query;

    if (error) return res.status(400).json({ error: 'OAuth Error', details: error });
    if (!code) return res.status(400).json({ error: 'No code provided' });

    try {
        // Decode state to get the original redirect URL
        let finalRedirect = '';
        if (state) {
            try {
                const decodedState = JSON.parse(Buffer.from(state as string, 'base64').toString('utf8'));
                finalRedirect = decodedState.redirectTo;
            } catch(e) {}
        }

        // Se o state veio vazio, tenta fallback para site_url configurado
        if (!finalRedirect) {
             const siteUrl = r.project.metadata?.auth_config?.site_url;
             if (siteUrl) {
                 finalRedirect = siteUrl;
             } else {
                 // Fallback final: Allowed Origins
                 const origins = r.project.metadata?.allowed_origins || [];
                 if (origins.length > 0) {
                     const first = origins[0];
                     finalRedirect = typeof first === 'string' ? first : first.url;
                 }
             }
        }

        const provider = 'google'; 
        const providerConfig = r.project.metadata?.auth_config?.providers?.[provider];
        if (!providerConfig) throw new Error("Provider config missing");

        const protocol = req.headers['x-forwarded-proto'] || 'http';
        const host = req.headers.host;
        let callbackUrl = '';
        if (r.project.custom_domain && host === r.project.custom_domain) {
            callbackUrl = `${protocol}://${host}/auth/v1/callback`;
        } else {
            callbackUrl = `${protocol}://${host}/api/data/${r.project.slug}/auth/v1/callback`;
        }

        const config = {
            clientId: providerConfig.client_id,
            clientSecret: providerConfig.client_secret,
            redirectUri: callbackUrl
        };

        const profile = await AuthService.handleCallback(provider, code as string, config);
        const userId = await AuthService.upsertUser(r.projectPool!, profile);
        const session = await AuthService.createSession(userId, r.projectPool!, r.project.jwt_secret);

        // Access Token Hash Fragment (Supabase Style)
        const hash = `access_token=${session.access_token}&refresh_token=${session.refresh_token}&expires_in=${session.expires_in}&token_type=bearer&type=recovery`;
        
        if (finalRedirect) {
            // Remove trailing slash to avoid double slash
            const cleanRedirect = finalRedirect.endsWith('/') ? finalRedirect.slice(0, -1) : finalRedirect;
            res.redirect(`${cleanRedirect}#${hash}`);
        } else {
            // HTML Fallback for missing redirect
            res.send(`
                <html>
                    <head>
                        <title>Login Successful</title>
                        <style>
                            body { font-family: sans-serif; text-align: center; padding: 50px; background: #f8fafc; color: #334155; }
                            .card { background: white; padding: 40px; border-radius: 20px; box-shadow: 0 10px 30px rgba(0,0,0,0.1); max-width: 400px; margin: 0 auto; }
                            h3 { color: #4F46E5; margin-bottom: 10px; }
                        </style>
                    </head>
                    <body>
                        <div class="card">
                            <h3>Autenticação Concluída</h3>
                            <p>Você pode fechar esta janela e retornar ao aplicativo.</p>
                        </div>
                        <script>
                            // Tenta enviar mensagem para a janela pai (Popups / WebViews)
                            if (window.opener) {
                                window.opener.postMessage({ session: ${JSON.stringify(session)}, error: null }, '*');
                                window.close();
                            }
                        </script>
                    </body>
                </html>
            `);
        }

    } catch (e: any) {
        res.status(500).json({ error: e.message });
    }
});

// --- DATA PLANE: STORAGE ---
app.get('/api/data/:slug/storage/search', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const { q, bucket } = req.query;
  const searchTerm = (q as string || '').toLowerCase();
  const projectRoot = path.join(STORAGE_ROOT, r.project.slug);
  const searchRoot = bucket ? path.join(projectRoot, bucket as string) : projectRoot;
  if (!fs.existsSync(searchRoot)) { res.json({ items: [] }); return; }
  if (!searchRoot.startsWith(projectRoot)) { res.status(403).json({ error: 'Access Denied' }); return; }
  try {
    let allFiles = walk(searchRoot, bucket ? searchRoot : projectRoot, []);
    if (searchTerm) allFiles = allFiles.filter(f => f.name.toLowerCase().includes(searchTerm));
    res.json({ items: allFiles });
  } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/storage/buckets', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const p = path.join(STORAGE_ROOT, r.project.slug);
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
  const items = fs.readdirSync(p).filter(f => fs.lstatSync(path.join(p, f)).isDirectory());
  res.json(items.map(name => ({ name })));
});

app.post('/api/data/:slug/storage/buckets', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const p = path.join(STORAGE_ROOT, r.project.slug, req.body.name);
  if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
  res.json({ success: true });
});

app.patch('/api/data/:slug/storage/buckets/:name', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const oldPath = path.join(STORAGE_ROOT, r.project.slug, req.params.name);
  const newPath = path.join(STORAGE_ROOT, r.project.slug, req.body.newName);
  if (!fs.existsSync(oldPath)) { res.status(404).json({ error: 'Bucket not found' }); return; }
  if (fs.existsSync(newPath)) { res.status(400).json({ error: 'Name already exists' }); return; }
  fs.renameSync(oldPath, newPath);
  res.json({ success: true });
});

app.delete('/api/data/:slug/storage/buckets/:name', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const bucketPath = path.join(STORAGE_ROOT, r.project.slug, req.params.name);
  if (!fs.existsSync(bucketPath)) { res.status(404).json({ error: 'Bucket not found' }); return; }
  if (!bucketPath.startsWith(path.join(STORAGE_ROOT, r.project.slug))) { res.status(403).json({ error: 'Access denied' }); return; }
  try { fs.rmSync(bucketPath, { recursive: true, force: true }); res.json({ success: true }); } catch (e: any) { res.status(500).json({ error: e.message }); }
});

app.post('/api/data/:slug/storage/:bucket/folder', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const { name, path: relativePath } = req.body;
  const bucketPath = path.join(STORAGE_ROOT, r.project.slug, req.params.bucket);
  const folderPath = path.join(bucketPath, relativePath || '', name);
  if (!folderPath.startsWith(bucketPath)) { res.status(403).json({ error: 'Access Denied' }); return; }
  if (!fs.existsSync(folderPath)) { fs.mkdirSync(folderPath, { recursive: true }); res.json({ success: true }); } else { res.status(400).json({ error: 'Folder exists' }); }
});

app.get('/api/data/:slug/storage/:bucket/list', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const { path: queryPath } = req.query;
  const bucketPath = path.join(STORAGE_ROOT, r.project.slug, req.params.bucket);
  const targetPath = path.join(bucketPath, (queryPath as string) || '');
  if (!targetPath.startsWith(bucketPath)) { res.status(403).json({ error: 'Access Denied' }); return; }
  if (!fs.existsSync(targetPath)) { res.json({ items: [] }); return; }
  try {
    const files = fs.readdirSync(targetPath);
    const items = files.map(file => {
      const filePath = path.join(targetPath, file);
      const stat = fs.statSync(filePath);
      return { name: file, type: stat.isDirectory() ? 'folder' : 'file', size: stat.size, updated_at: stat.mtime.toISOString(), path: path.relative(bucketPath, filePath).replace(/\\/g, '/') };
    });
    res.json({ items });
  } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/storage/:bucket/object/*', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const relativePath = req.params[0];
  const bucketPath = path.join(STORAGE_ROOT, r.project.slug, req.params.bucket);
  const filePath = path.join(bucketPath, relativePath);
  if (!filePath.startsWith(bucketPath)) { res.status(403).json({ error: 'Path Traversal Detected' }); return; }
  if (!fs.existsSync(filePath)) { res.status(404).json({ error: 'File Not Found' }); return; }
  res.sendFile(filePath);
});

app.post('/api/data/:slug/storage/:bucket/upload', async (req: any, res: any, next: NextFunction) => {
    (upload.single('file') as any)(req, res, async (err: any) => {
        if (err) return next(err);
        const r = req as CascataRequest;
        if (!r.file) return res.status(400).json({ error: 'No file found in request body.' });
        try {
            const governance = r.project.metadata?.storage_governance || {};
            const ext = path.extname(r.file.originalname).replace('.', '').toLowerCase();
            const sector = getSectorForExt(ext);
            const rule = governance[sector] || governance['global'] || { max_size: '10MB', allowed_exts: [] };
            if (rule.allowed_exts && rule.allowed_exts.length > 0 && !rule.allowed_exts.includes(ext)) { fs.unlinkSync(r.file.path); return res.status(403).json({ error: `Policy Violation: Extension .${ext} is not allowed.` }); }
            if (!validateMagicBytes(r.file.path, ext)) { fs.unlinkSync(r.file.path); return res.status(400).json({ error: 'Security Alert: File signature mismatch (Spoofing detected).' }); }
            if (r.file.size > parseBytes(rule.max_size)) { fs.unlinkSync(r.file.path); return res.status(403).json({ error: `Policy Violation: File size exceeds limit of ${rule.max_size}.` }); }
            const dest = path.join(STORAGE_ROOT, r.project.slug, req.params.bucket, r.body.path || '', r.file.originalname);
            if (!fs.existsSync(path.dirname(dest))) fs.mkdirSync(path.dirname(dest), { recursive: true });
            fs.renameSync(r.file.path, dest);
            res.json({ success: true, path: dest.replace(STORAGE_ROOT, '') });
        } catch (e: any) { if(r.file && fs.existsSync(r.file.path)) fs.unlinkSync(r.file.path); next(e); }
    });
});

app.post('/api/data/:slug/storage/move', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const { bucket, paths, destination } = req.body;
  const root = path.join(STORAGE_ROOT, r.project.slug);
  const destPath = path.join(root, destination.bucket || bucket, destination.path || '');
  if (!fs.existsSync(destPath)) fs.mkdirSync(destPath, { recursive: true });
  let movedCount = 0;
  for (const itemPath of paths) {
      const source = path.join(root, bucket, itemPath);
      const target = path.join(destPath, path.basename(itemPath));
      if (fs.existsSync(source)) { fs.renameSync(source, target); movedCount++; }
  }
  res.json({ success: true, moved: movedCount });
});

app.delete('/api/data/:slug/storage/:bucket/object', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const filePath = path.join(STORAGE_ROOT, r.project.slug, req.params.bucket, (req.query.path as string));
  if (fs.existsSync(filePath)) { fs.rmSync(filePath, { recursive: true, force: true }); res.json({ success: true }); } else { res.status(404).json({ error: 'Not found' }); }
});

// --- DATA PLANE: DOCS/AI/SESSIONS ---

app.get('/api/data/:slug/ai/sessions', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    try {
        const result = await systemPool.query(
            `SELECT * FROM system.ai_sessions WHERE project_slug = $1 ORDER BY updated_at DESC`,
            [r.project.slug]
        );
        res.json(result.rows);
    } catch (e: any) { next(e); }
});

app.patch('/api/data/:slug/ai/sessions/:id', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    try {
        const { title } = req.body;
        await systemPool.query(
            `UPDATE system.ai_sessions SET title = $1, updated_at = NOW() WHERE id = $2 AND project_slug = $3`,
            [title, req.params.id, r.project.slug]
        );
        res.json({ success: true });
    } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/ai/sessions/search', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    const { query } = req.body;
    if (!query) return res.json([]);
    try {
        const result = await systemPool.query(
            `SELECT DISTINCT s.id, s.title, s.updated_at 
             FROM system.ai_history h
             JOIN system.ai_sessions s ON s.id::text = h.session_id
             WHERE h.project_slug = $1 
             AND h.content ILIKE $2
             ORDER BY s.updated_at DESC
             LIMIT 10`,
            [r.project.slug, `%${query}%`]
        );
        res.json(result.rows);
    } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/ai/chat', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    const settingsRes = await systemPool.query("SELECT settings FROM system.ui_settings WHERE project_slug = '_system_root_' AND table_name = 'ai_config'");
    try {
        const { session_id, messages } = req.body;
        
        if (session_id) {
            await systemPool.query(
                `INSERT INTO system.ai_sessions (id, project_slug, title) 
                 VALUES ($1, $2, 'Nova Conversa') 
                 ON CONFLICT (id) DO UPDATE SET updated_at = NOW()`,
                [session_id, r.project.slug]
            ).catch(() => {});
        }

        const response = await AiService.chat(r.project.slug, r.projectPool!, settingsRes.rows[0]?.settings || {}, req.body);
        
        if (session_id) {
            const lastUser = messages[messages.length - 1];
            await systemPool.query(
                "INSERT INTO system.ai_history (project_slug, session_id, role, content) VALUES ($1, $2, 'user', $3), ($1, $2, 'assistant', $4)", 
                [r.project.slug, session_id, lastUser.content, response.choices[0].message.content]
            ).catch(() => {});
        }
        
        res.json(response);
    } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/docs/pages', async (req: any, res: any, next: NextFunction) => {
    try { const result = await systemPool.query('SELECT * FROM system.doc_pages WHERE project_slug = $1 ORDER BY title ASC', [req.params.slug]); res.json(result.rows); } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/docs/openapi', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    try { const spec = await OpenApiService.generate(r.project.slug, r.project.db_name, r.projectPool!, req.headers.host || 'localhost'); res.json(spec); } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/ai/fix-sql', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    const settingsRes = await systemPool.query("SELECT settings FROM system.ui_settings WHERE project_slug = '_system_root_' AND table_name = 'ai_config'");
    try {
        const fixedSql = await AiService.fixSQL(
            r.project.slug, 
            r.projectPool!, 
            settingsRes.rows[0]?.settings || {}, 
            req.body.sql, 
            req.body.error
        );
        res.json({ fixed_sql: fixedSql });
    } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/ai/explain', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    const { code, type } = req.body;
    const settingsRes = await systemPool.query("SELECT settings FROM system.ui_settings WHERE project_slug = '_system_root_' AND table_name = 'ai_config'");
    try {
        const result = await AiService.explainCode(
            r.project.slug,
            r.projectPool!,
            settingsRes.rows[0]?.settings || {},
            code,
            type || 'sql'
        );
        res.json(result);
    } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/ai/history/:session_id', async (req: any, res: any, next: NextFunction) => {
    try { const result = await systemPool.query("SELECT role, content, created_at FROM system.ai_history WHERE project_slug = $1 AND session_id = $2 ORDER BY created_at ASC", [req.params.slug, req.params.session_id]); res.json(result.rows); } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/ai/draft-doc', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    const settingsRes = await systemPool.query("SELECT settings FROM system.ui_settings WHERE project_slug = '_system_root_' AND table_name = 'ai_config'");
    try {
        const doc = await AiService.draftDoc(r.project.slug, r.projectPool!, settingsRes.rows[0]?.settings || {}, req.body.tableName);
        const saveRes = await systemPool.query("INSERT INTO system.doc_pages (project_slug, slug, title, content_markdown) VALUES ($1, $2, $3, $4) ON CONFLICT (project_slug, slug) DO UPDATE SET title = EXCLUDED.title, content_markdown = EXCLUDED.content_markdown, updated_at = NOW() RETURNING *", [r.project.slug, doc.id, doc.title, doc.content_markdown]);
        res.json(saveRes.rows[0]);
    } catch (e: any) { next(e); }
});

// --- DATA PLANE: SECURITY ---
app.get('/api/data/:slug/security/status', async (req: any, res: any, next: NextFunction) => {
    try { const panicMode = await RateLimitService.checkPanic(req.params.slug); res.json({ current_rps: 0, panic_mode: panicMode }); } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/security/panic', async (req: any, res: any, next: NextFunction) => {
    try { await RateLimitService.setPanic(req.params.slug, req.body.enabled); await systemPool.query("UPDATE system.projects SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{security,panic_mode}', $1) WHERE slug = $2", [JSON.stringify(req.body.enabled), req.params.slug]); res.json({ success: true, panic_mode: req.body.enabled }); } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/rate-limits', async (req: any, res: any, next: NextFunction) => {
    try { const result = await systemPool.query('SELECT * FROM system.rate_limits WHERE project_slug = $1 ORDER BY created_at DESC', [req.params.slug]); res.json(result.rows); } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/rate-limits', async (req: any, res: any, next: NextFunction) => {
    const { route_pattern, method, rate_limit, burst_limit, window_seconds, message_anon, message_auth } = req.body;
    try { const result = await systemPool.query("INSERT INTO system.rate_limits (project_slug, route_pattern, method, rate_limit, burst_limit, window_seconds, message_anon, message_auth) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (project_slug, route_pattern, method) DO UPDATE SET rate_limit = EXCLUDED.rate_limit, burst_limit = EXCLUDED.burst_limit, window_seconds = EXCLUDED.window_seconds, message_anon = EXCLUDED.message_anon, message_auth = EXCLUDED.message_auth, updated_at = NOW() RETURNING *", [req.params.slug, route_pattern, method, rate_limit, burst_limit, window_seconds || 1, message_anon, message_auth]); RateLimitService.clearRules(req.params.slug); res.json(result.rows[0]); } catch (e: any) { next(e); }
});

app.delete('/api/data/:slug/rate-limits/:id', async (req: any, res: any, next: NextFunction) => {
    try { await systemPool.query('DELETE FROM system.rate_limits WHERE id = $1 AND project_slug = $2', [req.params.id, req.params.slug]); RateLimitService.clearRules(req.params.slug); res.json({ success: true }); } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/policies', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  try { const result = await r.projectPool!.query("SELECT * FROM pg_policies"); res.json(result.rows); } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/policies', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  const { name, table, command, role, using, withCheck } = req.body;
  try { await r.projectPool!.query(`CREATE POLICY ${quoteId(name)} ON public.${quoteId(table)} FOR ${command} TO ${role} USING (${using}) ${withCheck ? `WITH CHECK (${withCheck})` : ''}`); res.json({ success: true }); } catch (e: any) { next(e); }
});

app.delete('/api/data/:slug/policies/:table/:name', async (req: any, res: any, next: NextFunction) => {
  const r = req as CascataRequest;
  try { await r.projectPool!.query(`DROP POLICY ${quoteId(req.params.name)} ON public.${quoteId(req.params.table)}`); res.json({ success: true }); } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/ui-settings/:table', async (req: any, res: any, next: NextFunction) => {
  try { const result = await systemPool.query('SELECT settings FROM system.ui_settings WHERE project_slug = $1 AND table_name = $2', [req.params.slug, req.params.table]); res.json(result.rows[0]?.settings || {}); } catch (e: any) { next(e); }
});

app.post('/api/data/:slug/ui-settings/:table', async (req: any, res: any, next: NextFunction) => {
  try { await systemPool.query("INSERT INTO system.ui_settings (project_slug, table_name, settings) VALUES ($1, $2, $3) ON CONFLICT (project_slug, table_name) DO UPDATE SET settings = $3", [req.params.slug, req.params.table, req.body.settings]); res.json({ success: true }); } catch (e: any) { next(e); }
});

app.get('/api/data/:slug/logs', async (req: any, res: any, next: NextFunction) => {
  try { const result = await systemPool.query('SELECT * FROM system.api_logs WHERE project_slug = $1 ORDER BY created_at DESC LIMIT 100', [req.params.slug]); res.json(result.rows); } catch (e: any) { next(e); }
});

// --- CONTROL PLANE: PROJECTS ---
app.get('/api/control/projects', async (req: any, res: any, next: NextFunction) => {
  try { const result = await systemPool.query("SELECT id, name, slug, db_name, custom_domain, ssl_certificate_source, blocklist, metadata, status, created_at, '******' as jwt_secret, pgp_sym_decrypt(anon_key::bytea, $1) as anon_key, '******' as service_key FROM system.projects ORDER BY created_at DESC", [SYS_SECRET]); res.json(result.rows); } catch (e: any) { next(e); }
});

app.post('/api/control/projects/:slug/reveal-key', async (req: any, res: any, next: NextFunction) => {
    const { password, keyType } = req.body;
    try {
        const admin = (await systemPool.query('SELECT * FROM system.admin_users LIMIT 1')).rows[0];
        let isValid = false;
        if (!admin.password_hash.startsWith('$2')) isValid = admin.password_hash === password;
        else isValid = await bcrypt.compare(password, admin.password_hash);
        if (!isValid) return res.status(403).json({ error: "Invalid Password" });
        const keyRes = await systemPool.query(`SELECT pgp_sym_decrypt(${keyType}::bytea, $2) as decrypted_key FROM system.projects WHERE slug = $1`, [req.params.slug, SYS_SECRET]);
        res.json({ key: keyRes.rows[0].decrypted_key });
    } catch (e: any) { next(e); }
});

// **NOVA ROTA: Global Environment Variables**
app.post('/api/control/projects/:slug/secrets', async (req: any, res: any, next: NextFunction) => {
    const { secrets } = req.body; // Expects Record<string, string>
    try {
        // We store secrets in the project metadata JSONB for flexibility
        await systemPool.query(
            `UPDATE system.projects SET metadata = jsonb_set(COALESCE(metadata, '{}'::jsonb), '{secrets}', $1) WHERE slug = $2`,
            [JSON.stringify(secrets), req.params.slug]
        );
        res.json({ success: true });
    } catch (e: any) { next(e); }
});

app.post('/api/control/projects', async (req: any, res: any, next: NextFunction) => {
  const { name, slug } = req.body;
  const safeSlug = slug.toLowerCase().replace(/[^a-z0-9-]/g, '');
  const dbName = `cascata_db_${safeSlug.replace(/-/g, '_')}`;
  try {
    const keys = { anon: generateKey(), service: generateKey(), jwt: generateKey() };
    const insertRes = await systemPool.query("INSERT INTO system.projects (name, slug, db_name, anon_key, service_key, jwt_secret, metadata) VALUES ($1, $2, $3, pgp_sym_encrypt($4, $7), pgp_sym_encrypt($5, $7), pgp_sym_encrypt($6, $7), '{}') RETURNING *", [name, safeSlug, dbName, keys.anon, keys.service, keys.jwt, SYS_SECRET]);
    await systemPool.query(`CREATE DATABASE ${quoteId(dbName)}`);
    const tempClient = new pg.Client({ connectionString: process.env.SYSTEM_DATABASE_URL?.replace(/\/[^\/?]+(\?.*)?$/, `/${dbName}$1`) });
    await tempClient.connect();
    await DatabaseService.initProjectDb(tempClient);
    await tempClient.end();
    res.json({ ...insertRes.rows[0], anon_key: keys.anon, service_key: keys.service, jwt_secret: keys.jwt });
  } catch (e: any) { await systemPool.query('DELETE FROM system.projects WHERE slug = $1', [safeSlug]).catch(() => {}); next(e); }
});

// --- CONTROL PLANE: BACKUP & RESTORE ---
app.get('/api/control/projects/:slug/export', async (req: any, res: any, next: NextFunction) => {
    // Admin check implicit via cascataAuth middleware for /api/control/*
    try {
        const project = (await systemPool.query('SELECT * FROM system.projects WHERE slug = $1', [req.params.slug])).rows[0];
        if (!project) return res.status(404).json({ error: 'Project not found' });
        
        await BackupService.streamExport(project, systemPool, res);
    } catch (e: any) {
        console.error("Export Error:", e);
        if (!res.headersSent) res.status(500).json({ error: e.message });
    }
});

app.post('/api/control/projects/import/upload', async (req: any, res: any, next: NextFunction) => {
    (backupUpload.single('file') as any)(req, res, async (err: any) => {
        if (err) return next(err);
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });
        
        try {
            const manifest = await ImportService.validateBackup(req.file.path);
            res.json({ 
                success: true, 
                manifest, 
                temp_path: req.file.path 
            });
        } catch (e: any) {
            fs.unlinkSync(req.file.path);
            res.status(400).json({ error: e.message });
        }
    });
});

app.post('/api/control/projects/import/confirm', async (req: any, res: any, next: NextFunction) => {
    const { temp_path, slug } = req.body;
    if (!temp_path || !slug) return res.status(400).json({ error: 'Missing parameters' });
    
    try {
        const result = await ImportService.restoreProject(temp_path, slug, systemPool);
        await CertificateService.rebuildNginxConfigs(systemPool);
        res.json(result);
    } catch (e: any) {
        next(e);
    }
});

app.delete('/api/control/projects/:slug', async (req: any, res: any, next: NextFunction) => {
  const { slug } = req.params;
  try {
    const project = (await systemPool.query('SELECT * FROM system.projects WHERE slug = $1', [slug])).rows[0];
    if (!project) return res.status(404).json({ error: 'Not found' });
    await PoolService.close(project.db_name);
    try { await systemPool.query(`DROP DATABASE IF EXISTS ${quoteId(project.db_name)}`); } catch { await systemPool.query(`SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = $1`, [project.db_name]); await systemPool.query(`DROP DATABASE IF EXISTS ${quoteId(project.db_name)}`); }
    await Promise.all(['projects','assets','webhooks','api_logs','ui_settings','rate_limits','doc_pages','ai_history', 'ai_sessions'].map(t => systemPool.query(`DELETE FROM system.${t} WHERE ${t === 'projects' ? 'slug' : 'project_slug'} = $1`, [slug])));
    const storagePath = path.join(STORAGE_ROOT, slug);
    if (fs.existsSync(storagePath)) fs.rmSync(storagePath, { recursive: true, force: true });
    await CertificateService.rebuildNginxConfigs(systemPool);
    res.json({ success: true });
  } catch (e: any) { next(e); }
});

app.patch('/api/control/projects/:slug', async (req: any, res: any, next: NextFunction) => {
  try {
    const { custom_domain, log_retention_days, metadata, ssl_certificate_source } = req.body;
    const safeDomain = custom_domain === null ? null : (custom_domain ? custom_domain.trim().toLowerCase() : undefined);
    const safeSource = ssl_certificate_source === null ? null : (ssl_certificate_source ? ssl_certificate_source.trim().toLowerCase() : undefined);

    const fields = [];
    const values = [];
    let idx = 1;

    if (custom_domain !== undefined) {
        fields.push(`custom_domain = $${idx++}`);
        values.push(safeDomain);
    }
    if (log_retention_days !== undefined) {
        fields.push(`log_retention_days = $${idx++}`);
        values.push(log_retention_days);
    }
    if (ssl_certificate_source !== undefined) {
        fields.push(`ssl_certificate_source = $${idx++}`);
        values.push(safeSource);
    }
    if (metadata !== undefined) {
        fields.push(`metadata = COALESCE(metadata, '{}'::jsonb) || $${idx++}::jsonb`);
        values.push(JSON.stringify(metadata));
    }

    if (fields.length === 0) return res.json({});

    fields.push(`updated_at = now()`);
    values.push(req.params.slug); 

    const query = `UPDATE system.projects SET ${fields.join(', ')} WHERE slug = $${idx} RETURNING *`;
    const result = await systemPool.query(query, values);
    
    await CertificateService.rebuildNginxConfigs(systemPool);
    res.json(result.rows[0]);
  } catch (e: any) { next(e); }
});

app.post('/api/control/projects/:slug/rotate-keys', async (req: any, res: any, next: NextFunction) => {
  const { type } = req.body;
  const col = type === 'anon' ? 'anon_key' : type === 'service' ? 'service_key' : 'jwt_secret';
  try { await systemPool.query(`UPDATE system.projects SET ${col} = pgp_sym_encrypt($1, $3) WHERE slug = $2`, [generateKey(), req.params.slug, SYS_SECRET]); res.json({ success: true }); } catch (e: any) { next(e); }
});

app.post('/api/control/projects/:slug/block-ip', async (req: any, res: any, next: NextFunction) => {
  try { await systemPool.query('UPDATE system.projects SET blocklist = array_append(blocklist, $1) WHERE slug = $2', [req.body.ip, req.params.slug]); res.json({ success: true }); } catch (e: any) { next(e); }
});

app.delete('/api/control/projects/:slug/blocklist/:ip', async (req: any, res: any, next: NextFunction) => {
  try { await systemPool.query('UPDATE system.projects SET blocklist = array_remove(blocklist, $1) WHERE slug = $2', [req.params.ip, req.params.slug]); res.json({ success: true }); } catch (e: any) { next(e); }
});

app.get('/api/control/me/ip', (req: any, res: any) => {
  const forwarded = req.headers['x-forwarded-for'];
  const realIp = req.headers['x-real-ip'];
  const socketIp = req.socket.remoteAddress;
  res.json({ ip: (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '' });
});

// --- CONTROL PLANE: AUTH ---
app.post('/api/control/auth/login', async (req: any, res: any, next: NextFunction) => {
  const { email, password } = req.body;
  
  // 1. IP extraction for Lockout Check (Control Plane)
  const forwarded = req.headers['x-forwarded-for'];
  const realIp = req.headers['x-real-ip'];
  const socketIp = req.socket.remoteAddress;
  let clientIp = (realIp as string) || (forwarded ? (forwarded as string).split(',')[0].trim() : socketIp) || '';
  clientIp = clientIp.replace('::ffff:', '');

  // Hardcoded stricter config for admin panel
  const adminSecConfig = { max_attempts: 5, lockout_minutes: 15, strategy: 'hybrid' as const };

  try {
    // 2. Check Lockout
    const lockout = await RateLimitService.checkAuthLockout('admin_control_plane', clientIp, email, adminSecConfig);
    if (lockout.locked) {
        return res.status(429).json({ error: lockout.reason });
    }

    const user = (await systemPool.query('SELECT * FROM system.admin_users WHERE email = $1', [email])).rows[0];
    if (!user) {
        await RateLimitService.registerAuthFailure('admin_control_plane', clientIp, email, adminSecConfig);
        return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    let isValid = false;
    if (!user.password_hash.startsWith('$2')) { 
        if (user.password_hash === password) { 
            await systemPool.query('UPDATE system.admin_users SET password_hash = $1 WHERE id = $2', [await bcrypt.hash(password, 10), user.id]); 
            isValid = true; 
        } 
    }
    else { 
        isValid = await bcrypt.compare(password, user.password_hash); 
    }

    if (!isValid) {
        await RateLimitService.registerAuthFailure('admin_control_plane', clientIp, email, adminSecConfig);
        return res.status(401).json({ error: 'Credenciais inválidas' });
    }

    // Success: Clear Failures
    await RateLimitService.clearAuthFailure('admin_control_plane', clientIp, email);

    res.json({ token: jwt.sign({ sub: user.id, role: 'superadmin' }, process.env.SYSTEM_JWT_SECRET!, { expiresIn: '12h' }) });
  } catch (e: any) { next(e); }
});

app.post('/api/control/auth/verify', async (req: any, res: any, next: NextFunction) => {
  try {
    const user = (await systemPool.query('SELECT * FROM system.admin_users LIMIT 1')).rows[0];
    let isValid = false;
    if (!user.password_hash.startsWith('$2')) isValid = user.password_hash === req.body.password;
    else isValid = await bcrypt.compare(req.body.password, user.password_hash);
    if (isValid) res.json({ success: true }); else res.status(401).json({ error: 'Senha incorreta' });
  } catch (e: any) { next(e); }
});

app.put('/api/control/auth/profile', async (req: any, res: any, next: NextFunction) => {
  try { if (req.body.password) await systemPool.query('UPDATE system.admin_users SET email = $1, password_hash = $2', [req.body.email, await bcrypt.hash(req.body.password, 10)]); else await systemPool.query('UPDATE system.admin_users SET email = $1', [req.body.email]); res.json({ success: true }); } catch (e: any) { next(e); }
});

app.get('/api/control/system/settings', async (req: any, res: any, next: NextFunction) => {
  try {
    const result = await systemPool.query("SELECT table_name, settings FROM system.ui_settings WHERE project_slug = '_system_root_'");
    const output: any = {};
    result.rows.forEach(r => { if(r.table_name === 'domain_config') output.domain = r.settings.domain; if(r.table_name === 'ai_config') output.ai = r.settings; });
    res.json(output);
  } catch (e: any) { next(e); }
});

app.post('/api/control/system/settings', async (req: any, res: any, next: NextFunction) => {
  const { domain, ai_config } = req.body;
  try {
    if (domain !== undefined) await systemPool.query("INSERT INTO system.ui_settings (project_slug, table_name, settings) VALUES ('_system_root_', 'domain_config', $1) ON CONFLICT (project_slug, table_name) DO UPDATE SET settings = $1", [JSON.stringify({ domain: domain?.trim().toLowerCase() || null })]);
    if (ai_config !== undefined) await systemPool.query("INSERT INTO system.ui_settings (project_slug, table_name, settings) VALUES ('_system_root_', 'ai_config', $1) ON CONFLICT (project_slug, table_name) DO UPDATE SET settings = $1", [JSON.stringify(ai_config)]);
    res.json({ success: true });
  } catch (e: any) { next(e); }
});

app.post('/api/control/system/ssl-check', async (req: any, res: any, next: NextFunction) => {
  if (!req.body.domain) { res.status(400).json({ error: 'Domain required' }); return; }
  try { await fetch(`https://${req.body.domain.trim().toLowerCase()}`, { method: 'HEAD', signal: AbortSignal.timeout(5000) }); res.json({ status: 'active' }); } catch (e: any) { res.json({ status: 'inactive', error: e.message }); }
});

// --- UPDATED CERTIFICATE ROUTES (VAULT) ---
app.get('/api/control/system/certificates/status', async (req: any, res: any, next: NextFunction) => {
  try { 
      const certs = await CertificateService.listAvailableCerts(); 
      res.json({ domains: certs }); 
  } catch (e: any) { next(e); }
});

app.post('/api/control/system/certificates', async (req: any, res: any, next: NextFunction) => {
  const { domain, email, cert, key, provider, isSystem } = req.body;
  const safeDomain = domain.trim().toLowerCase();
  
  try {
    const result = await CertificateService.requestCertificate(
        safeDomain, 
        email, 
        provider, 
        systemPool,
        { cert, key },
        isSystem
    );
    res.json(result);
  } catch (e: any) { next(e); }
});

app.delete('/api/control/system/certificates/:domain', async (req: any, res: any, next: NextFunction) => {
    try { await CertificateService.deleteCertificate(req.params.domain, systemPool); res.json({ success: true }); } catch (e: any) { next(e); }
});

// --- WEBHOOKS & LOGS ---
app.get('/api/control/projects/:slug/webhooks', async (req: any, res: any, next: NextFunction) => {
  try { const result = await systemPool.query('SELECT * FROM system.webhooks WHERE project_slug = $1', [req.params.slug]); res.json(result.rows); } catch (e: any) { next(e); }
});

app.post('/api/control/projects/:slug/webhooks', async (req: any, res: any, next: NextFunction) => {
  try { await systemPool.query('INSERT INTO system.webhooks (project_slug, target_url, event_type, table_name) VALUES ($1, $2, $3, $4)', [req.params.slug, req.body.target_url, req.body.event_type, req.body.table_name]); res.json({ success: true }); } catch (e: any) { next(e); }
});

// NEW SECURE LOG DELETION
app.delete('/api/control/projects/:slug/logs', async (req: any, res: any, next: NextFunction) => {
  try { 
      // Calls the secure stored procedure that bypasses the immutability trigger safely
      await systemPool.query(`SELECT system.purge_old_logs($1, $2)`, [req.params.slug, Number(req.query.days)]); 
      res.json({ success: true }); 
  } catch (e: any) { next(e); }
});

// --- EDGE FUNCTIONS (ENHANCED WITH GLOBALS) ---
app.post('/api/data/:slug/edge/:name', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    try {
        const assetRes = await systemPool.query("SELECT * FROM system.assets WHERE project_slug = $1 AND name = $2 AND type = 'edge_function'", [r.project.slug, req.params.name]);
        if (assetRes.rows.length === 0) throw new Error("Edge Function Not Found");
        const asset = assetRes.rows[0];
        
        // MERGE GLOBAL & LOCAL ENV VARS
        const globalSecrets = r.project.metadata?.secrets || {};
        const localEnv = asset.metadata.env_vars || {};
        const finalEnv = { ...globalSecrets, ...localEnv };

        const result = await EdgeService.execute(
            asset.metadata.sql, 
            { method: req.method, body: req.body, query: req.query, headers: req.headers, user: r.user }, 
            finalEnv, 
            r.projectPool!, 
            (asset.metadata.timeout || 5) * 1000
        );
        res.status(result.status).json(result.body);
    } catch (e: any) { next(e); }
});

// --- NEW POSTGREST COMPATIBILITY ROUTES (/rest/v1) ---

// 1. Root Handler: Auto-Discovery (OpenAPI)
app.all('/api/data/:slug/rest/v1', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    
    // SECURITY CHECK: Schema Exposure
    // Allow system requests (Dashboard/Docs) to proceed.
    // Block everyone else IF 'schema_exposure' is false/undefined.
    const isDiscoveryEnabled = r.project.metadata?.schema_exposure === true;
    if (!r.isSystemRequest && !isDiscoveryEnabled) {
         return res.status(403).json({ 
             error: 'API Schema Discovery is disabled.',
             hint: 'Enable "Schema Exposure" in Project Settings > API Schema Discovery to access this endpoint.'
         });
    }

    try {
        const protocol = req.headers['x-forwarded-proto'] || 'http';
        const host = req.headers.host;
        let baseUrl = '';

        // Se o projeto tem um domínio customizado E o request veio por ele:
        if (r.project.custom_domain && host === r.project.custom_domain) {
             baseUrl = `${protocol}://${host}/rest/v1`;
        } else {
             // Caso contrário, usa a rota de sistema com slug
             baseUrl = `${protocol}://${host}/api/data/${r.project.slug}/rest/v1`;
        }

        // Generate POSTGREST-COMPATIBLE Swagger/OpenAPI Spec for the project
        // This spec uses /tableName paths instead of /tables/tableName
        const spec = await OpenApiService.generatePostgrest(r.project.slug, r.project.db_name, r.projectPool!, baseUrl);
        res.json(spec);
    } catch (e: any) { next(e); }
});

// 2. RPC Handler (PostgREST style)
app.post('/api/data/:slug/rest/v1/rpc/:name', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    const params = req.body || {};
    const placeholders = Object.keys(params).map((_, i) => `$${i + 1}`).join(', ');
    const values = Object.values(params);
    try {
        const rows = await queryWithRLS(r, async (client) => {
            const result = await client.query(`SELECT * FROM public.${quoteId(req.params.name)}(${placeholders})`, values);
            return result.rows;
        });
        res.json(rows);
    } catch (e: any) { next(e); }
});

// 3. Table Handler (With Real Pagination & Content-Range)
app.all('/api/data/:slug/rest/v1/:tableName', async (req: any, res: any, next: NextFunction) => {
    const r = req as CascataRequest;
    if (!['GET', 'POST', 'PATCH', 'PUT', 'DELETE'].includes(req.method)) {
        return next(); 
    }

    try {
        // --- NEW POSTGREST QUERY BUILDER ---
        const { text, values, countQuery } = PostgrestService.buildQuery(
            req.params.tableName,
            req.method,
            req.query,
            req.body,
            req.headers
        );

        const result = await queryWithRLS(r, async (client) => {
            // Handle Count Query if requested (Prefer: count=exact)
            // Critical for React Admin / Pagination
            if (countQuery) {
                // Execute count query first to get total.
                // Note: values array contains ONLY filter params (not limit/offset which are baked into SQL string by PostgrestService)
                // So we can reuse `values` for both queries if they share same WHERE clause params.
                const countRes = await client.query(countQuery, values);
                const total = parseInt((countRes.rows[0] as any)?.total || '0');
                
                // If we haven't executed main query yet, let's do it now
                const mainRes = await client.query(text, values);
                
                const offset = parseInt(req.query.offset || '0');
                const start = offset;
                const end = Math.min(offset + mainRes.rows.length - 1, total - 1);
                
                // Handle empty result case
                const rangeHeader = mainRes.rows.length === 0 ? `*/${total}` : `${start}-${end}/${total}`;
                res.setHeader('Content-Range', rangeHeader);
                
                return mainRes;
            }
            
            return await client.query(text, values);
        });

        if (req.headers.accept === 'application/vnd.pgrst.object+json') {
            res.json(result.rows[0] || null);
        } else {
            res.json(result.rows);
        }

    } catch (e: any) {
        next(e);
    }
});

// ERROR HANDLER
app.use((err: any, req: any, res: any, next: NextFunction) => {
    if (!err.code?.startsWith('2') && !err.code?.startsWith('4')) console.error(`[Global Error] ${req.method} ${req.path}:`, err);
    if (err instanceof multer.MulterError) return res.status(err.code === 'LIMIT_FILE_SIZE' ? 413 : 400).json({ error: err.message, code: err.code });
    
    // --- AUTH ERROR MAPPING (GoTrue Compat) ---
    // Critical fix: FlutterFlow crashes if signup/login errors are not specific JSON
    if (err.message === "User already registered" || err.code === 'user_already_exists') {
         return res.status(422).json({ error: "user_already_exists", error_description: "User already registered" });
    }
    if (err.message === "Invalid login credentials") {
         return res.status(400).json({ error: "invalid_grant", error_description: "Invalid login credentials" });
    }
    if (err.message === "User not found") {
         return res.status(404).json({ error: "not_found", error_description: "User not found" });
    }

    if (err.code) {
        if (err.code === '23505') return res.status(409).json({ error: 'Conflict: Record exists.', code: err.code });
        if (err.code === '23503') return res.status(400).json({ error: 'Foreign Key Violation.', code: err.code });
        if (err.code === '42P01') return res.status(404).json({ error: 'Table Not Found.', code: err.code });
        if (err.code === '42703') return res.status(400).json({ error: 'Invalid Column.', code: err.code });
        if (err.code === '23502') return res.status(400).json({ error: 'Missing Required Field.', code: err.code });
        if (err.code === '22P02') return res.status(400).json({ error: 'Invalid Type.', code: err.code });
    }
    if (err instanceof SyntaxError && 'body' in err) return res.status(400).json({ error: 'Invalid JSON' });
    res.status(err.status || 500).json({ error: err.message || 'Internal Server Error', code: err.code || 'INTERNAL_ERROR' });
});

(async () => {
  try {
    console.log('[System] Starting Cascata Secure Engine v9.6 (Production Release)...');
    cleanTempUploads();
    app.listen(PORT, () => console.log(`[CASCATA SECURE ENGINE] Listening on port ${PORT}`));
    CertificateService.ensureSystemCert().catch(e => console.error("Cert Init Error:", e));
    waitForDatabase(30, 2000).then(async (ready) => {
        if (ready) await MigrationService.run(systemPool, MIGRATIONS_ROOT);
        else console.error('[System] CRITICAL: Main Database Unreachable.');
    });
  } catch (e) { console.error('[System] FATAL BOOT ERROR:', e); }
})();
