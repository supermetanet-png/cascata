
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
import { RateLimitService } from './services/RateLimitService.js';
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

// Global JSON/UrlEncoded Config
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
  if (!sizeStr) return 10 * 1024 * 1024; 
  const match = sizeStr.toString().match(/^(\d+(?:\.\d+)?)\s*([a-zA-Z]+)?$/);
  if (!match