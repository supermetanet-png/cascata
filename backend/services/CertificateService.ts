
import fs from 'fs';
import path from 'path';
import { spawn, execSync } from 'child_process';
import { Pool } from 'pg';
import axios from 'axios';

export type CertProvider = 'letsencrypt' | 'certbot' | 'manual' | 'cloudflare_pem';

/**
 * CertificateService v3.0 (Infrastructure Resilience)
 * Manages SSL certificates and Nginx configuration reloading.
 */
export class CertificateService {
  private static basePath = '/etc/letsencrypt/live'; 
  private static systemCertPath = '/etc/letsencrypt/live/system';
  private static webrootPath = '/var/www/html';
  private static nginxDynamicRoot = '/etc/nginx/conf.d/dynamic';
  
  // Sidecar Configuration
  private static CONTROLLER_URL = 'http://nginx_controller:3001'; 
  private static INTERNAL_SECRET = process.env.INTERNAL_CTRL_SECRET || 'fallback_secret';

  private static validateDomain(domain: string): boolean {
    if (!domain || typeof domain !== 'string') return false;
    const clean = domain.trim();
    if (clean.includes(' ')) return false;
    if (!clean.includes('.')) return false;
    const regex = /^[a-zA-Z0-9][a-zA-Z0-9-._*]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/; 
    return regex.test(clean) || clean.includes('localhost');
  }

  public static async reloadNginx() {
      try {
          console.log('[CertService] Requesting Nginx reload via Controller...');
          await axios.post(`${this.CONTROLLER_URL}/reload`, {}, {
              headers: { 'x-internal-secret': this.INTERNAL_SECRET }
          });
          console.log('[CertService] Nginx reload signal sent.');
      } catch (e: any) {
          console.error(`[CertService] Reload Warning: ${e.message} (Is nginx_controller running?)`);
      }
  }

  /**
   * CRITICAL: Ensures a certificate exists before Nginx starts.
   * If missing, generates a temporary self-signed cert to prevent Nginx boot failure.
   */
  public static async ensureSystemCert() {
    try {
        console.log('[CertService] Checking system SSL certificates...');
        
        // Ensure directory structure
        if (!fs.existsSync(this.systemCertPath)) {
            console.log('[CertService] Creating certificate directory structure...');
            fs.mkdirSync(this.systemCertPath, { recursive: true });
        }
        
        const certFile = path.join(this.systemCertPath, 'fullchain.pem');
        const keyFile = path.join(this.systemCertPath, 'privkey.pem');

        // Check if certs exist
        if (!fs.existsSync(certFile) || !fs.existsSync(keyFile)) {
            console.warn('[CertService] ⚠️ No system certificates found.');
            console.log('[CertService] 🛠️ Generating temporary self-signed certificate (Bootstrap Mode)...');
            
            // Generate Self-Signed Cert using OpenSSL (Available in Alpine)
            // Valid for 10 years, just enough to let Nginx boot and wait for Certbot
            const cmd = `openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout "${keyFile}" -out "${certFile}" -subj "/C=US/ST=State/L=City/O=Cascata/CN=localhost"`;
            
            execSync(cmd, { stdio: 'ignore' });
            
            console.log('[CertService] ✅ Temporary certificate generated. Nginx can now start.');
        } else {
            console.log('[CertService] ✅ System certificates present.');
        }
    } catch (e) {
        console.error('[CertService] ❌ Failed to ensure system cert:', e);
        // Do not throw, try to continue boot
    }
  }

  /**
   * Resolve o caminho do certificado.
   * Agora com suporte robusto para mapear 'zero.beemovi.com' -> 'wildcard.beemovi.com'
   */
  private static resolveCertPath(domain: string): { fullchain: string, privkey: string } | null {
      // 1. Tentar match exato (Diretório com o nome exato do domínio)
      let certDir = path.join(this.basePath, domain);
      if (fs.existsSync(path.join(certDir, 'fullchain.pem'))) {
          return {
              fullchain: path.join(certDir, 'fullchain.pem'),
              privkey: path.join(certDir, 'privkey.pem')
          };
      }

      // 2. Tentar Wildcard (ex: sub.domain.com -> tenta *.domain.com e wildcard.domain.com)
      const parts = domain.split('.');
      if (parts.length >= 2) {
          const rootDomain = parts.slice(1).join('.');
          
          // Candidatos possíveis para a pasta do wildcard
          const candidates = [
              `wildcard.${rootDomain}`, // Padrão interno nosso
              `*.${rootDomain}`,        // Padrão Certbot (às vezes)
              rootDomain                // Padrão manual Cloudflare simples
          ];

          for (const cand of candidates) {
              const candPath = path.join(this.basePath, cand);
              if (fs.existsSync(path.join(candPath, 'fullchain.pem'))) {
                  return {
                      fullchain: path.join(candPath, 'fullchain.pem'),
                      privkey: path.join(candPath, 'privkey.pem')
                  };
              }
          }
      }

      return null;
  }

  /**
   * RECONSTRÓI TODAS AS CONFIGURAÇÕES DO NGINX
   */
  public static async rebuildNginxConfigs(systemPool: Pool) {
    console.log('[CertService] Rebuilding Routing Table...');
    try {
      if (!fs.existsSync(this.nginxDynamicRoot)) fs.mkdirSync(this.nginxDynamicRoot, { recursive: true });

      // Limpa configs antigas
      const oldFiles = fs.readdirSync(this.nginxDynamicRoot);
      for (const file of oldFiles) {
        if (file.endsWith('.conf')) fs.unlinkSync(path.join(this.nginxDynamicRoot, file));
      }

      // 1. Configurar SYSTEM DASHBOARD
      const sysSettings = await systemPool.query("SELECT settings->>'domain' as domain FROM system.ui_settings WHERE project_slug = '_system_root_' AND table_name = 'domain_config'");
      const sysDomain = sysSettings.rows[0]?.domain;

      // Always configure dashboard if domain is set, utilizing self-signed fallback if needed
      if (sysDomain && this.validateDomain(sysDomain)) {
          let certPaths = this.resolveCertPath(sysDomain);
          
          // Fallback to system certs if specific domain certs missing (Bootstrap scenario)
          if (!certPaths) {
             certPaths = {
                 fullchain: path.join(this.systemCertPath, 'fullchain.pem'),
                 privkey: path.join(this.systemCertPath, 'privkey.pem')
             };
          }

          const sysConfig = this.generateNginxBlock(sysDomain, certPaths, 'frontend', 'http://backend_control:3000');
          fs.writeFileSync(path.join(this.nginxDynamicRoot, '00_system_dashboard.conf'), sysConfig);
          console.log(`[CertService] Routed Dashboard: https://${sysDomain}`);
      }

      // 2. Configurar PROJETOS
      const projects = await systemPool.query('SELECT slug, custom_domain, ssl_certificate_source FROM system.projects WHERE custom_domain IS NOT NULL');
      
      for (const proj of projects.rows) {
        if (!proj.custom_domain) continue;
        if (proj.custom_domain === sysDomain) continue; // Evita conflito

        // Tenta resolver certificado (Próprio ou Herdado/Source)
        let certPaths = this.resolveCertPath(proj.custom_domain);
        
        // Se o projeto tem uma fonte de SSL explicita (ex: wildcard compartilhado), tenta usar
        if (!certPaths && proj.ssl_certificate_source) {
             certPaths = this.resolveCertPath(proj.ssl_certificate_source);
        }
        
        if (certPaths) {
            const projConfig = this.generateNginxBlock(proj.custom_domain, certPaths, 'backend_data', null);
            fs.writeFileSync(path.join(this.nginxDynamicRoot, `10_proj_${proj.slug}.conf`), projConfig);
            console.log(`[CertService] Routed Project ${proj.slug}: https://${proj.custom_domain}`);
        } else {
            console.warn(`[CertService] Orphan Domain: ${proj.custom_domain} (No Certificate Found)`);
        }
      }
      
      await this.reloadNginx(); 
      
    } catch (e) {
      console.error('[CertService] Failed to rebuild configs:', e);
    }
  }

  private static generateNginxBlock(domain: string, certs: { fullchain: string, privkey: string }, targetService: 'frontend' | 'backend_data', apiControlUpstream: string | null): string {
      let locationBlocks = '';

      if (targetService === 'frontend') {
          locationBlocks = `
    location / {
        limit_req zone=api_limit burst=50 nodelay;
        limit_conn conn_limit 50;
        proxy_pass http://frontend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location /api/control/ {
        limit_req zone=api_limit burst=20 nodelay;
        proxy_pass ${apiControlUpstream};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    location /api/data/ {
        limit_req zone=api_limit burst=50 nodelay;
        limit_conn conn_limit 50;
        proxy_pass http://backend_data:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
          `;
      } else {
          locationBlocks = `
    location / {
        limit_req zone=api_limit burst=100 nodelay;
        limit_conn conn_limit 100;
        proxy_pass http://backend_data:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_hide_header X-Powered-By;
    }
          `;
      }

      const httpLocationBlocks = locationBlocks.replace(
          'location / {', 
          `location / {
        if ($http_x_forwarded_proto != "https") {
            return 301 https://$host$request_uri;
        }`
      );

      return `
server {
    listen 443 ssl;
    server_name ${domain};
    server_tokens off;
    
    ssl_certificate ${certs.fullchain};
    ssl_certificate_key ${certs.privkey};
    
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    
    add_header Strict-Transport-Security "max-age=31536000" always;
    client_max_body_size 100M;

    location /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }

    ${locationBlocks}
}

server {
    listen 80;
    server_name ${domain};
    
    location /.well-known/acme-challenge/ {
        root /var/www/html;
        allow all;
    }

    ${httpLocationBlocks}
}
`;
  }

  public static async deleteCertificate(domain: string, systemPool: Pool): Promise<void> {
      const cleanDomain = domain.trim().toLowerCase().replace(/^\*\./, '');
      
      const targets = [
          path.join(this.basePath, domain), 
          path.join(this.basePath, `wildcard.${cleanDomain}`), 
          path.join(this.basePath, cleanDomain) 
      ];
      
      let removed = false;
      for (const t of targets) {
          if (fs.existsSync(t)) {
              fs.rmSync(t, { recursive: true, force: true });
              const renewal = path.join('/etc/letsencrypt/renewal', `${path.basename(t)}.conf`);
              if (fs.existsSync(renewal)) fs.unlinkSync(renewal);
              removed = true;
          }
      }

      if (removed) {
          await this.rebuildNginxConfigs(systemPool);
      } else {
          console.warn(`[CertService] Cert files for ${domain} not found.`);
      }
  }

  public static async listAvailableCerts(): Promise<string[]> {
      if (!fs.existsSync(this.basePath)) return [];
      try {
          const dirs = fs.readdirSync(this.basePath).filter(f => 
              fs.lstatSync(path.join(this.basePath, f)).isDirectory() && f !== 'system' && f !== 'README'
          );
          return dirs.map(d => d.startsWith('wildcard.') ? d.replace('wildcard.', '*.') : d);
      } catch (e) { return []; }
  }

  public static async requestCertificate(
      domain: string, 
      email: string, 
      provider: CertProvider, 
      systemPool: Pool,
      manualData?: { cert: string, key: string }, 
      isSystem: boolean = false
  ): Promise<{ success: boolean, message: string }> {
    
    const isWildcard = domain.startsWith('*.');
    const fsName = isWildcard ? `wildcard.${domain.replace('*.', '')}` : domain; 
    
    if (provider === 'letsencrypt' && isWildcard) {
        throw new Error("Let's Encrypt via HTTP-01 não suporta Wildcards (*). Use um domínio específico ou faça upload manual.");
    }

    if (!this.validateDomain(domain.replace('*.', 'a.'))) throw new Error("Domínio inválido.");
    
    const domainDir = path.join(this.basePath, fsName);
    
    if (provider === 'manual' || provider === 'cloudflare_pem' as any) {
        if (!manualData?.cert || !manualData?.key) throw new Error("Cert/Key required.");
        if (!fs.existsSync(this.basePath)) fs.mkdirSync(this.basePath, { recursive: true });
        
        if (fs.existsSync(domainDir)) fs.rmSync(domainDir, { recursive: true, force: true });
        fs.mkdirSync(domainDir, { recursive: true });
        
        fs.writeFileSync(path.join(domainDir, 'fullchain.pem'), manualData.cert.trim());
        fs.writeFileSync(path.join(domainDir, 'privkey.pem'), manualData.key.trim());
        
        console.log(`[CertService] Stored certificate in ${fsName}`);
        await this.rebuildNginxConfigs(systemPool);
        return { success: true, message: "Certificado salvo no cofre." };
    }

    if (provider === 'certbot' || provider === 'letsencrypt' as any) {
        if (!email.includes('@')) throw new Error("Email inválido.");
        
        console.log(`[CertService] Starting Certbot for ${domain}...`);
        
        if (!fs.existsSync(this.webrootPath)) fs.mkdirSync(this.webrootPath, { recursive: true });
        const acmeDir = path.join(this.webrootPath, '.well-known', 'acme-challenge');
        if (!fs.existsSync(acmeDir)) fs.mkdirSync(acmeDir, { recursive: true });

        return new Promise((resolve, reject) => {
            const certbot = spawn('certbot', [
                'certonly', '--webroot', '-w', this.webrootPath, '-d', domain,
                '--email', email, '--agree-tos', '--no-eff-email', '--force-renewal', '--non-interactive', '--text'
            ]);
            
            let log = '';
            certbot.stdout.on('data', d => log += d.toString());
            certbot.stderr.on('data', d => log += d.toString());
            
            certbot.on('close', async (code) => {
                if (code === 0) {
                    await this.rebuildNginxConfigs(systemPool);
                    resolve({ success: true, message: "Certificado emitido e aplicado." });
                } else {
                    reject(new Error(`Falha no Certbot: ${log.slice(-300)}`));
                }
            });
        });
    }
    
    throw new Error("Provider desconhecido.");
  }
}
