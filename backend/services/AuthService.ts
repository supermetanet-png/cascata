
import { Pool } from 'pg';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';

interface ProviderConfig {
    clientId?: string;
    clientSecret?: string;
    redirectUri?: string;
    webhookUrl?: string;
}

interface UserProfile {
    provider: string;
    id: string;
    email?: string;
    name?: string;
    avatar_url?: string;
}

interface SessionTokens {
    access_token: string;
    refresh_token: string;
    expires_in: number;
    user: {
        id: string;
        email?: string;
        app_metadata?: any;
        user_metadata?: any;
    };
}

interface OtpConfig {
    length?: number;
    charset?: 'numeric' | 'alphanumeric' | 'alpha' | 'hex';
    expiration_minutes?: number;
    regex_validation?: string;
}

interface EmailConfig {
    delivery_method: 'webhook' | 'resend' | 'smtp';
    webhook_url?: string;
    resend_api_key?: string;
    from_email?: string;
    // SMTP fields would be here
}

export class AuthService {

    /**
     * Valida um Google ID Token diretamente com o Google.
     * Suporta múltiplos Client IDs e Skip Nonce.
     */
    public static async verifyGoogleIdToken(idToken: string, config: any): Promise<UserProfile> {
        try {
            const res = await fetch(`https://oauth2.googleapis.com/tokeninfo?id_token=${idToken}`);
            
            if (!res.ok) {
                throw new Error('Invalid Google ID Token');
            }

            const payload = await res.json();

            // 1. Validate Audience (Client ID)
            const mainClientId = config.client_id;
            const extraClientIds = (config.authorized_clients || '').split(',').map((s: string) => s.trim()).filter(Boolean);
            const allowedAudiences = [mainClientId, ...extraClientIds];

            // Permissive check if no client_id configured (development)
            if (mainClientId && !allowedAudiences.includes(payload.aud)) {
                throw new Error(`Token audience mismatch. Expected one of [${allowedAudiences.join(', ')}], got ${payload.aud}`);
            }

            // 2. Nonce Check (Optional)
            if (!config.skip_nonce && payload.nonce) {
                // In a stricter implementation, we would validate the nonce against session storage.
                // For stateless REST APIs, often the client validates the nonce, or we skip it here.
                // This block is a placeholder for future nonce validation logic if needed.
            }

            return {
                provider: 'google',
                id: payload.sub,
                email: payload.email,
                name: payload.name,
                avatar_url: payload.picture
            };
        } catch (e: any) {
            console.error('[AuthService] Google Verification Failed:', e.message);
            throw new Error(`Unable to verify Google identity: ${e.message}`);
        }
    }

    /**
     * Generates the authorization URL for standard OAuth2 providers
     */
    public static getAuthUrl(provider: string, config: ProviderConfig, state: string): string {
        if (provider === 'google') {
            const root = 'https://accounts.google.com/o/oauth2/v2/auth';
            if (!config.clientId) throw new Error("Google Client ID missing");
            const options = {
                redirect_uri: config.redirectUri || '',
                client_id: config.clientId,
                access_type: 'offline',
                response_type: 'code',
                prompt: 'consent',
                scope: 'https://www.googleapis.com/auth/userinfo.profile https://www.googleapis.com/auth/userinfo.email',
                state
            };
            return `${root}?${new URLSearchParams(options).toString()}`;
        }
        
        if (provider === 'github') {
            const root = 'https://github.com/login/oauth/authorize';
            if (!config.clientId) throw new Error("GitHub Client ID missing");
            const options = {
                client_id: config.clientId,
                redirect_uri: config.redirectUri || '',
                scope: 'user:email',
                state
            };
            return `${root}?${new URLSearchParams(options).toString()}`;
        }

        throw new Error(`Provider ${provider} does not support OAuth URL generation.`);
    }

    /**
     * Exchanges the authorization code for user profile (Standard OAuth2)
     */
    public static async handleCallback(provider: string, code: string, config: ProviderConfig): Promise<UserProfile> {
        if (provider === 'google') {
            const tokenRes = await fetch('https://oauth2.googleapis.com/token', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    client_id: config.clientId,
                    client_secret: config.clientSecret,
                    code,
                    grant_type: 'authorization_code',
                    redirect_uri: config.redirectUri
                })
            });
            const tokens = await tokenRes.json();
            if (tokens.error) throw new Error(`Google Token Error: ${tokens.error_description}`);

            const profileRes = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
                headers: { Authorization: `Bearer ${tokens.access_token}` }
            });
            const profile = await profileRes.json();
            
            return {
                provider: 'google',
                id: profile.id,
                email: profile.email,
                name: profile.name,
                avatar_url: profile.picture
            };
        }

        if (provider === 'github') {
            const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    client_id: config.clientId,
                    client_secret: config.clientSecret,
                    code,
                    redirect_uri: config.redirectUri
                })
            });
            const tokens = await tokenRes.json();
            if (tokens.error) throw new Error(`GitHub Token Error: ${tokens.error_description}`);

            const profileRes = await fetch('https://api.github.com/user', {
                headers: { Authorization: `Bearer ${tokens.access_token}` }
            });
            const profile = await profileRes.json();

            let email = profile.email;
            if (!email) {
                try {
                    const emailsRes = await fetch('https://api.github.com/user/emails', {
                        headers: { Authorization: `Bearer ${tokens.access_token}` }
                    });
                    const emails = await emailsRes.json();
                    if (Array.isArray(emails)) {
                        const primary = emails.find((e: any) => e.primary && e.verified);
                        if (primary) email = primary.email;
                    }
                } catch(e) {}
            }

            return {
                provider: 'github',
                id: String(profile.id),
                email: email,
                name: profile.name || profile.login,
                avatar_url: profile.avatar_url
            };
        }

        throw new Error(`Provider ${provider} not implemented in callback`);
    }

    // --- EMAIL ENGINE (HYBRID: WEBHOOK OR NATIVE) ---

    private static async sendEmail(
        to: string, 
        subject: string, 
        htmlContent: string, 
        config: EmailConfig, 
        projectSecret: string,
        actionType: string
    ) {
        // 1. Webhook Mode (External Automation: n8n/Zapier/Make)
        if (config.delivery_method === 'webhook' && config.webhook_url) {
            await this.dispatchWebhook(config.webhook_url, {
                action: actionType,
                to,
                subject,
                html: htmlContent,
                timestamp: new Date().toISOString()
            }, projectSecret);
            return;
        }

        // 2. Native Resend Mode (Direct API)
        if (config.delivery_method === 'resend' && config.resend_api_key) {
            const res = await fetch('https://api.resend.com/emails', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${config.resend_api_key}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    from: config.from_email || 'onboarding@resend.dev',
                    to: [to],
                    subject: subject,
                    html: htmlContent
                })
            });
            
            if (!res.ok) {
                const err = await res.json();
                throw new Error(`Resend API Error: ${err.message}`);
            }
            return;
        }

        // 3. SMTP Mode (Placeholder for future implementation or requiring nodemailer)
        if (config.delivery_method === 'smtp') {
            throw new Error("Native SMTP not fully implemented in this runtime. Please use Webhook or Resend.");
        }

        throw new Error("Email configuration missing or invalid provider selected.");
    }

    // --- MAGIC LINK & RECOVERY ---

    public static async sendMagicLink(
        pool: Pool, 
        email: string, 
        projectUrl: string, 
        emailConfig: EmailConfig, 
        jwtSecret: string
    ) {
        return this.sendAuthLink(pool, email, projectUrl, emailConfig, jwtSecret, 'magiclink');
    }

    public static async sendRecovery(
        pool: Pool, 
        email: string, 
        projectUrl: string, 
        emailConfig: EmailConfig, 
        jwtSecret: string
    ) {
        return this.sendAuthLink(pool, email, projectUrl, emailConfig, jwtSecret, 'recovery');
    }

    private static async sendAuthLink(
        pool: Pool, 
        email: string, 
        projectUrl: string, 
        emailConfig: EmailConfig, 
        jwtSecret: string,
        type: 'magiclink' | 'recovery'
    ) {
        // 1. Generate Secure Token
        const token = crypto.randomBytes(32).toString('hex');
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        const expirationMinutes = 60; // 1 hour validity

        // 2. Store in auth.otp_codes (Reusing table for simplicity, but distinguishing via metadata)
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            
            // Invalidate previous codes of same type
            await client.query(
                `DELETE FROM auth.otp_codes WHERE identifier = $1 AND metadata->>'type' = $2`, 
                [email, type]
            );

            await client.query(
                `INSERT INTO auth.otp_codes (provider, identifier, code, expires_at, metadata) 
                 VALUES ('email', $1, $2, now() + interval '${expirationMinutes} minutes', $3::jsonb)`,
                [
                    email, 
                    tokenHash, // Store HASH, send RAW
                    JSON.stringify({ type, generated_at: new Date() }) 
                ]
            );

            await client.query('COMMIT');
        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }

        // 3. Construct URL
        // Ex: https://api.myapp.com/auth/v1/verify?token=...&type=magiclink&email=...
        // Note: verify endpoint needs to be implemented/updated to handle this
        const actionUrl = `${projectUrl}/auth/v1/verify?token=${token}&type=${type}&email=${encodeURIComponent(email)}`;
        
        const subject = type === 'magiclink' ? 'Your Login Link' : 'Reset Your Password';
        const html = `
            <h2>${type === 'magiclink' ? 'Log in to your account' : 'Reset Password'}</h2>
            <p>Click the link below to proceed:</p>
            <a href="${actionUrl}" style="padding: 10px 20px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 5px;">
                ${type === 'magiclink' ? 'Sign In' : 'Reset Password'}
            </a>
            <p style="margin-top: 20px; color: #666; font-size: 12px;">This link expires in ${expirationMinutes} minutes.</p>
        `;

        // 4. Send Email
        await this.sendEmail(email, subject, html, emailConfig, jwtSecret, type);
    }

    // --- OTP LOGIC ---

    /**
     * Gera um código seguro baseado na configuração visual da estratégia.
     */
    private static generateCode(config: OtpConfig): string {
        const length = config.length || 6;
        const charsetType = config.charset || 'numeric';
        
        let chars = '0123456789';
        if (charsetType === 'alpha') chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (charsetType === 'alphanumeric') chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        if (charsetType === 'hex') chars = '0123456789ABCDEF';

        const randomBytes = crypto.randomBytes(length);
        let result = '';
        for (let i = 0; i < length; i++) {
            result += chars[randomBytes[i] % chars.length];
        }
        return result;
    }

    /**
     * Valida o identificador (CPF, Telefone, Email) antes de processar.
     */
    private static validateIdentifier(identifier: string, regexPattern?: string): boolean {
        if (!regexPattern) return true; // Se não tem regra, aceita tudo (fallback)
        try {
            const regex = new RegExp(regexPattern);
            return regex.test(identifier);
        } catch (e) {
            console.warn('[AuthService] Invalid Regex Pattern in Config:', regexPattern);
            return true; // Fail open to avoid blocking valid users on bad config
        }
    }

    public static async dispatchWebhook(webhookUrl: string, payload: any, secret: string) {
        // Assina o payload para garantir autenticidade no n8n/endpoint
        const signature = crypto.createHmac('sha256', secret)
            .update(JSON.stringify(payload))
            .digest('hex');

        try {
            const res = await fetch(webhookUrl, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'X-Cascata-Signature': signature,
                    'X-Cascata-Event': 'auth.challenge_request'
                },
                body: JSON.stringify(payload)
            });
            
            if (!res.ok) {
                const txt = await res.text();
                throw new Error(`Webhook failed with status ${res.status}: ${txt}`);
            }
        } catch (e: any) {
            console.error(`[AuthService] Webhook Dispatch Error: ${e.message}`);
            throw new Error(`Failed to send challenge via webhook transport.`);
        }
    }

    /**
     * Inicia um desafio de autenticação (OTP).
     * Agora suporta validação de formato e configuração de código.
     */
    public static async initiatePasswordless(
        pool: Pool, 
        provider: string, // strategy name (e.g. 'cpf', 'phone')
        identifier: string, 
        webhookUrl: string, 
        serviceKey: string,
        otpConfig: OtpConfig = {}
    ): Promise<void> {
        // 1. Validation Logic
        if (otpConfig.regex_validation) {
            const isValid = this.validateIdentifier(identifier, otpConfig.regex_validation);
            if (!isValid) {
                throw new Error(`Invalid format for ${provider}. Please check your input.`);
            }
        }

        // 2. Code Generation
        const code = this.generateCode(otpConfig);
        const expirationMinutes = otpConfig.expiration_minutes || 15;

        const client = await pool.connect();
        
        try {
            await client.query('BEGIN');
            
            // Clean previous codes for this exact strategy+identifier to prevent flooding
            await client.query(
                `DELETE FROM auth.otp_codes WHERE provider = $1 AND identifier = $2`,
                [provider, identifier]
            );
            
            // Store Code securely
            // Uses columns from migration 008 (metadata, attempts)
            await client.query(
                `INSERT INTO auth.otp_codes (provider, identifier, code, expires_at, metadata) 
                 VALUES ($1, $2, $3, now() + interval '${expirationMinutes} minutes', $4::jsonb)`,
                [
                    provider, 
                    identifier, 
                    code, 
                    JSON.stringify({ 
                        generated_at: new Date(), 
                        format: otpConfig.charset 
                    })
                ]
            );

            // Payload for Webhook (n8n/Zapier)
            const payload = {
                action: 'send_challenge',
                strategy: provider,
                identifier,
                code, // The secret code to send
                timestamp: new Date().toISOString(),
                meta: {
                    expiration: `${expirationMinutes}m`,
                    format: otpConfig.charset || 'numeric'
                }
            };
            
            // 3. Dispatch Transport
            await this.dispatchWebhook(webhookUrl, payload, serviceKey);
            
            await client.query('COMMIT');
        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }
    }

    /**
     * Valida o desafio. Exige match exato de Strategy + Identifier + Code.
     * Suporta validação de Magic Links (verificando hash) se o tipo for passado.
     */
    public static async verifyPasswordless(pool: Pool, provider: string, identifier: string, code: string, isHashCheck: boolean = false): Promise<UserProfile> {
        // Validate inputs
        if (!provider || !identifier || !code) {
            throw new Error("Missing verification parameters.");
        }

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const res = await client.query(
                `SELECT * FROM auth.otp_codes 
                 WHERE provider = $1 AND identifier = $2 AND expires_at > now()`,
                [provider, isHashCheck ? code : identifier] // If hash check, identifier match is tricky, usually we lookup by code hash
            );
            
            // Note: For OTP, we look up by (provider, identifier).
            // For Magic Links (hash check), we might need to look up differently or the caller handles it.
            // Simplification: OTP flow remains standard. Magic Link flow uses verifyMagicLink method below.

            if (res.rows.length === 0) {
                 throw new Error("Invalid or expired verification code.");
            }

            const record = res.rows[0];
            
            // Check attempts
            if (record.attempts >= 5) {
                await client.query(`DELETE FROM auth.otp_codes WHERE id = $1`, [record.id]);
                await client.query('COMMIT');
                throw new Error("Too many failed attempts. Code revoked.");
            }

            if (record.code !== code) {
                await client.query(`UPDATE auth.otp_codes SET attempts = attempts + 1 WHERE id = $1`, [record.id]);
                await client.query('COMMIT');
                throw new Error("Invalid code.");
            }

            // Consume the code (One-time use)
            await client.query(`DELETE FROM auth.otp_codes WHERE id = $1`, [record.id]);
            await client.query('COMMIT');

            return {
                provider,
                id: identifier, // The identifier serves as the ID for custom strategies
                email: identifier.includes('@') ? identifier : undefined,
                name: identifier 
            };

        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }
    }

    public static async verifyMagicLinkToken(pool: Pool, email: string, token: string, type: string): Promise<UserProfile> {
        const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
        
        const client = await pool.connect();
        try {
            await client.query('BEGIN');
            
            // Find code by HASH (stored in identifier column for magic links, see sendAuthLink)
            // Wait, sendAuthLink stores `identifier = tokenHash`. So we look up by identifier.
            // AND we ensure the provider is 'email' and metadata.type matches.
            
            const res = await client.query(
                `SELECT * FROM auth.otp_codes 
                 WHERE provider = 'email' 
                 AND identifier = $1 
                 AND metadata->>'type' = $2
                 AND expires_at > now()`,
                [tokenHash, type]
            );

            if (res.rows.length === 0) {
                throw new Error("Invalid or expired link.");
            }

            const record = res.rows[0];
            
            // Consume
            await client.query(`DELETE FROM auth.otp_codes WHERE id = $1`, [record.id]);
            await client.query('COMMIT');

            return {
                provider: 'email',
                id: email, 
                email: email,
                name: email.split('@')[0]
            };

        } catch(e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }
    }

    // --- SESSION & USER MANAGEMENT (ENHANCED) ---

    public static async upsertUser(projectPool: Pool, profile: UserProfile): Promise<string> {
        const client = await projectPool.connect();
        try {
            await client.query('BEGIN');

            const identityRes = await client.query(
                `SELECT user_id FROM auth.identities WHERE provider = $1 AND identifier = $2`,
                [profile.provider, profile.id]
            );

            if (identityRes.rows.length > 0) {
                const userId = identityRes.rows[0].user_id;
                await client.query('UPDATE auth.users SET last_sign_in_at = now() WHERE id = $1', [userId]);
                
                // CRITICAL FIX: Explicit cast to ::jsonb for PostgreSQL
                await client.query(
                    `UPDATE auth.identities 
                     SET last_sign_in_at = now(), identity_data = $2::jsonb 
                     WHERE provider = $3 AND identifier = $4`, 
                    [userId, JSON.stringify(profile), profile.provider, profile.id]
                );
                await client.query('COMMIT');
                return userId;
            }

            let userId: string | null = null;

            // Link by email if exists and safe to do so
            if (profile.email) {
                const emailRes = await client.query(
                    `SELECT id FROM auth.users WHERE raw_user_meta_data->>'email' = $1`,
                    [profile.email]
                );
                if (emailRes.rows.length > 0) {
                    userId = emailRes.rows[0].id;
                }
            }

            if (!userId) {
                const meta = { 
                    name: profile.name, 
                    avatar_url: profile.avatar_url,
                    email: profile.email
                };
                
                // CRITICAL FIX: Explicit cast to ::jsonb
                const newUserRes = await client.query(
                    `INSERT INTO auth.users (raw_user_meta_data, created_at, last_sign_in_at) 
                     VALUES ($1::jsonb, now(), now()) RETURNING id`,
                    [JSON.stringify(meta)]
                );
                userId = newUserRes.rows[0].id;
            }

            // CRITICAL FIX: Removido literal 'email' que causava erro de coluna mismatch
            await client.query(
                `INSERT INTO auth.identities (user_id, provider, identifier, identity_data, created_at, last_sign_in_at)
                 VALUES ($1, $2, $3, $4::jsonb, now(), now())`,
                [userId, profile.provider, profile.id, JSON.stringify(profile)]
            );

            await client.query('COMMIT');
            return userId as string;

        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }
    }

    /**
     * Creates a full session with Access Token and Refresh Token.
     */
    public static async createSession(
        userId: string,
        projectPool: Pool,
        jwtSecret: string,
        expiresIn: string = '1h',
        refreshTokenExpiresInDays: number = 30
    ): Promise<SessionTokens> {
        // 1. Generate Access Token (JWT)
        const accessToken = jwt.sign(
            { 
                sub: userId, 
                role: 'authenticated',
                aud: 'authenticated'
            }, 
            jwtSecret, 
            { expiresIn: expiresIn as any }
        );

        // 2. Generate Refresh Token (Opaque)
        const rawRefreshToken = crypto.randomBytes(40).toString('hex');
        
        // 3. Hash Refresh Token for Storage
        const tokenHash = crypto.createHash('sha256').update(rawRefreshToken).digest('hex');

        // 4. Store in DB
        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + refreshTokenExpiresInDays);

        await projectPool.query(
            `INSERT INTO auth.refresh_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)`,
            [tokenHash, userId, expiresAt]
        );

        // 5. Get User Data for response
        const userRes = await projectPool.query(`SELECT id, raw_user_meta_data FROM auth.users WHERE id = $1`, [userId]);
        const user = userRes.rows[0];

        return {
            access_token: accessToken,
            refresh_token: rawRefreshToken,
            expires_in: this.parseSeconds(expiresIn),
            user: {
                id: user.id,
                email: user.raw_user_meta_data?.email,
                user_metadata: user.raw_user_meta_data,
                app_metadata: { provider: 'cascata', role: 'authenticated' }
            }
        };
    }

    /**
     * Exchanges a Refresh Token for a new Pair (Rotation).
     */
    public static async refreshSession(
        rawRefreshToken: string,
        projectPool: Pool,
        jwtSecret: string,
        expiresIn: string = '1h'
    ): Promise<SessionTokens> {
        const tokenHash = crypto.createHash('sha256').update(rawRefreshToken).digest('hex');

        const client = await projectPool.connect();
        try {
            await client.query('BEGIN');

            const res = await client.query(
                `SELECT id, user_id, revoked, parent_token FROM auth.refresh_tokens 
                 WHERE token_hash = $1 AND expires_at > now()`,
                [tokenHash]
            );

            if (res.rows.length === 0) {
                throw new Error("Invalid or expired refresh token");
            }

            const oldToken = res.rows[0];

            if (oldToken.revoked) {
                // Reuse Detection Logic could trigger here (revoke all user tokens)
                throw new Error("Token has been revoked (Reuse detected)");
            }

            await client.query(`UPDATE auth.refresh_tokens SET revoked = true WHERE id = $1`, [oldToken.id]);

            const newRawRefreshToken = crypto.randomBytes(40).toString('hex');
            const newTokenHash = crypto.createHash('sha256').update(newRawRefreshToken).digest('hex');
            const newExpiresAt = new Date();
            newExpiresAt.setDate(newExpiresAt.getDate() + 30);

            await client.query(
                `INSERT INTO auth.refresh_tokens (token_hash, user_id, expires_at, parent_token) 
                 VALUES ($1, $2, $3, $4)`,
                [newTokenHash, oldToken.user_id, newExpiresAt, oldToken.id]
            );

            const accessToken = jwt.sign(
                { sub: oldToken.user_id, role: 'authenticated', aud: 'authenticated' }, 
                jwtSecret, 
                { expiresIn: expiresIn as any }
            );

            const userRes = await client.query(`SELECT id, raw_user_meta_data FROM auth.users WHERE id = $1`, [oldToken.user_id]);
            const user = userRes.rows[0];

            await client.query('COMMIT');

            return {
                access_token: accessToken,
                refresh_token: newRawRefreshToken,
                expires_in: this.parseSeconds(expiresIn),
                user: {
                    id: user.id,
                    email: user.raw_user_meta_data?.email,
                    user_metadata: user.raw_user_meta_data,
                    app_metadata: { provider: 'cascata', role: 'authenticated' }
                }
            };

        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }
    }

    private static parseSeconds(str: string): number {
        const match = str.match(/^(\d+)([smhd])$/);
        if (!match) return 3600;
        const val = parseInt(match[1]);
        const unit = match[2];
        if (unit === 's') return val;
        if (unit === 'm') return val * 60;
        if (unit === 'h') return val * 3600;
        if (unit === 'd') return val * 86400;
        return 3600;
    }
}
