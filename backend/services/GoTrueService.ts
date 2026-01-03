
import { Pool } from 'pg';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { AuthService } from './AuthService.js';

interface GoTrueSignupParams {
    email: string;
    password: string;
    data?: any; // User metadata
}

interface GoTrueTokenParams {
    email?: string;
    password?: string;
    refresh_token?: string;
    id_token?: string; // Google Token
    provider?: string;
    grant_type: 'password' | 'refresh_token' | 'id_token' | 'magic_link';
    token?: string; // For magic link
}

export class GoTrueService {

    /**
     * Emula o endpoint /signup do GoTrue
     * Agora suporta envio de e-mail de confirmação (se configurado).
     */
    public static async handleSignup(
        pool: Pool, 
        params: any, 
        jwtSecret: string
    ) {
        const { email, password, data } = params;

        if (!email || !password) {
            throw new Error("Email and password required");
        }
        
        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const check = await client.query(
                `SELECT id FROM auth.users WHERE raw_user_meta_data->>'email' = $1`, 
                [email]
            );

            if (check.rows.length > 0) {
                const err: any = new Error("User already registered");
                err.code = "user_already_exists"; 
                throw err;
            }

            const meta = { email, ...(data || {}) };
            
            const userRes = await client.query(
                `INSERT INTO auth.users (raw_user_meta_data, created_at, last_sign_in_at, banned) 
                 VALUES ($1::jsonb, now(), now(), false) RETURNING *`,
                [JSON.stringify(meta)]
            );
            const user = userRes.rows[0];

            const passwordHash = await bcrypt.hash(password, 10);
            
            await client.query(
                `INSERT INTO auth.identities (user_id, provider, identifier, password_hash, identity_data, created_at, last_sign_in_at)
                 VALUES ($1, 'email', $2, $3, $4::jsonb, now(), now())`,
                [user.id, email, passwordHash, JSON.stringify({ sub: user.id, email })]
            );

            await client.query('COMMIT');

            // TODO: Se email confirmation estiver ativo, enviar Magic Link aqui ao invés de sessão direta.
            // Por enquanto, comportamento "Auto-Confirm" padrão.

            const session = await AuthService.createSession(user.id, pool, jwtSecret);
            return this.formatSessionResponse(session);

        } catch (e) {
            await client.query('ROLLBACK');
            throw e;
        } finally {
            client.release();
        }
    }

    /**
     * Emula endpoint /recover (Password Reset)
     */
    public static async handleRecover(
        pool: Pool,
        email: string,
        projectUrl: string, // Base URL for the link
        emailConfig: any, // Config from Project Metadata
        jwtSecret: string
    ) {
        if (!email) throw new Error("Email required");

        // Verifica se usuário existe
        const userCheck = await pool.query(
            `SELECT id FROM auth.users WHERE raw_user_meta_data->>'email' = $1`, 
            [email]
        );
        
        if (userCheck.rows.length === 0) {
            // Security: Don't reveal user existence
            return {};
        }

        await AuthService.sendRecovery(pool, email, projectUrl, emailConfig, jwtSecret);
        return {}; // Standard empty JSON response on success
    }

    /**
     * Emula endpoint /magiclink (Request Login Link)
     */
    public static async handleMagicLink(
        pool: Pool,
        email: string,
        projectUrl: string,
        emailConfig: any,
        jwtSecret: string
    ) {
        if (!email) throw new Error("Email required");
        
        // Verifica se usuário existe (ou auto-signup se configurado, mas vamos manter simples)
        const userCheck = await pool.query(
            `SELECT id FROM auth.users WHERE raw_user_meta_data->>'email' = $1`, 
            [email]
        );
        
        if (userCheck.rows.length === 0) {
             throw new Error("User not found");
        }

        await AuthService.sendMagicLink(pool, email, projectUrl, emailConfig, jwtSecret);
        return {};
    }

    /**
     * Emula o endpoint /token do GoTrue (Login & Refresh & Social & Magic Link)
     */
    public static async handleToken(
        pool: Pool,
        params: GoTrueTokenParams,
        jwtSecret: string,
        projectConfig: any // To pass Google Config
    ) {
        // 1. PASSWORD FLOW
        if (params.grant_type === 'password') {
            if (!params.email || !params.password) throw new Error("Email and password required");
            
            const idRes = await pool.query(
                `SELECT * FROM auth.identities WHERE provider = 'email' AND identifier = $1`,
                [params.email]
            );

            if (idRes.rows.length === 0) throw new Error("Invalid login credentials");
            const identity = idRes.rows[0];

            const userCheck = await pool.query(`SELECT banned FROM auth.users WHERE id = $1`, [identity.user_id]);
            if (userCheck.rows[0]?.banned) {
                 throw new Error("Invalid login credentials"); 
            }

            const match = await bcrypt.compare(params.password, identity.password_hash);
            if (!match) throw new Error("Invalid login credentials");

            await pool.query('UPDATE auth.users SET last_sign_in_at = now() WHERE id = $1', [identity.user_id]);

            const session = await AuthService.createSession(identity.user_id, pool, jwtSecret);
            return this.formatSessionResponse(session);
        }

        // 2. REFRESH TOKEN FLOW
        if (params.grant_type === 'refresh_token') {
            if (!params.refresh_token) throw new Error("Refresh token required");
            const session = await AuthService.refreshSession(params.refresh_token, pool, jwtSecret);
            return this.formatSessionResponse(session);
        }

        // 3. ID TOKEN FLOW (GOOGLE / APPLE)
        if (params.grant_type === 'id_token') {
            const provider = params.provider;
            const idToken = params.id_token;

            if (!idToken || !provider) throw new Error("id_token and provider required");

            let profile;
            if (provider === 'google') {
                const googleConfig = projectConfig?.auth_config?.providers?.google;
                if (!googleConfig) throw new Error("Google provider not configured");
                
                profile = await AuthService.verifyGoogleIdToken(idToken, googleConfig);
            } else {
                throw new Error(`Provider ${provider} not supported for id_token flow yet`);
            }

            const userId = await AuthService.upsertUser(pool, profile);
            
            const userCheck = await pool.query(`SELECT banned FROM auth.users WHERE id = $1`, [userId]);
            if (userCheck.rows[0]?.banned) {
                 throw new Error("User is banned"); 
            }

            const session = await AuthService.createSession(userId, pool, jwtSecret);
            return this.formatSessionResponse(session);
        }

        throw new Error("Unsupported grant_type");
    }

    /**
     * Emula o endpoint /user do GoTrue (Get User)
     */
    public static async handleGetUser(pool: Pool, userId: string) {
        const res = await pool.query(`SELECT * FROM auth.users WHERE id = $1`, [userId]);
        if (res.rows.length === 0) throw new Error("User not found");
        
        const user = res.rows[0];
        const identitiesRes = await pool.query(`SELECT * FROM auth.identities WHERE user_id = $1`, [userId]);
        
        return this.formatUserObject(user, identitiesRes.rows);
    }

    public static async handleLogout(pool: Pool, token: string, jwtSecret: string) {
        try {
            const decoded = jwt.verify(token, jwtSecret) as any;
            if(!decoded || !decoded.sub) return;
            // Opcional: Revogar refresh tokens associados
            return true;
        } catch(e) {
            return true;
        }
    }

    // --- HELPERS ---

    private static formatSessionResponse(session: any) {
        const currentSeconds = Math.floor(Date.now() / 1000);
        const expiresAt = currentSeconds + session.expires_in;

        return {
            access_token: session.access_token,
            token_type: "bearer",
            expires_in: session.expires_in,
            expires_at: expiresAt,
            refresh_token: session.refresh_token,
            user: this.formatUserObject({
                id: session.user.id,
                raw_user_meta_data: session.user.user_metadata,
                created_at: new Date().toISOString(),
                last_sign_in_at: new Date().toISOString(),
                email: session.user.email
            }, []) 
        };
    }

    private static formatUserObject(user: any, identities: any[]) {
        return {
            id: user.id,
            aud: "authenticated",
            role: "authenticated",
            email: user.email || user.raw_user_meta_data?.email,
            email_confirmed_at: user.created_at,
            phone: "",
            confirmation_sent_at: user.created_at,
            confirmed_at: user.created_at,
            last_sign_in_at: user.last_sign_in_at,
            app_metadata: {
                provider: "email",
                providers: identities.map(i => i.provider)
            },
            user_metadata: user.raw_user_meta_data || {},
            identities: identities.map(i => ({
                id: i.id,
                user_id: i.user_id,
                identity_data: i.identity_data,
                provider: i.provider,
                last_sign_in_at: i.last_sign_in_at,
                created_at: i.created_at,
                updated_at: i.created_at
            })),
            created_at: user.created_at,
            updated_at: user.created_at
        };
    }
}
