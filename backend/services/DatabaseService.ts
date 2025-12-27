import { PoolClient, Client } from 'pg';

export class DatabaseService {
    /**
     * Initializes the standard Cascata database structure.
     * Creates: extensions, auth schema, auth tables, default roles, and realtime triggers.
     */
    public static async initProjectDb(client: PoolClient | Client) {
        console.log('[DatabaseService] Initializing project structure (Production Mode)...');
        
        await client.query(`
            -- Extensions
            CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
            CREATE EXTENSION IF NOT EXISTS "pgcrypto";
            
            -- Schemas
            CREATE SCHEMA IF NOT EXISTS auth;
            
            -- Auth Tables: Users
            CREATE TABLE IF NOT EXISTS auth.users (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                created_at TIMESTAMPTZ DEFAULT now(),
                last_sign_in_at TIMESTAMPTZ,
                banned BOOLEAN DEFAULT false,
                raw_user_meta_data JSONB DEFAULT '{}'
            );

            -- Auth Tables: Identities
            CREATE TABLE IF NOT EXISTS auth.identities (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                user_id UUID REFERENCES auth.users(id) ON DELETE CASCADE,
                provider TEXT NOT NULL,
                identifier TEXT NOT NULL,
                password_hash TEXT,
                identity_data JSONB DEFAULT '{}',
                created_at TIMESTAMPTZ DEFAULT now(),
                last_sign_in_at TIMESTAMPTZ,
                UNIQUE(provider, identifier)
            );

            -- Auth Tables: Refresh Tokens (Session Management)
            CREATE TABLE IF NOT EXISTS auth.refresh_tokens (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                token_hash TEXT NOT NULL,
                user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
                revoked BOOLEAN DEFAULT false,
                created_at TIMESTAMPTZ DEFAULT now(),
                expires_at TIMESTAMPTZ NOT NULL,
                parent_token UUID REFERENCES auth.refresh_tokens(id) -- Support for Token Rotation Families
            );
            CREATE INDEX IF NOT EXISTS idx_refresh_tokens_token_hash ON auth.refresh_tokens(token_hash);
            CREATE INDEX IF NOT EXISTS idx_refresh_tokens_user_id ON auth.refresh_tokens(user_id);

            -- Auth Tables: OTP Codes (Passwordless)
            CREATE TABLE IF NOT EXISTS auth.otp_codes (
                id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
                identifier TEXT NOT NULL,
                provider TEXT NOT NULL,
                code TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                created_at TIMESTAMPTZ DEFAULT now()
            );

            -- Global Roles & Grants (Idempotent)
            DO $$ 
            BEGIN
                -- Ensure usage
                GRANT USAGE ON SCHEMA public TO anon, authenticated, service_role;
                GRANT USAGE ON SCHEMA auth TO service_role;
                
                -- Ensure permissions
                GRANT ALL ON ALL TABLES IN SCHEMA public TO service_role;
                GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO service_role;
                
                -- Anon & Authenticated need limited access managed by RLS
                GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO anon, authenticated;
                GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO anon, authenticated;
            END $$;
        `);
        
        // Secure Realtime Trigger Function
        // CRITICAL SECURITY FIX: Never send 'OLD' or 'NEW' row data directly in pg_notify.
        // Doing so bypasses Row Level Security (RLS) because the notification payload is visible to anyone listening.
        // Instead, we send only the Primary Key (id) and metadata. The client must fetch the data via API (which enforces RLS).
        await client.query(`
            CREATE OR REPLACE FUNCTION public.notify_changes()
            RETURNS trigger AS $$
            DECLARE
                record_id text;
            BEGIN
                -- Try to extract ID if it exists
                BEGIN
                    IF (TG_OP = 'DELETE') THEN
                        record_id := OLD.id::text;
                    ELSE
                        record_id := NEW.id::text;
                    END IF;
                EXCEPTION WHEN OTHERS THEN
                    record_id := 'unknown';
                END;

                PERFORM pg_notify(
                    'cascata_events',
                    json_build_object(
                        'table', TG_TABLE_NAME,
                        'schema', TG_TABLE_SCHEMA,
                        'action', TG_OP,
                        'record_id', record_id,
                        'timestamp', now()
                    )::text
                );
                RETURN NULL;
            END;
            $$ LANGUAGE plpgsql;
        `);
        
        console.log('[DatabaseService] Initialization complete.');
    }
}