import archiver from 'archiver';
import { Pool } from 'pg';
import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import axios from 'axios';
import { Readable } from 'stream';

interface ProjectMetadata {
    id: string;
    name: string;
    slug: string;
    db_name: string;
    jwt_secret: string;
    anon_key: string;
    service_key: string;
    custom_domain?: string;
    metadata?: any;
}

interface TableDefinition {
    schema: string;
    name: string;
}

export class BackupService {
    
    public static async streamExport(project: ProjectMetadata, res: any) {
        const archive = archiver('zip', { zlib: { level: 9 } });
        const qdrantUrl = `http://${process.env.QDRANT_HOST || 'qdrant'}:${process.env.QDRANT_PORT || '6333'}`;

        archive.on('error', (err) => {
            console.error('[BackupService] Archiver error:', err);
            if (!res.headersSent) res.status(500).send({ error: 'Falha crítica na compressão do snapshot .CAF' });
            else res.end();
        });

        // Nomeclatura oficial .CAF
        res.attachment(`${project.slug}_${new Date().toISOString().split('T')[0]}.caf`);
        archive.pipe(res);

        try {
            // CRITICAL ARCHITECTURE RESTORATION:
            // Detecta se o projeto usa banco local ou externo (Ejected Project)
            const connectionString = this.resolveConnectionString(project);

            // 1. MANIFESTO .CAF 2.0 (Híbrido)
            const manifest = {
                version: '2.0',
                engine: 'Cascata-Cheshire-Symbiosis',
                exported_at: new Date().toISOString(),
                project: {
                    name: project.name,
                    slug: project.slug,
                    db_name: project.db_name,
                    jwt_secret: project.jwt_secret, 
                    anon_key: project.anon_key,
                    service_key: project.service_key,
                    custom_domain: project.custom_domain,
                    // Inclui a matriz de vulto (PCA) se existir no metadata para a VPS 3
                    semantic_matrix: project.metadata?.semantic_matrix || null,
                    is_ejected: !!project.metadata?.external_db_url
                }
            };
            archive.append(JSON.stringify(manifest, null, 2), { name: 'manifest.json' });

            // 2. CORPO (Estrutura Relacional)
            // Passamos a connectionString resolvida (seja local ou externa)
            const schemaStream = await this.getSchemaDumpStream(connectionString);
            archive.append(schemaStream, { name: 'graph/structure.sql' });

            // 3. MEMÓRIA ATÔMICA (Dados)
            const tables = await this.listTables(connectionString);
            for (const table of tables) {
                const tableStream = await this.getTableDataStream(connectionString, table.schema, table.name);
                archive.append(tableStream, { name: `data/${table.schema}.${table.name}.csv` });
            }

            // 4. SORRISO (Intuição Vetorial - Qdrant Snapshot)
            console.log(`[CAF:Snapshot] Capturing vector state for ${project.slug}...`);
            try {
                // Solicita snapshot da coleção específica do projeto
                const snapRes = await axios.post(`${qdrantUrl}/collections/${project.slug}/snapshots`);
                const snapName = snapRes.data.result.name;
                
                const snapDownloadUrl = `${qdrantUrl}/collections/${project.slug}/snapshots/${snapName}`;
                const snapStream = await axios.get(snapDownloadUrl, { responseType: 'stream' });
                
                archive.append(snapStream.data, { name: `vector/snapshot.qdrant` });
                
                // Cleanup assíncrono no servidor Qdrant
                snapStream.data.on('end', () => {
                    axios.delete(snapDownloadUrl).catch(() => {});
                });
            } catch (vErr: any) {
                console.warn(`[CAF:Warning] Vector state skipped: ${vErr.message}`);
                archive.append('Vector state not available or collection missing.', { name: 'vector/missing.log' });
            }

            // 5. ASSETS (Storage)
            // Nota: Storage externo (S3) não é baixado, apenas referência. Storage local é incluído.
            const projectStoragePath = path.resolve(process.env.STORAGE_ROOT || '../storage', project.slug);
            if (fs.existsSync(projectStoragePath)) {
                archive.directory(projectStoragePath, 'storage');
            }

            await archive.finalize();

        } catch (e: any) {
            console.error('[BackupService] .CAF Generation Failed:', e);
            archive.abort(); 
            throw e;
        }
    }

    /**
     * Resolve a string de conexão correta.
     * Prioriza banco externo (Ejected Project) se configurado no metadata.
     * Esta lógica é vital para escalabilidade horizontal.
     */
    private static resolveConnectionString(project: ProjectMetadata): string {
        if (project.metadata?.external_db_url) {
            console.log(`[BackupService] Using external DB connection for ${project.slug} (Ejected Mode)`);
            return project.metadata.external_db_url;
        }

        // Fallback para infraestrutura local (Docker)
        const host = process.env.DB_DIRECT_HOST || 'db';
        const port = process.env.DB_DIRECT_PORT || '5432';
        const user = process.env.DB_USER || 'cascata_admin';
        const pass = process.env.DB_PASS || 'secure_pass';
        return `postgresql://${user}:${pass}@${host}:${port}/${project.db_name}`;
    }

    private static async listTables(connectionString: string): Promise<TableDefinition[]> {
        const pool = new Pool({ connectionString });
        try {
            const res = await pool.query(`
                SELECT table_schema, table_name 
                FROM information_schema.tables 
                WHERE table_schema IN ('public', 'auth') 
                AND table_type = 'BASE TABLE'
                AND table_name NOT LIKE '_deleted_%'
            `);
            return res.rows.map(r => ({ schema: r.table_schema, name: r.table_name }));
        } finally {
            await pool.end();
        }
    }

    private static async getSchemaDumpStream(connectionString: string): Promise<Readable> {
        // pg_dump aceita a connection string diretamente via parâmetro -d ou argumento posicional
        // Adiciona --no-owner para evitar erros ao importar em bancos gerenciados (RDS/Supabase)
        const child = spawn('pg_dump', [
            '--dbname', connectionString,
            '--schema-only', 
            '--no-owner', 
            '--no-privileges'
        ]);
        
        // Log de erro do stderr para debug
        child.stderr.on('data', (data) => console.error(`[pg_dump error] ${data}`));
        
        // FIX: Strict Null Check for TypeScript (child.stdout can be null)
        if (!child.stdout) {
            throw new Error("pg_dump process failed to spawn stdout stream");
        }
        return child.stdout;
    }

    private static async getTableDataStream(connectionString: string, schema: string, tableName: string): Promise<Readable> {
        const query = `COPY (SELECT * FROM "${schema}"."${tableName}") TO STDOUT WITH CSV HEADER`;
        const child = spawn('psql', [
            '--dbname', connectionString,
            '-c', query
        ]);
        
        child.stderr.on('data', (data) => console.error(`[psql copy error] ${data}`));

        // FIX: Strict Null Check for TypeScript (child.stdout can be null)
        if (!child.stdout) {
            throw new Error("psql process failed to spawn stdout stream");
        }
        return child.stdout;
    }
}