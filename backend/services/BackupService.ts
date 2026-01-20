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
    
    public static async streamExport(project: ProjectMetadata, systemPool: Pool, res: any) {
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
                    semantic_matrix: project.metadata?.semantic_matrix || null 
                }
            };
            archive.append(JSON.stringify(manifest, null, 2), { name: 'manifest.json' });

            // 2. CORPO (Estrutura Relacional)
            const schemaStream = await this.getSchemaDumpStream(project.db_name);
            archive.append(schemaStream, { name: 'graph/structure.sql' });

            // 3. MEMÓRIA ATÔMICA (Dados)
            const tables = await this.listTables(project.db_name);
            for (const table of tables) {
                const tableStream = await this.getTableDataStream(project.db_name, table.schema, table.name);
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

    private static getDirectDbUrl(dbName: string): string {
        const host = process.env.DB_DIRECT_HOST || 'db';
        const port = process.env.DB_DIRECT_PORT || '5432';
        const user = process.env.DB_USER || 'cascata_admin';
        const pass = process.env.DB_PASS || 'secure_pass';
        return `postgresql://${user}:${pass}@${host}:${port}/${dbName}`;
    }

    private static async listTables(dbName: string): Promise<TableDefinition[]> {
        const pool = new Pool({ connectionString: this.getDirectDbUrl(dbName) });
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

    private static async getSchemaDumpStream(dbName: string): Promise<Readable> {
        const env = { ...process.env, PGPASSWORD: process.env.DB_PASS };
        const host = process.env.DB_DIRECT_HOST || 'db';
        const port = process.env.DB_DIRECT_PORT || '5432';
        const child = spawn('pg_dump', [
            '-h', host, '-p', port,
            '-U', process.env.DB_USER || 'postgres',
            '-d', dbName,
            '--schema-only', '--no-owner', '--no-privileges'
        ], { env });
        return child.stdout;
    }

    private static async getTableDataStream(dbName: string, schema: string, tableName: string): Promise<Readable> {
        const env = { ...process.env, PGPASSWORD: process.env.DB_PASS };
        const host = process.env.DB_DIRECT_HOST || 'db';
        const port = process.env.DB_DIRECT_PORT || '5432';
        const query = `COPY (SELECT * FROM "${schema}"."${tableName}") TO STDOUT WITH CSV HEADER`;
        const child = spawn('psql', [
            '-h', host, '-p', port,
            '-U', process.env.DB_USER || 'postgres',
            '-d', dbName, '-c', query
        ], { env });
        return child.stdout;
    }
}