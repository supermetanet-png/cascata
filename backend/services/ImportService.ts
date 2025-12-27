import AdmZip from 'adm-zip';
import path from 'path';
import fs from 'fs';
import { Pool, PoolClient, Client } from 'pg';
import { spawn, execSync } from 'child_process';
import { DatabaseService } from './DatabaseService.js';

export class ImportService {
    
    /**
     * Valida se um arquivo ZIP é um backup Cascata válido (.caf)
     * e retorna o manifesto.
     */
    public static async validateBackup(filePath: string): Promise<any> {
        try {
            const zip = new AdmZip(filePath);
            const manifestEntry = zip.getEntry('manifest.json');
            
            if (!manifestEntry) {
                throw new Error("Arquivo inválido: manifest.json não encontrado.");
            }

            const manifestContent = manifestEntry.getData().toString('utf8');
            const manifest = JSON.parse(manifestContent);

            if (!manifest.version || !manifest.project) {
                throw new Error("Manifesto corrompido ou formato desconhecido.");
            }

            return manifest;
        } catch (e: any) {
            throw new Error(`Falha na validação do backup: ${e.message}`);
        }
    }

    /**
     * Executa o processo completo de restauração.
     */
    public static async restoreProject(filePath: string, targetSlug: string, systemPool: Pool) {
        const tempDir = path.resolve(process.env.TEMP_UPLOAD_ROOT || '../temp_uploads', `restore_${targetSlug}_${Date.now()}`);
        
        try {
            // 1. Extrair ZIP
            console.log(`[Import] Extracting CAF to ${tempDir}...`);
            const zip = new AdmZip(filePath);
            zip.extractAllTo(tempDir, true);

            // 2. Ler Manifesto
            const manifestPath = path.join(tempDir, 'manifest.json');
            const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
            const dbName = `cascata_proj_${targetSlug.replace(/-/g, '_')}`;

            // 3. Provisionar Banco de Dados
            console.log(`[Import] Provisioning Database ${dbName}...`);
            await this.provisionDatabase(dbName, systemPool);

            // 3.1 Inicializar Estrutura Padrão (Auth, Extensões)
            console.log(`[Import] Initializing Base Structure...`);
            await this.initBaseStructure(dbName);

            // 4. Registrar no Sistema
            console.log(`[Import] Registering Project ${targetSlug}...`);
            await this.registerProject(targetSlug, manifest.project.name, dbName, manifest.project, systemPool);

            // 5. Aplicar Schema (DDL) do Backup
            console.log(`[Import] Applying Backup Schema...`);
            const schemaPath = path.join(tempDir, 'schema', 'structure.sql');
            if (fs.existsSync(schemaPath)) {
                await this.executeSqlFile(dbName, schemaPath);
            }

            // 6. Injetar Dados (Bulk Insert)
            console.log(`[Import] Hydrating Data...`);
            const dataDir = path.join(tempDir, 'data');
            if (fs.existsSync(dataDir)) {
                await this.bulkInsertData(dbName, dataDir);
            }

            // 7. Restaurar Storage
            console.log(`[Import] Restoring Storage Files...`);
            const storageSource = path.join(tempDir, 'storage');
            const storageTarget = path.resolve(process.env.STORAGE_ROOT || '../storage', targetSlug);
            
            if (fs.existsSync(storageSource)) {
                if (fs.existsSync(storageTarget)) {
                    fs.rmSync(storageTarget, { recursive: true, force: true });
                }
                fs.renameSync(storageSource, storageTarget);
            } else {
                fs.mkdirSync(storageTarget, { recursive: true });
            }

            return { success: true, slug: targetSlug };

        } catch (e: any) {
            console.error('[Import] Fatal Error:', e);
            throw new Error(`Restore Failed: ${e.message}`);
        } finally {
            // Cleanup Temp
            try { fs.rmSync(tempDir, { recursive: true, force: true }); } catch (e) {}
            try { fs.unlinkSync(filePath); } catch(e) {}
        }
    }

    // --- INTERNAL HELPERS ---

    private static async provisionDatabase(dbName: string, systemPool: Pool) {
        await systemPool.query(`DROP DATABASE IF EXISTS "${dbName}"`);
        await systemPool.query(`CREATE DATABASE "${dbName}"`);
    }

    private static async initBaseStructure(dbName: string) {
        const dbUrl = this.getDbUrl(dbName);
        const client = new Client({ connectionString: dbUrl });
        await client.connect();
        try {
            await DatabaseService.initProjectDb(client);
        } finally {
            await client.end();
        }
    }

    private static getDbUrl(dbName: string): string {
        const user = process.env.DB_USER || 'cascata_admin';
        const pass = process.env.DB_PASS || 'secure_pass';
        const host = process.env.DEFAULT_PROJECT_DB_HOST || 'db';
        return `postgresql://${user}:${pass}@${host}:5432/${dbName}`;
    }

    private static async registerProject(slug: string, name: string, dbName: string, meta: any, systemPool: Pool) {
        await systemPool.query(`
            INSERT INTO system.projects (
                name, slug, db_name, jwt_secret, anon_key, service_key, metadata, status
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, 'healthy')
        `, [
            name,
            slug,
            dbName,
            meta.jwt_secret,
            meta.anon_key,
            meta.service_key,
            { restored_from: meta.slug, restored_at: new Date() }
        ]);
    }

    private static async executeSqlFile(dbName: string, sqlPath: string) {
        const env = { ...process.env, PGPASSWORD: process.env.DB_PASS };
        const host = process.env.DEFAULT_PROJECT_DB_HOST || 'db';
        execSync(`psql -h ${host} -U ${process.env.DB_USER || 'postgres'} -d ${dbName} -f "${sqlPath}"`, { env });
    }

    private static async bulkInsertData(dbName: string, dataDir: string) {
        const files = fs.readdirSync(dataDir).filter(f => f.endsWith('.csv'));
        const env = { ...process.env, PGPASSWORD: process.env.DB_PASS };
        const host = process.env.DEFAULT_PROJECT_DB_HOST || 'db';

        // 1. Disable Triggers & Constraints via 'replica' role
        // This is crucial for importing 'auth' schema and handling cyclic FKs
        const setReplica = `SET session_replication_role = 'replica';`;

        for (const file of files) {
            // Determine fully qualified table name
            // Old format: table.csv -> public.table
            // New format: schema.table.csv -> schema.table
            let quotedTableName = '';
            const baseName = file.replace('.csv', '');
            
            if (baseName.includes('.')) {
                const parts = baseName.split('.');
                quotedTableName = parts.map(p => `"${p}"`).join('.');
            } else {
                quotedTableName = `"public"."${baseName}"`;
            }
            
            const filePath = path.join(dataDir, file);
            
            console.log(`[Import] Copying ${quotedTableName}...`);
            
            const copyCmd = `\\COPY ${quotedTableName} FROM STDIN WITH CSV HEADER`;
            
            await new Promise<void>((resolve, reject) => {
                const psql = spawn('psql', [
                    '-h', host,
                    '-U', process.env.DB_USER || 'postgres',
                    '-d', dbName,
                    '-c', `${setReplica} ${copyCmd}`
                ], { env, stdio: ['pipe', 'ignore', 'pipe'] }); 

                const fileStream = fs.createReadStream(filePath);
                fileStream.pipe(psql.stdin);

                psql.on('close', (code) => {
                    if (code === 0) resolve();
                    else reject(new Error(`Copy failed for ${quotedTableName} code ${code}`));
                });
                
                psql.stderr.on('data', (d) => {
                    const msg = d.toString();
                    // Ignore benign notices
                    if (!msg.includes('NOTICE')) console.warn(`[Import Warning ${quotedTableName}]: ${msg}`);
                });
            });
        }
    }
}