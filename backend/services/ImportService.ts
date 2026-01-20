import AdmZip from 'adm-zip';
import path from 'path';
import fs from 'fs';
import { Pool, Client } from 'pg';
import { spawn, execSync } from 'child_process';
import axios from 'axios';
import FormData from 'form-data';
import { DatabaseService } from './DatabaseService.js';

export class ImportService {
    
    public static async validateBackup(filePath: string): Promise<any> {
        const zip = new AdmZip(filePath);
        const manifestEntry = zip.getEntry('manifest.json');
        if (!manifestEntry) throw new Error("Snapshot inválido: manifest.json ausente.");
        return JSON.parse(manifestEntry.getData().toString('utf8'));
    }

    public static async restoreProject(filePath: string, targetSlug: string, systemPool: Pool) {
        const safeSlug = targetSlug.replace(/[^a-z0-9-_]/gi, '');
        const tempDir = path.resolve(process.env.TEMP_UPLOAD_ROOT || '../temp_uploads', `restore_${safeSlug}_${Date.now()}`);
        const qdrantUrl = `http://${process.env.QDRANT_HOST || 'qdrant'}:${process.env.QDRANT_PORT || '6333'}`;
        
        try {
            const zip = new AdmZip(filePath);
            zip.extractAllTo(tempDir, true);

            const manifest = JSON.parse(fs.readFileSync(path.join(tempDir, 'manifest.json'), 'utf-8'));
            const dbName = `cascata_proj_${safeSlug.replace(/-/g, '_')}`;

            // 1. Provisionamento SQL
            await systemPool.query(`DROP DATABASE IF EXISTS "${dbName}"`);
            await systemPool.query(`CREATE DATABASE "${dbName}"`);
            
            // 2. Registro no Control Plane
            await systemPool.query(`
                INSERT INTO system.projects (name, slug, db_name, jwt_secret, anon_key, service_key, metadata, status) 
                VALUES ($1, $2, $3, $4, $5, $6, $7, 'healthy')
            `, [manifest.project.name, targetSlug, dbName, manifest.project.jwt_secret, manifest.project.anon_key, manifest.project.service_key, manifest.project.metadata || {}]);

            // 3. Aplicação de Schema e Dados
            const schemaPath = path.join(tempDir, 'graph', 'structure.sql');
            if (fs.existsSync(schemaPath)) await this.executeSqlFile(dbName, schemaPath);
            
            const dataDir = path.join(tempDir, 'data');
            if (fs.existsSync(dataDir)) await this.bulkInsertData(dbName, dataDir);

            // 4. Reidratação Vetorial (Qdrant)
            const vectorPath = path.join(tempDir, 'vector', 'snapshot.qdrant');
            if (fs.existsSync(vectorPath)) {
                console.log(`[Import:CAF] Rehydrating vector smile for ${targetSlug}...`);
                try {
                    // Garante que a coleção existe
                    await axios.put(`${qdrantUrl}/collections/${safeSlug}`, {
                        vectors: { size: 1536, distance: 'Cosine' } 
                    }).catch(() => {});

                    const formData = new FormData();
                    formData.append('snapshot', fs.createReadStream(vectorPath));
                    
                    const uploadRes = await axios.post(`${qdrantUrl}/collections/${safeSlug}/snapshots/upload`, formData, {
                        headers: formData.getHeaders()
                    });
                    
                    const snapshotName = uploadRes.data.result.name;
                    await axios.post(`${qdrantUrl}/collections/${safeSlug}/snapshots/recover`, {
                        location: `${qdrantUrl}/collections/${safeSlug}/snapshots/${snapshotName}`
                    });
                } catch (vErr: any) {
                    console.error(`[Import:Error] Vector recovery failed: ${vErr.message}`);
                }
            }

            // 5. Restauração de Storage
            const storageSource = path.join(tempDir, 'storage');
            const storageTarget = path.resolve(process.env.STORAGE_ROOT || '../storage', targetSlug);
            if (fs.existsSync(storageSource)) {
                if (fs.existsSync(storageTarget)) fs.rmSync(storageTarget, { recursive: true, force: true });
                fs.renameSync(storageSource, storageTarget);
            }

            return { success: true, slug: targetSlug };

        } finally {
            if (fs.existsSync(tempDir)) fs.rmSync(tempDir, { recursive: true, force: true });
        }
    }

    private static async executeSqlFile(dbName: string, sqlPath: string) {
        const env = { ...process.env, PGPASSWORD: process.env.DB_PASS };
        execSync(`psql -h ${process.env.DB_DIRECT_HOST || 'db'} -U ${process.env.DB_USER || 'postgres'} -d ${dbName} -f "${sqlPath}"`, { env, stdio: 'ignore' });
    }

    private static async bulkInsertData(dbName: string, dataDir: string) {
        // Lógica de inserção em massa via COPY...
    }
}