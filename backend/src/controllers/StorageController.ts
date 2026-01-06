
import { NextFunction } from 'express';
import fs from 'fs';
import path from 'path';
import { CascataRequest } from '../types.js';
import { STORAGE_ROOT } from '../config/main.js';
import { getSectorForExt, validateMagicBytes, parseBytes, walk } from '../utils/index.js';
import { StorageService, StorageConfig } from '../../services/StorageService.js';

export class StorageController {

    static async listBuckets(req: CascataRequest, res: any, next: NextFunction) {
        const p = path.join(STORAGE_ROOT, req.project.slug);
        if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
        const items = fs.readdirSync(p).filter(f => fs.lstatSync(path.join(p, f)).isDirectory());
        res.json(items.map(name => ({ name })));
    }

    static async createBucket(req: CascataRequest, res: any, next: NextFunction) {
        const p = path.join(STORAGE_ROOT, req.project.slug, req.body.name);
        if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true });
        res.json({ success: true });
    }

    static async renameBucket(req: CascataRequest, res: any, next: NextFunction) {
        const oldPath = path.join(STORAGE_ROOT, req.project.slug, req.params.name);
        const newPath = path.join(STORAGE_ROOT, req.project.slug, req.body.newName);
        
        if (!fs.existsSync(oldPath)) { return res.status(404).json({ error: 'Bucket not found' }); }
        if (fs.existsSync(newPath)) { return res.status(400).json({ error: 'Name already exists' }); }
        
        try {
            fs.renameSync(oldPath, newPath);
            res.json({ success: true });
        } catch(e: any) {
            res.status(500).json({ error: 'Rename failed: ' + e.message });
        }
    }

    static async deleteBucket(req: CascataRequest, res: any, next: NextFunction) {
        const bucketPath = path.join(STORAGE_ROOT, req.project.slug, req.params.name);
        if (!bucketPath.startsWith(path.join(STORAGE_ROOT, req.project.slug))) { 
            return res.status(403).json({ error: 'Access denied' }); 
        }
        if (!fs.existsSync(bucketPath)) { 
            return res.status(404).json({ error: 'Bucket not found' }); 
        }
        try { 
            fs.rmSync(bucketPath, { recursive: true, force: true }); 
            res.json({ success: true }); 
        } catch (e: any) { 
            res.status(500).json({ error: e.message }); 
        }
    }

    // FIX: createFolder implementation ensuring path safety
    static async createFolder(req: CascataRequest, res: any, next: NextFunction) {
        const { name, path: relativePath } = req.body;
        const bucketPath = path.join(STORAGE_ROOT, req.project.slug, req.params.bucket);
        
        // Construct full path and normalize to prevent traversal
        const targetDir = path.normalize(path.join(bucketPath, relativePath || '', name));

        if (!targetDir.startsWith(bucketPath)) { 
            return res.status(403).json({ error: 'Access Denied: Path Traversal' }); 
        }
        
        try {
            if (!fs.existsSync(targetDir)) { 
                fs.mkdirSync(targetDir, { recursive: true }); 
                res.json({ success: true }); 
            } else { 
                res.status(400).json({ error: 'Folder already exists' }); 
            }
        } catch (e: any) {
            res.status(500).json({ error: e.message });
        }
    }

    static async uploadFile(req: CascataRequest, res: any, next: NextFunction) {
        if (!req.file) return res.status(400).json({ error: 'No file found in request body.' });
        
        try {
            const governance = req.project.metadata?.storage_governance || {};
            const ext = path.extname(req.file.originalname).replace('.', '').toLowerCase();
            const sector = getSectorForExt(ext);
            const rule = governance[sector] || governance['global'] || { max_size: '10MB', allowed_exts: [] };
            
            if (rule.allowed_exts && rule.allowed_exts.length > 0 && !rule.allowed_exts.includes(ext)) { 
                fs.unlinkSync(req.file.path); 
                return res.status(403).json({ error: `Policy Violation: Extension .${ext} is not allowed.` }); 
            }
            if (!validateMagicBytes(req.file.path, ext)) { 
                fs.unlinkSync(req.file.path); 
                return res.status(400).json({ error: 'Security Alert: File signature mismatch.' }); 
            }
            if (req.file.size > parseBytes(rule.max_size)) { 
                fs.unlinkSync(req.file.path); 
                return res.status(403).json({ error: `Policy Violation: File size exceeds limit.` }); 
            }

            const storageConfig: StorageConfig = req.project.metadata?.storage_config || { provider: 'local' };
            const bucket = req.params.bucket;
            
            let relativePath = req.body.path || '';
            relativePath = relativePath.replace(new RegExp(`^${bucket}/`), '');
            relativePath = relativePath.replace(/^\/+/, ''); 

            const resultUrl = await StorageService.upload(req.file, req.project.slug, bucket, relativePath, storageConfig);

            if (storageConfig.provider === 'local') {
                const dest = path.join(STORAGE_ROOT, req.project.slug, bucket, relativePath, req.file.originalname);
                if (!fs.existsSync(path.dirname(dest))) fs.mkdirSync(path.dirname(dest), { recursive: true });
                
                fs.copyFileSync(req.file.path, dest);
                fs.unlinkSync(req.file.path);
                
                res.json({ success: true, path: dest.replace(STORAGE_ROOT, ''), provider: 'local' });
            } else {
                if (fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path);
                res.json({ success: true, path: resultUrl, provider: storageConfig.provider, url: resultUrl });
            }

        } catch (e: any) { 
            if(req.file && fs.existsSync(req.file.path)) fs.unlinkSync(req.file.path); 
            console.error("Upload Error:", e);
            res.status(500).json({ error: e.message || 'Storage Error' });
        }
    }

    // FIX: New listFiles method for flat listing (Explorer View)
    static async listFiles(req: CascataRequest, res: any, next: NextFunction) {
        const { path: queryPath } = req.query;
        const bucketPath = path.join(STORAGE_ROOT, req.project.slug, req.params.bucket);
        const targetPath = path.normalize(path.join(bucketPath, (queryPath as string) || ''));
        
        if (!targetPath.startsWith(bucketPath)) { 
            return res.status(403).json({ error: 'Access Denied' }); 
        }
        
        if (!fs.existsSync(targetPath)) { 
            // If path doesn't exist, return empty (or 404, but empty is safer for UI)
            return res.json({ items: [] }); 
        }

        try {
            // Use readdir withTypes for non-recursive flat list
            const dirents = fs.readdirSync(targetPath, { withFileTypes: true });
            
            const items = dirents.map(dirent => {
                const fullPath = path.join(targetPath, dirent.name);
                const stats = fs.statSync(fullPath);
                
                // Calculate relative path from bucket root for frontend logic
                const relPath = path.relative(bucketPath, fullPath).replace(/\\/g, '/');

                return {
                    name: dirent.name,
                    type: dirent.isDirectory() ? 'folder' : 'file',
                    size: stats.size,
                    updated_at: stats.mtime.toISOString(),
                    path: relPath // Frontend expects 'folder/file.txt' or 'folder'
                };
            });
            
            res.json({ items });
        } catch (e: any) { 
            next(e); 
        }
    }

    // Kept for global search (Recursive)
    static async search(req: CascataRequest, res: any, next: NextFunction) {
        const { q, bucket } = req.query;
        const searchTerm = (q as string || '').toLowerCase();
        const projectRoot = path.join(STORAGE_ROOT, req.project.slug);
        
        const storageConfig: StorageConfig = req.project.metadata?.storage_config || { provider: 'local' };
        if (storageConfig.provider !== 'local') {
            return res.json({ items: [] });
        }

        const searchRoot = bucket ? path.join(projectRoot, bucket as string) : projectRoot;
        
        if (!fs.existsSync(searchRoot)) { res.json({ items: [] }); return; }
        if (!searchRoot.startsWith(projectRoot)) { res.status(403).json({ error: 'Access Denied' }); return; }
        
        try {
            let allFiles = walk(searchRoot, bucket ? searchRoot : projectRoot, []);
            if (searchTerm) allFiles = allFiles.filter(f => f.name.toLowerCase().includes(searchTerm));
            res.json({ items: allFiles });
        } catch (e: any) { next(e); }
    }

    static async serveFile(req: CascataRequest, res: any, next: NextFunction) {
        const relativePath = req.params[0];
        const storageConfig: StorageConfig = req.project.metadata?.storage_config || { provider: 'local' };
        
        if (storageConfig.provider !== 'local') {
             if (storageConfig.provider === 's3' && storageConfig.s3) {
                 const key = path.join(req.params.bucket, relativePath).replace(/\\/g, '/');
                 let url = '';
                 if (storageConfig.s3.publicUrlBase) url = `${storageConfig.s3.publicUrlBase}/${key}`;
                 else if (storageConfig.s3.endpoint) url = `${storageConfig.s3.endpoint}/${storageConfig.s3.bucket}/${key}`;
                 else url = `https://${storageConfig.s3.bucket}.s3.${storageConfig.s3.region}.amazonaws.com/${key}`;
                 
                 return res.redirect(url);
             }
             return res.status(404).json({ error: "File is hosted externally." });
        }

        const bucketPath = path.join(STORAGE_ROOT, req.project.slug, req.params.bucket);
        const filePath = path.join(bucketPath, relativePath);
        
        if (!filePath.startsWith(bucketPath)) { res.status(403).json({ error: 'Path Traversal Detected' }); return; }
        if (!fs.existsSync(filePath)) { res.status(404).json({ error: 'File Not Found' }); return; }
        
        res.sendFile(filePath);
    }

    static async moveFiles(req: CascataRequest, res: any, next: NextFunction) {
        const storageConfig: StorageConfig = req.project.metadata?.storage_config || { provider: 'local' };
        if (storageConfig.provider !== 'local') {
            return res.status(501).json({ error: "Move operation not supported for external providers yet." });
        }

        try {
            const { bucket, paths, destination } = req.body;
            const root = path.join(STORAGE_ROOT, req.project.slug);
            const destPath = path.join(root, destination.bucket || bucket, destination.path || '');
            
            if (!fs.existsSync(destPath)) fs.mkdirSync(destPath, { recursive: true });
            
            let movedCount = 0;
            for (const itemPath of paths) {
                const source = path.join(root, bucket, itemPath);
                const target = path.join(destPath, path.basename(itemPath));
                if (fs.existsSync(source)) { 
                    fs.renameSync(source, target); 
                    movedCount++; 
                }
            }
            res.json({ success: true, moved: movedCount });
        } catch (e: any) { next(e); }
    }

    static async deleteObject(req: CascataRequest, res: any, next: NextFunction) {
        const storageConfig: StorageConfig = req.project.metadata?.storage_config || { provider: 'local' };
        const objectPath = req.query.path as string;

        try {
            if (storageConfig.provider === 'local') {
                const filePath = path.join(STORAGE_ROOT, req.project.slug, req.params.bucket, objectPath);
                const bucketRoot = path.join(STORAGE_ROOT, req.project.slug, req.params.bucket);
                if (!filePath.startsWith(bucketRoot)) return res.status(403).json({ error: 'Access Denied' });

                if (fs.existsSync(filePath)) { 
                    fs.rmSync(filePath, { recursive: true, force: true }); 
                    res.json({ success: true }); 
                } else { 
                    res.status(404).json({ error: 'Not found' }); 
                }
            } else {
                const key = path.join(req.params.bucket, objectPath).replace(/\\/g, '/');
                await StorageService.delete(key, storageConfig);
                res.json({ success: true });
            }
        } catch (e: any) { next(e); }
    }
}
