
import fs from 'fs';
import path from 'path';
import { S3Client, PutObjectCommand, DeleteObjectCommand } from '@aws-sdk/client-s3';
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import axios from 'axios';
import FormData from 'form-data';
import { Buffer } from 'buffer';
import jwt from 'jsonwebtoken';

export type StorageProviderType = 'local' | 's3' | 'cloudinary' | 'imagekit' | 'cloudflare_images' | 'gdrive' | 'dropbox' | 'onedrive' | 'terabox';

export interface MulterFile {
    path: string;
    originalname: string;
    mimetype: string;
    size: number;
    [key: string]: any;
}

export interface StorageConfig {
    provider: StorageProviderType;
    optimize?: boolean; // Flag da Solução 3 (Configurável no Painel)
    s3?: {
        bucket: string;
        region: string;
        endpoint?: string;
        accessKeyId: string;
        secretAccessKey: string;
        publicUrlBase?: string;
    };
    cloudinary?: {
        cloudName: string;
        apiKey: string;
        apiSecret: string;
        uploadPreset?: string;
    };
    imagekit?: {
        publicKey: string;
        privateKey: string;
        urlEndpoint: string;
    };
    cloudflare?: {
        accountId: string;
        apiToken: string;
        variant?: string;
    };
    gdrive?: {
        clientEmail: string;
        privateKey: string;
        rootFolderId?: string;
    };
    dropbox?: {
        clientId: string;
        clientSecret: string;
        refreshToken: string;
    };
    onedrive?: {
        clientId: string;
        clientSecret: string;
        refreshToken: string;
    };
    terabox?: {
        user?: string;
        token?: string;
    }
}

/**
 * StorageService v3.0 (Enterprise Stream & Hybrid)
 * - Solução 2: Uso de Streams nativos (fs.createReadStream) para evitar estouro de memória RAM.
 * - Solução 1: Suporte nativo a Presigned URLs (S3) para uploads diretos do frontend (futuro).
 * - Solução 3: Lógica condicional para otimização de imagens (respeitando a config do projeto).
 */
export class StorageService {

    // --- MAIN UPLOAD METHOD (STREAMING) ---
    public static async upload(
        file: MulterFile, 
        projectSlug: string, 
        bucketName: string, 
        targetPath: string, 
        config: StorageConfig
    ): Promise<string> {
        // Normaliza caminhos para evitar barras duplicadas
        const fullKey = path.join(targetPath, file.originalname).replace(/\\/g, '/').replace(/^\//, '');
        
        // --- SOLUÇÃO 3: OTIMIZAÇÃO CONFIGURÁVEL ---
        // Se a otimização estiver ativa E for imagem, poderíamos passar por um pipe (sharp/jimp).
        // Por enquanto, mantemos o stream original para garantir compatibilidade sem dependências extras.
        // O administrador do projeto controla isso via painel (flag config.optimize).
        let fileStream: fs.ReadStream | any = fs.createReadStream(file.path);
        
        if (config.optimize && file.mimetype.startsWith('image/')) {
             // Placeholder para injeção de pipeline de processamento (ex: sharp)
             // console.log(`[StorageService] Optimization requested for ${fullKey}`);
             // fileStream = fileStream.pipe(sharp().resize(800).webp());
        }

        try {
            switch (config.provider) {
                case 's3':
                    if (!config.s3) throw new Error("S3 Config missing");
                    return await this.uploadS3(fileStream, file, fullKey, config.s3);
                case 'cloudinary':
                    if (!config.cloudinary) throw new Error("Cloudinary Config missing");
                    return await this.uploadCloudinary(fileStream, targetPath, config.cloudinary);
                case 'imagekit':
                    if (!config.imagekit) throw new Error("ImageKit Config missing");
                    return await this.uploadImageKit(fileStream, file, fullKey, config.imagekit);
                case 'cloudflare_images':
                    if (!config.cloudflare) throw new Error("Cloudflare Config missing");
                    return await this.uploadCloudflare(fileStream, config.cloudflare);
                case 'gdrive':
                    if (!config.gdrive) throw new Error("Google Drive Config missing");
                    return await this.uploadGDrive(fileStream, file, targetPath, config.gdrive);
                case 'dropbox':
                    if (!config.dropbox) throw new Error("Dropbox Config missing");
                    return await this.uploadDropbox(fileStream, file, fullKey, config.dropbox);
                case 'onedrive':
                    if (!config.onedrive) throw new Error("OneDrive Config missing");
                    return await this.uploadOneDrive(fileStream, file, fullKey, config.onedrive);
                case 'terabox':
                    throw new Error("TeraBox API is not supported directly. Use WebDAV or local storage.");
                case 'local':
                default:
                    // Local é tratado pelo controller, retornamos vazio aqui.
                    return ''; 
            }
        } catch (error: any) {
            console.error(`[StorageService] Upload Failed (${config.provider}):`, error.response?.data || error.message);
            throw new Error(`Upload Failed: ${error.message}`);
        }
    }

    // --- MAIN DELETE METHOD ---
    public static async delete(
        key: string,
        config: StorageConfig
    ): Promise<void> {
        const cleanKey = key.startsWith('/') ? key.substring(1) : key;

        try {
            switch (config.provider) {
                case 's3':
                    if (!config.s3) throw new Error("S3 Config missing");
                    const s3 = new S3Client({
                        region: config.s3.region,
                        endpoint: config.s3.endpoint,
                        credentials: {
                            accessKeyId: config.s3.accessKeyId,
                            secretAccessKey: config.s3.secretAccessKey
                        },
                        forcePathStyle: !!config.s3.endpoint 
                    });
                    await s3.send(new DeleteObjectCommand({
                        Bucket: config.s3.bucket,
                        Key: cleanKey
                    }));
                    break;

                case 'cloudinary':
                    if (!config.cloudinary) throw new Error("Cloudinary Config missing");
                    // Cloudinary usa public_id sem extensão geralmente, mas depende da config
                    const publicId = cleanKey.replace(/\.[^/.]+$/, "");
                    await this.deleteCloudinary(publicId, config.cloudinary);
                    break;
                
                case 'imagekit':
                    if (!config.imagekit) throw new Error("ImageKit Config missing");
                    await this.deleteImageKit(cleanKey, config.imagekit);
                    break;
                
                case 'dropbox':
                    if (!config.dropbox) throw new Error("Dropbox Config missing");
                    await this.deleteDropbox('/' + cleanKey, config.dropbox);
                    break;
                
                case 'onedrive':
                    if (!config.onedrive) throw new Error("OneDrive Config missing");
                    await this.deleteOneDrive(cleanKey, config.onedrive);
                    break;

                case 'gdrive':
                    throw new Error("Google Drive deletion by path is not supported via this API (Requires ID).");
                
                default:
                    throw new Error(`Delete not supported for ${config.provider}`);
            }
        } catch (error: any) {
             console.error(`[StorageService] Delete Failed (${config.provider}):`, error.response?.data || error.message);
             throw new Error(`Delete Failed: ${error.message}`);
        }
    }

    // --- SOLUÇÃO 1: PRESIGNED URL GENERATION ---
    // Permite que o frontend faça upload direto para o S3, removendo o gargalo do backend.
    public static async createUploadUrl(
        key: string,
        contentType: string,
        config: StorageConfig
    ): Promise<{ url: string, fields?: any }> {
        if (config.provider === 's3' && config.s3) {
            const s3 = new S3Client({
                region: config.s3.region,
                endpoint: config.s3.endpoint,
                credentials: {
                    accessKeyId: config.s3.accessKeyId,
                    secretAccessKey: config.s3.secretAccessKey
                },
                forcePathStyle: !!config.s3.endpoint 
            });

            const command = new PutObjectCommand({
                Bucket: config.s3.bucket,
                Key: key,
                ContentType: contentType,
                ACL: 'public-read'
            });

            const url = await getSignedUrl(s3, command, { expiresIn: 3600 });
            return { url };
        }

        // Outros providers (GDrive, Dropbox) geralmente não suportam PUT pré-assinado simples
        // Nesses casos, o fallback é o proxy via backend (método upload acima).
        throw new Error(`Presigned URLs not supported for provider: ${config.provider}`);
    }

    // --- PROVIDER IMPLEMENTATIONS (ALL STREAM BASED) ---

    private static async uploadS3(stream: fs.ReadStream, file: MulterFile, key: string, conf: NonNullable<StorageConfig['s3']>) {
        const s3 = new S3Client({
            region: conf.region,
            endpoint: conf.endpoint,
            credentials: {
                accessKeyId: conf.accessKeyId,
                secretAccessKey: conf.secretAccessKey
            },
            forcePathStyle: !!conf.endpoint 
        });

        // Upload via Stream (Solução 2)
        await s3.send(new PutObjectCommand({
            Bucket: conf.bucket,
            Key: key,
            Body: stream, 
            ContentType: file.mimetype,
            ACL: 'public-read',
            ContentLength: file.size 
        }));

        if (conf.publicUrlBase) return `${conf.publicUrlBase}/${key}`;
        if (conf.endpoint) return `${conf.endpoint.replace(/\/$/, '')}/${conf.bucket}/${key}`;
        return `https://${conf.bucket}.s3.${conf.region}.amazonaws.com/${key}`;
    }

    private static async uploadCloudinary(stream: fs.ReadStream, folder: string, conf: NonNullable<StorageConfig['cloudinary']>) {
        const formData = new FormData();
        formData.append('file', stream); // Axios suporta streams no FormData
        formData.append('api_key', conf.apiKey);
        formData.append('timestamp', Math.floor(Date.now() / 1000).toString());
        if (folder) formData.append('folder', folder);
        
        if (!conf.uploadPreset) throw new Error("Cloudinary Upload Preset is required (Unsigned).");
        formData.append('upload_preset', conf.uploadPreset);

        const res = await axios.post(
            `https://api.cloudinary.com/v1_1/${conf.cloudName}/auto/upload`,
            formData,
            { headers: formData.getHeaders() }
        );

        return res.data.secure_url;
    }

    private static async deleteCloudinary(publicId: string, conf: NonNullable<StorageConfig['cloudinary']>) {
        const timestamp = Math.floor(Date.now() / 1000).toString();
        // Assinatura manual SHA1 para deleção segura
        const strToSign = `public_id=${publicId}&timestamp=${timestamp}${conf.apiSecret}`;
        const crypto = await import('crypto');
        const signature = crypto.createHash('sha1').update(strToSign).digest('hex');

        const formData = new FormData();
        formData.append('public_id', publicId);
        formData.append('api_key', conf.apiKey);
        formData.append('timestamp', timestamp);
        formData.append('signature', signature);

        await axios.post(
            `https://api.cloudinary.com/v1_1/${conf.cloudName}/image/destroy`,
            formData,
            { headers: formData.getHeaders() }
        );
    }

    private static async uploadImageKit(stream: fs.ReadStream, file: MulterFile, key: string, conf: NonNullable<StorageConfig['imagekit']>) {
        const formData = new FormData();
        formData.append('file', stream);
        formData.append('fileName', file.originalname);
        formData.append('useUniqueFileName', 'false');
        
        const folder = path.dirname(key);
        if (folder && folder !== '.') formData.append('folder', folder);

        const authHeader = `Basic ${Buffer.from(conf.privateKey + ':').toString('base64')}`;

        const res = await axios.post(
            'https://upload.imagekit.io/api/v1/files/upload',
            formData,
            { headers: { ...formData.getHeaders(), 'Authorization': authHeader } }
        );

        return res.data.url;
    }

    private static async deleteImageKit(filePath: string, conf: NonNullable<StorageConfig['imagekit']>) {
        const authHeader = `Basic ${Buffer.from(conf.privateKey + ':').toString('base64')}`;
        const fileName = path.basename(filePath);
        
        // 1. Busca ID pelo nome (ImageKit requer ID para deletar)
        const searchRes = await axios.get('https://api.imagekit.io/v1/files', {
            params: { searchQuery: `name = "${fileName}"`, limit: 1 },
            headers: { 'Authorization': authHeader }
        });

        if (searchRes.data && searchRes.data.length > 0) {
            await axios.delete(`https://api.imagekit.io/v1/files/${searchRes.data[0].fileId}`, {
                headers: { 'Authorization': authHeader }
            });
        }
    }

    private static async uploadCloudflare(stream: fs.ReadStream, conf: NonNullable<StorageConfig['cloudflare']>) {
        const formData = new FormData();
        formData.append('file', stream);
        
        const res = await axios.post(
            `https://api.cloudflare.com/client/v4/accounts/${conf.accountId}/images/v1`,
            formData,
            { headers: { ...formData.getHeaders(), 'Authorization': `Bearer ${conf.apiToken}` } }
        );
        
        const variants = res.data.result.variants;
        if (!variants || variants.length === 0) throw new Error("No image variants returned.");
        return variants[0]; 
    }

    private static async uploadGDrive(stream: fs.ReadStream, file: MulterFile, targetPath: string, conf: NonNullable<StorageConfig['gdrive']>) {
        // Autenticação JWT Service Account
        const tokenUrl = 'https://oauth2.googleapis.com/token';
        const now = Math.floor(Date.now() / 1000);
        
        const jwtClaim = {
            iss: conf.clientEmail,
            scope: 'https://www.googleapis.com/auth/drive.file',
            aud: tokenUrl,
            exp: now + 3600,
            iat: now
        };

        const signedJwt = jwt.sign(jwtClaim, conf.privateKey, { algorithm: 'RS256' });

        const tokenRes = await axios.post(tokenUrl, {
            grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            assertion: signedJwt
        });
        
        const accessToken = tokenRes.data.access_token;
        const metadata = {
            name: file.originalname,
            parents: conf.rootFolderId ? [conf.rootFolderId] : undefined
        };
        
        const formData = new FormData();
        formData.append('metadata', JSON.stringify(metadata), { contentType: 'application/json' });
        // Stream do arquivo para GDrive
        formData.append('file', stream, { contentType: file.mimetype, knownLength: file.size });

        const uploadRes = await axios.post(
            'https://www.googleapis.com/upload/drive/v3/files?uploadType=multipart&fields=id,webViewLink',
            formData,
            { headers: { ...formData.getHeaders(), 'Authorization': `Bearer ${accessToken}` } }
        );

        return uploadRes.data.webViewLink;
    }

    private static async uploadDropbox(stream: fs.ReadStream, file: MulterFile, key: string, conf: NonNullable<StorageConfig['dropbox']>) {
        // 1. Refresh Token para obter Access Token
        const tokenRes = await axios.post('https://api.dropbox.com/oauth2/token', null, {
            params: {
                grant_type: 'refresh_token',
                refresh_token: conf.refreshToken,
                client_id: conf.clientId,
                client_secret: conf.clientSecret
            }
        });
        const accessToken = tokenRes.data.access_token;
        const dropboxPath = '/' + key; 

        // 2. Upload Session/Stream
        const uploadRes = await axios.post('https://content.dropboxapi.com/2/files/upload', stream, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Dropbox-API-Arg': JSON.stringify({
                    path: dropboxPath,
                    mode: 'add',
                    autorename: true,
                    mute: false
                }),
                'Content-Type': 'application/octet-stream',
                'Content-Length': file.size // Dropbox precisa do tamanho no header em streams
            },
            maxBodyLength: Infinity,
            maxContentLength: Infinity
        });

        // 3. Criar Link Compartilhado
        try {
            const shareRes = await axios.post('https://api.dropboxapi.com/2/sharing/create_shared_link_with_settings', {
                path: uploadRes.data.path_display
            }, {
                headers: { 'Authorization': `Bearer ${accessToken}`, 'Content-Type': 'application/json' }
            });
            // Transforma link de preview em link direto (dl=1)
            return shareRes.data.url.replace('?dl=0', '?dl=1'); 
        } catch(e) {
            return `https://www.dropbox.com/home${dropboxPath}`; 
        }
    }

    private static async deleteDropbox(path: string, conf: NonNullable<StorageConfig['dropbox']>) {
        const tokenRes = await axios.post('https://api.dropbox.com/oauth2/token', null, {
            params: { grant_type: 'refresh_token', refresh_token: conf.refreshToken, client_id: conf.clientId, client_secret: conf.clientSecret }
        });
        await axios.post('https://api.dropboxapi.com/2/files/delete_v2', { path }, {
            headers: { 'Authorization': `Bearer ${tokenRes.data.access_token}`, 'Content-Type': 'application/json' }
        });
    }

    private static async uploadOneDrive(stream: fs.ReadStream, file: MulterFile, key: string, conf: NonNullable<StorageConfig['onedrive']>) {
        // 1. Refresh Token
        const params = new URLSearchParams();
        params.append('client_id', conf.clientId);
        params.append('client_secret', conf.clientSecret);
        params.append('refresh_token', conf.refreshToken);
        params.append('grant_type', 'refresh_token');
        params.append('scope', 'Files.ReadWrite.All');

        const tokenRes = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', params);
        const accessToken = tokenRes.data.access_token;

        // 2. Upload via PUT
        const uploadUrl = `https://graph.microsoft.com/v1.0/me/drive/root:/${key}:/content`;

        const uploadRes = await axios.put(uploadUrl, stream, {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Content-Type': file.mimetype,
                'Content-Length': file.size
            },
            maxBodyLength: Infinity,
            maxContentLength: Infinity
        });

        return uploadRes.data['@microsoft.graph.downloadUrl'] || uploadRes.data.webUrl;
    }

    private static async deleteOneDrive(key: string, conf: NonNullable<StorageConfig['onedrive']>) {
        const params = new URLSearchParams();
        params.append('client_id', conf.clientId);
        params.append('client_secret', conf.clientSecret);
        params.append('refresh_token', conf.refreshToken);
        params.append('grant_type', 'refresh_token');
        params.append('scope', 'Files.ReadWrite.All');

        const tokenRes = await axios.post('https://login.microsoftonline.com/common/oauth2/v2.0/token', params);
        
        await axios.delete(`https://graph.microsoft.com/v1.0/me/drive/root:/${key}`, {
            headers: { 'Authorization': `Bearer ${tokenRes.data.access_token}` }
        });
    }
}
