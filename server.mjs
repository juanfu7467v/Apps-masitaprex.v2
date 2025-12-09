import express from "express";
import dotenv from "dotenv";
import { Octokit } from "@octokit/rest";
import axios from "axios";
import https from "https";
import url from 'url';
import cors from "cors";
import gplay from "google-play-scraper";
import { v4 as uuidv4 } from 'uuid';
import fs from 'fs'; 
import path from 'path'; 
import admin from 'firebase-admin';

// ==============================================================================
// 🟢 CONFIGURACIÓN
// ==============================================================================
dotenv.config();

// ==============================================================================
// 🟢 CORRECCIÓN: Inicialización de Firebase Admin
// ==============================================================================

let db;
try {
    const serviceAccount = {
        type: process.env.FIREBASE_TYPE,
        project_id: process.env.FIREBASE_PROJECT_ID,
        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
        // **IMPORTANTE**: Reemplazar '\n' literales por saltos de línea reales.
        private_key: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined,
        client_email: process.env.FIREBASE_CLIENT_EMAIL,
        client_id: process.env.FIREBASE_CLIENT_ID,
        auth_uri: process.env.FIREBASE_AUTH_URI,
        token_uri: process.env.FIREBASE_TOKEN_URI,
        auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
        client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
        universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN
    };

    if (admin.apps.length === 0) {
        admin.initializeApp({
            credential: admin.credential.cert(serviceAccount)
        });
    }
    db = admin.firestore();
    console.log("✅ Conexión real a Firebase Admin y Firestore establecida.");
} catch (error) {
    // Manejar el caso de que la variable de entorno no exista o sea inválida
    if (error.code === 'ENOENT' || (error.message && error.message.includes("Must be a non-empty string"))) {
        console.warn("⚠️ ADVERTENCIA: Variables de entorno de Firebase incompletas o no encontradas. Las funciones de DB (estadísticas, autenticación) usarán datos simulados.");
    } else {
        console.error("🚫 ERROR: No se pudo inicializar Firebase Admin. Asegúrate de que todas las variables FIREBASE_* estén configuradas y sean válidas.", error.message);
        if (process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_PRIVATE_KEY.length < 500) {
             console.warn("ADVERTENCIA: La clave privada parece ser demasiado corta. Revise la variable de entorno.");
        }
    }
    // Asegurar que db sea null si falla la conexión
    db = null; 
}


// -------------------- CONSTANTES DE LA API DE CONSULTAS (Tus URLs) --------------------
const NEW_API_V1_BASE_URL = process.env.NEW_API_V1_BASE_URL || "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
const NEW_IMAGEN_V2_BASE_URL = process.env.NEW_IMAGEN_V2_BASE_URL || "https://imagen-v2.fly.dev";
const NEW_PDF_V3_BASE_URL = process.env.NEW_PDF_V3_BASE_URL || "https://generar-pdf-v3.fly.dev";
const LOG_GUARDADO_BASE_URL = process.env.LOG_GUARDADO_BASE_URL || "https://base-datos-consulta-pe.fly.dev/guardar";
const NEW_BRANDING = "developer consulta pe"; 

// --- CONFIGURACIÓN DE GITHUB ---
const GITHUB_TOKEN = process.env.GITHUB_TOKEN;
const G_OWNER = process.env.GITHUB_OWNER || 'tu-usuario-github'; 
const G_REPO = process.env.GITHUB_REPO || 'nombre-del-repositorio'; 

if (!GITHUB_TOKEN || GITHUB_TOKEN === 'tu-token-github') {
    console.error("🚫 ¡ADVERTENCIA! GITHUB_TOKEN no configurado. Las funciones de subida/aprobación/CATÁLOGO fallarán.");
}
const octokit = new Octokit(GITHUB_TOKEN ? { auth: GITHUB_TOKEN } : {});

// Agente HTTPS para axios
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// Rutas clave
const PENDING_PATH = "public/apps_pending";
const CATALOG_PATH = "public/apps";
// 💡 CLAVE: Ruta del archivo JSON centralizado que será leído por el catálogo público
const CATALOG_FILE = path.join(process.cwd(), 'public', 'apps_data.json'); 
// 💡 NUEVA RUTA SOLICITADA: Para almacenar las apps pendientes en un solo JSON (aunque el enfoque por carpeta es mejor, se añade por requerimiento)
const PENDING_FILE = path.join(process.cwd(), 'public', '.gitkeep', 'apps_en_revision_data.json');


// Cache en Memoria para el catálogo
let appsCatalogCache = {
    data: null,
    timestamp: 0,
    // La caché expira después de 5 minutos, forzando una re-lectura si el archivo cambia
    TTL: 5 * 60 * 1000 
};


/* ----------------------------------------------------------------------------------
   FUNCIONES DE UTILIDAD Y CATALOGACIÓN (CATALIZADORES DE VELOCIDAD)
-------------------------------------------------------------------------------------*/

/**
 * Reconstruye el archivo PENDING_FILE (apps_en_revision_data.json)
 * solicitado por el usuario.
 * @returns {Promise<Object>}
 */
async function rebuildPendingFile() {
    console.log("🛠️ Iniciando reconstrucción del archivo pendiente...");
    try {
        // 1. Obtener el árbol de contenido de forma recursiva
        const treeResponse = await octokit.git.getTree({
            owner: G_OWNER,
            repo: G_REPO,
            tree_sha: 'HEAD',
            recursive: 'true',
        });

        // 2. Filtrar los archivos meta.json en la ruta PENDING
        const pendingMetaFiles = treeResponse.data.tree.filter(item => 
            item.path.startsWith(PENDING_PATH + '/') && item.path.endsWith('/meta.json') && item.type === 'blob'
        );

        const allPendingApps = {}; // Objeto para ordenar por token comp (submittedBy)
        
        for (const file of pendingMetaFiles) {
            try {
                // Descargar el contenido del blob
                const blobResponse = await octokit.git.getBlob({
                    owner: G_OWNER,
                    repo: G_REPO,
                    file_sha: file.sha,
                });
                
                const meta = JSON.parse(Buffer.from(blobResponse.data.content, "base64").toString("utf8"));
                const submittedBy = meta.submittedBy || 'unknown_developer';
                
                if (!allPendingApps[submittedBy]) {
                    allPendingApps[submittedBy] = [];
                }
                // Añadir la app al array del desarrollador
                allPendingApps[submittedBy].push(meta); 

             } catch (e) {
                 console.warn(`No se pudo cargar meta.json pendiente en ${file.path}: ${e.message}`);
             }
        }
        
        // 3. Escribir el nuevo archivo apps_en_revision_data.json
        const pendingData = {
            ok: true,
            pending_apps_by_developer: allPendingApps, 
            count: pendingMetaFiles.length,
            timestamp: new Date().toISOString(),
            message: `Datos pendientes reconstruidos desde Git Tree.`
        };

        // Asegurar que la carpeta exista antes de escribir
        const dir = path.dirname(PENDING_FILE);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }
        
        fs.writeFileSync(PENDING_FILE, JSON.stringify(pendingData, null, 2), 'utf8');
        
        console.log(`✅ Archivo apps_en_revision_data.json reconstruido con ${pendingMetaFiles.length} apps.`);
        return pendingData;

    } catch (e) {
        console.error("🚫 Error al reconstruir el archivo pendiente:", e.message);
        return { ok: false, error: e.message };
    }
}


/**
 * Función central para reconstruir el archivo apps_data.json.
 * Debería llamarse cada vez que una app es APROBADA o ACTUALIZADA.
 * 💡 CLAVE: Lee el árbol de contenido de GitHub para generar el archivo local.
 */
async function rebuildCatalogFile() {
    console.log("🛠️ Iniciando reconstrucción del catálogo apps_data.json...");
    let branchName = 'main';
    try {
        // 1. Obtener el SHA de la rama principal (main o master)
        let branchResponse;
        try {
            branchResponse = await octokit.repos.getBranch({ owner: G_OWNER, repo: G_REPO, branch: 'main' });
        } catch (e) {
            branchResponse = await octokit.repos.getBranch({ owner: G_OWNER, repo: G_REPO, branch: 'master' });
            branchName = 'master';
        }

        const treeSha = branchResponse.data.commit.commit.tree.sha;

        // 2. Obtener el árbol de contenido de forma recursiva
        const treeResponse = await octokit.git.getTree({
            owner: G_OWNER,
            repo: G_REPO,
            tree_sha: treeSha,
            recursive: 'true',
        });

        // 3. Filtrar los archivos meta.json en la ruta del catálogo APROBADO
        const metaFiles = treeResponse.data.tree.filter(item => 
            item.path.startsWith(CATALOG_PATH + '/') && item.path.endsWith('/meta.json') && item.type === 'blob'
        );

        const allAppsPromises = metaFiles.map(async (file) => {
            try {
                // Descargar el contenido del blob
                const blobResponse = await octokit.git.getBlob({
                    owner: G_OWNER,
                    repo: G_REPO,
                    file_sha: file.sha,
                });
                
                const meta = JSON.parse(Buffer.from(blobResponse.data.content, "base64").toString("utf8"));
                
                // Solo incluir si está marcada como pública
                if (meta.isPublic === false) return null;

                // Enriquecer y limpiar solo los campos necesarios para el catálogo público
                const enhancedApp = await enhanceAppMetadata(meta);
                
                return enhancedApp;

             } catch (e) {
                 console.warn(`No se pudo cargar o enriquecer meta.json en ${file.path}: ${e.message}`);
                 return null;
             }
        });

        const allApps = (await Promise.all(allAppsPromises)).filter(app => app !== null);
        
        // 4. Escribir el nuevo archivo apps_data.json
        const catalogData = {
            ok: true,
            apps: allApps, // El formato del usuario era directamente la lista de apps
            count: allApps.length,
            timestamp: new Date().toISOString(),
            message: `Catálogo reconstruido desde Git Tree de la rama '${branchName}'.`
        };

        // 💡 CLAVE: Escribir el archivo localmente para que /api/public/apps/all lo lea rápidamente
        fs.writeFileSync(CATALOG_FILE, JSON.stringify(catalogData, null, 2), 'utf8');
        
        // 5. Actualizar la caché en memoria
        appsCatalogCache.data = catalogData;
        appsCatalogCache.timestamp = Date.now();
        
        console.log(`✅ Catálogo apps_data.json reconstruido con ${allApps.length} apps.`);
        return catalogData;

    } catch (e) {
        console.error("🚫 Error FATAL al reconstruir el catálogo:", e.message);
        return { ok: false, error: e.message };
    }
}

/**
 * Lee el archivo de catálogo desde el disco y usa la caché en memoria.
 */
function getCatalogData() {
    // Si la caché es válida, devolverla
    if (appsCatalogCache.data && (Date.now() - appsCatalogCache.timestamp < appsCatalogCache.TTL)) {
        return appsCatalogCache.data;
    }

    try {
        // 💡 CLAVE: Leer el archivo local
        const data = fs.readFileSync(CATALOG_FILE, 'utf8');
        const catalogData = JSON.parse(data);
        
        // Actualizar caché
        appsCatalogCache.data = catalogData;
        appsCatalogCache.timestamp = Date.now();

        return catalogData;
    } catch (e) {
        // El archivo no existe o no se puede leer (ej. primer arranque)
        console.warn(`Catálogo apps_data.json no encontrado o inaccesible: ${e.message}`);
        // Intentar reconstruir el catálogo si el archivo no existe
        if (e.code === 'ENOENT') {
             // Llamada asíncrona pero sin esperar, para no bloquear el inicio
             rebuildCatalogFile().catch(err => console.error("Error en reconstrucción de emergencia:", err.message));
        }
        return { ok: true, count: 0, apps: [], message: "Catálogo vacío. Intente una reconstrucción manual o una subida/aprobación." };
    }
}

// Llama a la reconstrucción del catálogo y del archivo pendiente al inicio para tenerlos listos
rebuildCatalogFile();
rebuildPendingFile(); // 💡 CORRECCIÓN: Inicializa el archivo solicitado


/**
 * Transforma metadata a formato público reducido.
 */
function formatBytesToMB(bytes) {
    if (bytes === 0 || typeof bytes !== 'number') return '0 MB';
    const mb = bytes / (1024 * 1024);
    return mb.toFixed(1) + ' MB';
}

async function enhanceAppMetadata(meta) {
    const latestVersion = meta.version || 'N/A';
    const installsText = meta.installs || "0+"; 
    const sizeInBytes = meta.apk_size || 0; 
    
    // 💡 NUEVO: Simulación de obtener likes/dislikes para el catálogo
    const stats = await getAppStatistics(meta.appId || meta.packageName);

    // Aquí puedes incluir cualquier otro campo necesario para la vista de lista/catálogo
    return {
        appId: meta.appId || meta.packageName,
        name: meta.title || meta.name,
        description: meta.summary || meta.briefDescription, // Usar briefDescription si existe
        icon: meta.icon,
        category: meta.genre || meta.category || 'General',
        score: stats.score, // Usar score de las estadísticas reales/simuladas
        ratings: stats.ratings || meta.ratings,
        installs: installsText, 
        size_mb: formatBytesToMB(sizeInBytes), 
        version: latestVersion,
        updatedAt: meta.updated || meta.updatedAt,
        // 💡 NUEVO: Incluir likes/dislikes
        likes: stats.likes, 
        dislikes: stats.dislikes,
        // 💡 NUEVO: Incluir Autor y Sistema Operativo para listado
        author: meta.author || 'Desconocido', 
        operatingSystem: meta.operatingSystem || 'Multiplataforma',
        // Se añade el estado para el panel del desarrollador
        status: meta.status || (meta.isPublic === true ? 'approved' : 'pending_review'),
        // Añadir el ID del desarrollador para el filtro en el panel
        submittedBy: meta.submittedBy || 'Desconocido', 
        developerName: meta.developerName || 'Desconocido',
        externalDownloadUrl: meta.externalDownloadUrl || 'N/A',
        isPublic: meta.isPublic,
    };
}

/**
 * Función para obtener el contenido de un archivo meta.json específico.
 */
async function getAppMetadataFromGithub(appId, isPending) {
    // 💡 CORRECCIÓN: Asegurar que la ruta base use la ruta correcta.
    const basePath = isPending ? PENDING_PATH : CATALOG_PATH;
    const contentPath = `${basePath}/${appId}/meta.json`;
    
    try {
        const fileData = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: contentPath });
        const meta = JSON.parse(Buffer.from(fileData.data.content, "base64").toString("utf8"));
        
        // Agregar el path para referencia
        meta.githubPath = contentPath; 
        
        return meta;
    } catch (e) {
        // Propagar el error si no es un 404 para manejo posterior
        if (e.status !== 404) throw e; 
        return null;
    }
}

// ----------------------------------------------------------------------------------
// NUEVA FUNCIÓN: Obtener estadísticas reales (si Firestore está disponible) o simulación.
// ----------------------------------------------------------------------------------
const getAppStatistics = async (appId) => {
    let stats = {
        installs: 0,
        likes: 0,
        dislikes: 0,
        score: 0,
        ratings: 0,
        last7days_downloads: 0
    };

    if (db) {
        try {
            // Asume que tienes una colección 'estadisticas' y 'app_likes'
            const statsDoc = await db.collection('estadisticas').doc(appId).get();
            if (statsDoc.exists) {
                stats = { ...stats, ...statsDoc.data() };
            }
            
            const likesDoc = await db.collection('app_likes').doc(appId).get();
            if (likesDoc.exists) {
                stats = { ...stats, likes: likesDoc.data().likes || 0, dislikes: likesDoc.data().dislikes || 0 };
            }
        } catch (e) {
            console.error(`Error al obtener estadísticas REALES para ${appId}:`, e.message);
        }
    }
    
    // Simulación si no hay datos o si no hay conexión a la DB
    if (stats.installs === 0 && stats.likes === 0 && stats.dislikes === 0) {
        return {
            installs: Math.floor(Math.random() * 1000) * 10,
            likes: Math.floor(Math.random() * 50),
            dislikes: Math.floor(Math.random() * 5),
            score: (Math.random() * (5 - 3) + 3).toFixed(1),
            ratings: Math.floor(Math.random() * 100),
            last7days_downloads: Math.floor(Math.random() * 100)
        };
    }
    
    // Recalcular score basado en likes/dislikes si es necesario (ejemplo simple)
    if (stats.likes + stats.dislikes > 0) {
        const totalVotes = stats.likes + stats.dislikes;
        // Ponderación simple (5 * likes / totalVotes)
        const rawScore = (stats.likes * 5) / totalVotes; 
        // Asegurar que el score esté entre 3.0 y 5.0
        stats.score = Math.max(3.0, Math.min(5.0, rawScore)).toFixed(1);
        stats.ratings = totalVotes;
    }

    return stats;
};

/**
 * Middleware para autenticar al desarrollador usando x-api-key contra Firestore real.
 * 🛑 CORRECCIÓN CLAVE: Busca en Firestore por el campo `apiKey`, no por el ID del documento.
 */
const authenticateDeveloper = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];

    if (!db) {
        return res.status(500).json({
            ok: false,
            error: "Error de configuración: Conexión a Firestore no disponible para autenticación. Revise la inicialización."
        });
    }

    if (!apiKey) {
        return res.status(401).json({ 
            ok: false, 
            error: "Acceso denegado. Se requiere 'x-api-key' en el encabezado." 
        });
    }

    try {
        // -------------------------------------------------------------------------
        // 💡 CORRECCIÓN: Usar .where('apiKey', '==', apiKey) para buscar por valor
        // -------------------------------------------------------------------------
        const snapshot = await db.collection('usuarios').where('apiKey', '==', apiKey).limit(1).get();

        if (snapshot.empty) {
            return res.status(403).json({ 
                ok: false, 
                error: "API Key inválida o no encontrada en la colección de usuarios." 
            });
        }

        const userDoc = snapshot.docs[0];
        const developerData = userDoc.data();
        
        // Agregar el ID del documento (que es el userId)
        developerData.userId = userDoc.id; 

        req.developer = developerData; 
        req.apiKey = apiKey;

        next();

    } catch (e) {
        console.error("Error al autenticar con Firestore:", e.message);
        return res.status(500).json({
            ok: false,
            error: "Error interno en el servicio de autenticación."
        });
    }
};

/**
 * Transforma un archivo base64 (de un input de formulario) en una URL de GitHub blob.
 * Acepta Base64 o URL directa.
 */
async function uploadImageToGithub(base64DataOrUrl, appId, filename, isPending = true) {
    if (!base64DataOrUrl) return null;
    
    // 🛑 CORRECCIÓN CLAVE: Si ya es una URL, la devolvemos inmediatamente.
    if (base64DataOrUrl.startsWith('http')) {
        return base64DataOrUrl; 
    }

    // Procesar Base64
    const match = base64DataOrUrl.match(/^data:(image\/(png|jpeg|webp|gif|svg\+xml));base64,(.*)$/);
    if (!match) {
        // No es Base64 ni URL, se ignora
        return null;
    }

    const [fullMatch, mimeType, extension, data] = match;
    
    // Límite de 2MB para imágenes
    // 💡 CORRECCIÓN: Usar el tamaño de la cadena Base64 antes de ser decodificada (aproximadamente 4/3 del tamaño binario)
    const sizeInBytesEstimate = (data.length * 0.75) - (data.endsWith('==') ? 2 : data.endsWith('=') ? 1 : 0);
    const MAX_SIZE_BYTES = 1024 * 1024 * 2; // 2 MB
    
    if (sizeInBytesEstimate > MAX_SIZE_BYTES) { 
        // Lanza un error para ser capturado en el endpoint
        throw new Error(`El archivo ${filename} excede el límite de 2MB. Tamaño estimado: ${formatBytesToMB(sizeInBytesEstimate)}`);
    }

    // 💡 CORRECCIÓN: Usar la extensión correcta
    let finalFilename = filename;
    // Intentar extraer la extensión real del Base64
    if (mimeType.includes('/')) {
        const actualExtension = mimeType.split('/')[1].replace('+xml', '');
        // Reemplazar la extensión genérica si es necesario
        if (!finalFilename.includes(`.${actualExtension}`)) {
             finalFilename = finalFilename.replace(/\.png|\.jpg|\.jpeg|\.webp|\.gif/i, '') + `.${actualExtension}`;
        }
    }
    
    const basePath = isPending ? PENDING_PATH : CATALOG_PATH;
    const contentPath = `${basePath}/${appId}/${finalFilename}`;
    const commitMessage = `Add ${finalFilename} for ${appId} - by ${appId}`;
    
    try {
        // Primero, intentar obtener el SHA actual para sobrescribir (si existe)
        let sha = undefined;
        try {
            const fileData = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: contentPath });
            sha = fileData.data.sha;
        } catch (e) {
            // Se ignora el 404, el archivo no existe
        }
        
        const response = await octokit.repos.createOrUpdateFileContents({
            owner: G_OWNER,
            repo: G_REPO,
            path: contentPath,
            message: commitMessage,
            content: data, // El Base64 sin el prefijo 'data:...'
            sha: sha, // Se incluye el SHA si se encontró, para sobrescribir
        });

        // La descarga es más rápida que el raw.githubusercontent.com
        return response.data.content.download_url;
        
    } catch (e) {
        console.error(`Error al subir ${filename} a GitHub:`, e.message);
        // Devolver null o el base64 original si falla puede ser arriesgado. Mejor lanzar el error.
        throw new Error(`Error al subir imagen a GitHub: ${e.message}`);
    }
}

/**
 * 💡 NUEVA FUNCIÓN: Elimina un archivo de GitHub.
 */
async function deleteFileFromGithub(appId, filename, isPending = true) {
    const basePath = isPending ? PENDING_PATH : CATALOG_PATH;
    const contentPath = `${basePath}/${appId}/${filename}`;
    const commitMessage = `Remove ${filename} for ${appId}`;
    
    try {
        const fileData = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: contentPath });
        const sha = fileData.data.sha;

        await octokit.repos.deleteFile({
            owner: G_OWNER,
            repo: G_REPO,
            path: contentPath,
            message: commitMessage,
            sha: sha, 
        });
        
        return true;
    } catch (e) {
        // Ignorar si el archivo no existe (404)
        if (e.status !== 404) {
            console.error(`Error al eliminar ${filename} de GitHub:`, e.message);
        }
        return false;
    }
}

/**
 * Crea o actualiza un archivo JSON en GitHub.
 * 💡 MEJORA: Permite especificar la ruta base (PENDING o CATALOG)
 */
async function saveMetadataToGithub(appId, metadata, isPending, commitMessage) {
    const jsonContent = JSON.stringify(metadata, null, 2);
    const basePath = isPending ? PENDING_PATH : CATALOG_PATH;
    const contentPath = `${basePath}/${appId}/meta.json`;
    const contentBase64 = Buffer.from(jsonContent).toString('base64');
    
    let sha = undefined;
    try {
        const fileData = await octokit.repos.getContent({
            owner: G_OWNER,
            repo: G_REPO,
            path: contentPath
        });
        sha = fileData.data.sha;
    } catch (e) {} // Ignorar si el archivo no existe

    const response = await octokit.repos.createOrUpdateFileContents({
        owner: G_OWNER,
        repo: G_REPO,
        path: contentPath,
        message: commitMessage,
        content: contentBase64,
        sha: sha, 
    });
    
    return response.data.commit;
}

/**
 * 💡 NUEVA FUNCIÓN: Elimina una carpeta completa (junto con el meta.json) en GitHub.
 * Esto es necesario después de aprobar o rechazar una app pendiente.
 */
async function deleteAppFolderFromGithub(appId, isPending) {
    const basePath = isPending ? PENDING_PATH : CATALOG_PATH;
    const appPath = `${basePath}/${appId}`;
    
    try {
        // 1. Obtener todos los archivos en esa carpeta para borrarlos uno por uno.
        const treeResponse = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: appPath });
        // Asegurar que sea un array si solo hay un archivo
        const filesToDelete = Array.isArray(treeResponse.data) ? treeResponse.data : [treeResponse.data];

        for (const file of filesToDelete) {
             // Solo eliminar archivos, no subcarpetas.
             if (file.type === 'file') {
                 console.log(`- Eliminando archivo: ${file.path}`);
                 // Hay que obtener el SHA de nuevo si el tree es recursivo, 
                 // pero getContent ya da el SHA correcto si no es recursivo.
                 await octokit.repos.deleteFile({
                    owner: G_OWNER,
                    repo: G_REPO,
                    path: file.path,
                    message: `Cleanup: Remove ${file.name} for ${appId}`,
                    sha: file.sha, // Usar el SHA del file individual
                });
             }
        }
        return true;
        
    } catch (e) {
        // Ignorar 404 (carpeta no existe o ya está vacía)
        if (e.status !== 404) {
            console.error(`Error al eliminar la carpeta ${appPath} de GitHub:`, e.message);
        }
        return false;
    }
}

/**
 * Función genérica para consumir API, procesar la respuesta y guardar el LOG EXTERNO.
 */
const guardarLogExterno = async (logData) => {
    const horaConsulta = new Date(logData.timestamp).toISOString();
    const url = `${LOG_GUARDADO_BASE_URL}/log_consulta?host=${encodeURIComponent(logData.domain)}&hora=${encodeURIComponent(horaConsulta)}&endpoint=${encodeURIComponent(logData.endpoint)}&userId=${logData.userId || 'public_access'}&costo=${logData.cost}`;
    
    try {
        await axios.get(url, { httpsAgent });
    } catch (e) {
        console.error("Error al guardar log en API externa:", e.message);
    }
};

const getOriginDomain = (req) => {
  const origin = req.headers.origin || req.headers.referer;
  if (!origin) return "Unknown/Direct Access";
  try {
    const parsedUrl = new url.URL(origin);
    return parsedUrl.host; 
  } catch (e) {
    return origin; 
  }
};

const replaceBranding = (data) => {
  if (typeof data === 'string') {
    return data.replace(/@otra|\[FACTILIZA]/g, NEW_BRANDING);
  }
  if (Array.isArray(data)) {
    return data.map(item => replaceBranding(item));
  }
  if (typeof data === 'object' && data !== null) {
    const newObject = {};
    for (const key in data) {
      if (Object.prototype.hasOwnProperty.call(data, key)) {
        if (key === "bot_used") {
          continue; 
        } else {
          newObject[key] = replaceBranding(data[key]);
        }
      }
    }
    return newObject;
  }
  return data;
};

const procesarRespuesta = (response) => {
  let processedResponse = replaceBranding(response);

  delete processedResponse["developed-by"];
  delete processedResponse["credits"];

  const userPlan = {
    tipo: "public-access",
    creditosRestantes: "N/A",
  };

  if (processedResponse.data) {
    delete processedResponse.data["developed-by"];
    delete processedResponse.data["credits"];

    processedResponse.data.userPlan = userPlan;
    processedResponse.data["powered-by"] = "Consulta PE";
  }

  processedResponse["consulta-pe"] = {
    poweredBy: "Consulta PE",
    userPlan,
  };

  return processedResponse;
};

const transformarRespuestaBusqueda = (response) => {
  let processedResponse = procesarRespuesta(response);

  if (processedResponse.message && typeof processedResponse.message === 'string') {
    processedResponse.message = processedResponse.message.replace(/\s*↞ Puedes visualizar la foto de una coincidencia antes de usar \/dni ↠\s*/, '').trim();
  }

  return processedResponse;
};

const consumirAPI = async (req, res, targetUrl, costo, transformer = procesarRespuesta) => {
  const domain = getOriginDomain(req);
  const logData = {
    userId: req.developer ? req.developer.userId : "public_access", 
    timestamp: new Date(),
    domain: domain,
    cost: costo, 
    endpoint: req.path,
  };
    
  try {
    const response = await axios.get(targetUrl, { httpsAgent });
    const processedResponse = transformer(response.data); 

    if (response.status >= 200 && response.status < 300) {
        guardarLogExterno(logData);
    }
    
    res.json(processedResponse);
  } catch (error) {
    console.error(`Error al consumir API externa (${targetUrl}):`, error.message);
    
    const errorResponse = {
      ok: false,
      error: "Error en API externa",
      details: error.response ? error.response.data : error.message,
    };
    
    const processedErrorResponse = procesarRespuesta(errorResponse);
    const statusCode = error.response ? error.response.status : 500;
    
    res.status(statusCode).json(processedErrorResponse);
  }
};


/* ----------------------------------------------------------------------------------
   SERVIDOR EXPRESS
-------------------------------------------------------------------------------------*/

const app = express();
// 🚀 CORRECCIÓN CLAVE: Aumentar el límite de body para aceptar múltiples imágenes Base64 grandes (20MB)
app.use(express.json({ limit: "20mb" })); 

const corsOptions = {
  origin: "*", 
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE", 
  allowedHeaders: ["Content-Type", "x-api-key", "x-admin-key"], 
  exposedHeaders: ["x-api-key", "x-admin-key"],
  credentials: true, 
};

app.use(cors(corsOptions)); 
app.use(express.static('public'));

/* ----------------------------------------------------------------------------------
   ENDPOINTS DE DESARROLLADOR
-------------------------------------------------------------------------------------*/

app.get("/api/dev/me", authenticateDeveloper, (req, res) => {
    res.json({
        ok: true,
        // Usar el userId del documento para el developerInfo
        developerInfo: {
            userId: req.developer.userId, 
            developerName: req.developer.developerName || req.developer.email,
            email: req.developer.email,
        },
        message: `Bienvenido/a, ${req.developer.developerName || req.developer.email}. Tu API Key es válida.`,
        apiKey: req.apiKey
    });
});

/**
 * 💡 NUEVO ENDPOINT: Búsqueda de Play Store.
 * GET /api/dev/apps/lookup/playstore?packageId={id}
 * Función: Debe buscar en Google Play y devolver el nombre, ícono y una descripción.
 */
app.get("/api/dev/apps/lookup/playstore", authenticateDeveloper, async (req, res) => {
    const { packageId } = req.query;

    if (!packageId) {
        return res.status(400).json({ ok: false, error: "El parámetro 'packageId' es obligatorio." });
    }

    try {
        // 🛑 CORRECCIÓN APLICADA: Se elimina el parámetro 'country: us' 
        // para mejorar la compatibilidad y capacidad de búsqueda de gplay.
        const playStoreMeta = await gplay.app({ appId: packageId }); 

        res.json({
            ok: true,
            message: `Datos de la aplicación '${playStoreMeta.title}' obtenidos de Google Play Store.`,
            appData: {
                appId: playStoreMeta.appId,
                name: playStoreMeta.title,
                iconUrl: playStoreMeta.icon,
                // Usar 'summary' (descripción corta) o 'description' (descripción larga)
                briefDescription: playStoreMeta.summary, 
                fullDescription: playStoreMeta.descriptionHTML,
                category: playStoreMeta.genre,
                developer: playStoreMeta.developer,
                // Datos adicionales útiles
                version: playStoreMeta.version,
                updated: playStoreMeta.updated,
                installs: playStoreMeta.installs,
                score: playStoreMeta.score,
                ratings: playStoreMeta.ratings,
                screenshots: playStoreMeta.screenshots, // Capturas de pantalla
                video: playStoreMeta.video // URL de video
            }
        });

    } catch (e) {
        // 💡 MEJORA: Unifica el mensaje de error para "No encontrada"
        const isNotFound = e.message && (e.message.includes('App not found') || e.message.includes('Not Found'));
        
        if (isNotFound) {
            return res.status(404).json({ 
                ok: false, 
                error: `Aplicación no encontrada en Play Store. Verifica el ID: '${packageId}'.` 
            });
        }
        
        console.error("Error al buscar app en Play Store:", e.message);
        res.status(500).json({ 
            ok: false, 
            error: "Error interno al procesar la solicitud. " + e.message 
        });
    }
});


/**
 * 💡 NUEVO ENDPOINT: Búsqueda de Apps por nombre en Play Store.
 * GET /api/dev/apps/search/playstore?query={name}
 * Función: Permite buscar apps por nombre (ej. facebook) y devuelve una lista de resultados.
 */
app.get("/api/dev/apps/search/playstore", authenticateDeveloper, async (req, res) => {
    const { query } = req.query;

    if (!query) {
        return res.status(400).json({ ok: false, error: "El parámetro 'query' es obligatorio para la búsqueda." });
    }

    try {
        // 🛑 CORRECCIÓN CLAVE: Uso correcto de gplay.search
        const results = await gplay.search({
            term: query,
            num: 10, // Limitar a 10 resultados para no sobrecargar
            lang: 'es', // Usar español para resultados relevantes si es posible
            country: 'us'
        });

        const formattedResults = results.map(app => ({
            appId: app.appId,
            name: app.title,
            icon: app.icon,
            developer: app.developer,
            score: app.scoreText,
            price: app.priceText,
            summary: app.summary,
            genre: app.genre,
            // Puedes usar app.appId en el endpoint /lookup para obtener más detalles
        }));

        res.json({
            ok: true,
            message: `Resultados de la búsqueda para '${query}' en Google Play Store (país: US).`,
            count: formattedResults.length,
            apps: formattedResults
        });

    } catch (e) {
        console.error("Error al buscar apps en Play Store:", e.message);
        // Si no hay resultados, gplay.search puede devolver un array vacío o lanzar un error genérico en algunos casos.
        if (e.message.includes('App not found')) {
             return res.status(404).json({ ok: false, error: `No se encontraron resultados para la búsqueda '${query}'.` });
        }
        res.status(500).json({ 
            ok: false, 
            error: "Error interno al procesar la solicitud. " + e.message 
        });
    }
});


/**
 * 🚀 FUNCIÓN 1: Subir App desde Play Store (Busca y Enriquecer)
 * POST /api/dev/apps/submit/playstore
 * (No se modifican los campos de SO/Autor/Video aquí, ya que se obtienen de Play Store)
 */
app.post("/api/dev/apps/submit/playstore", authenticateDeveloper, async (req, res) => {
    const { playStoreId, directDownloadUrl, briefDescription } = req.body;
    
    if (!playStoreId) {
        return res.status(400).json({ ok: false, error: "El campo 'playStoreId' es obligatorio." });
    }
    // 💡 AÑADIDO: Validación de directDownloadUrl, ya que es la clave para la descarga
    if (!directDownloadUrl) {
         return res.status(400).json({ ok: false, error: "El campo 'directDownloadUrl' es obligatorio para la descarga." });
    }
    
    try {
        // 🛑 CORRECCIÓN APLICADA: Se elimina el parámetro 'country: us'
        const playStoreMeta = await gplay.app({ appId: playStoreId });
        
        // 1. Subida de archivos (el ícono es una URL, se usa la función para manejar la URL)
        const iconUrl = await uploadImageToGithub(playStoreMeta.icon, playStoreId, "icon.png", true);

        // 💡 MEJORA: Obtener las capturas de pantalla de Play Store (que son URLs)
        const screenshotUrls = playStoreMeta.screenshots || [];

        const metadata = {
            appId: playStoreId,
            title: playStoreMeta.title,
            icon: iconUrl,
            summary: playStoreMeta.summary,
            description: playStoreMeta.descriptionHTML,
            genre: playStoreMeta.genre,
            score: playStoreMeta.score,
            ratings: playStoreMeta.ratings,
            installs: playStoreMeta.installs,
            screenshots: screenshotUrls,
            developer: playStoreMeta.developer,
            externalDownloadUrl: directDownloadUrl,
            briefDescription: briefDescription || playStoreMeta.summary,
            // 💡 ESTADO DE LA APLICACIÓN
            status: "pending_review", 
            submittedBy: req.developer.userId, 
            developerName: req.developer.developerName || playStoreMeta.developer,
            submissionDate: new Date().toISOString(),
            source: "playstore_scraped",
            // Campos adicionales para la reconstrucción del catálogo
            updated: playStoreMeta.updated,
            version: playStoreMeta.version,
            // Cálculo del tamaño (gplay.app no siempre da el tamaño en bytes, a veces en string, se usa una conversión simple si es necesario)
            apk_size: (playStoreMeta.size && typeof playStoreMeta.size === 'string' && playStoreMeta.size.includes('M')) 
                      ? parseFloat(playStoreMeta.size.replace('M', '').replace(',', '.')) * 1024 * 1024 
                      : 0,
            // Datos opcionales que Play Store a menudo tiene
            operatingSystem: 'Android',
            author: playStoreMeta.developer, 
            video: playStoreMeta.video,
            isPublic: false, // Por defecto al subir
        };
        
        const commit = await saveMetadataToGithub(
            playStoreId, 
            metadata, 
            true, // isPending = true
            `Play Store Submission: ${playStoreMeta.title} (${playStoreId})`
        );
        
        // 💡 CLAVE: Reconstruir el archivo pendiente
        await rebuildPendingFile();

        res.json({
            ok: true,
            message: "✅ Aplicación enviada a revisión con datos de Play Store.",
            appId: playStoreId,
            status: "En revisión",
            commitUrl: commit.html_url
        });

    } catch (e) {
        const isNotFound = e.message && (e.message.includes('App not found') || e.message.includes('Not Found'));
        if (isNotFound) {
            return res.status(404).json({ 
                ok: false, 
                error: `AppId '${playStoreId}' no encontrada en Google Play Store.` 
            });
        }
        console.error("Error al enviar app Play Store:", e.message);
        res.status(500).json({ 
            ok: false, 
            error: "Error interno al procesar la solicitud. " + e.message 
        });
    }
});


/**
 * 🚀 FUNCIÓN 2: Subir App no Play Store (Carga Manual Completa)
 * POST /api/dev/apps/submit/manual
 * 💡 MEJORAS: Soporte para Base64/URL directa, video de YouTube, SO y Autor.
 */
app.post("/api/dev/apps/submit/manual", authenticateDeveloper, async (req, res) => {
    const { 
        appName, packageName, directDownloadUrl, 
        iconBase64, classification, website, language, 
        briefDescription, fullDescription, 
        screenshotsBase64 = [], 
        operatingSystem, 
        author, 
        version = '1.0.0', apk_size = 0, youtubeUrl
    } = req.body;
    
    // --- Validación básica de campos obligatorios ---
    if (!appName || !packageName || !directDownloadUrl || !iconBase64 || !briefDescription || !classification || !operatingSystem || !language) {
        return res.status(400).json({ 
            ok: false, 
            error: "Faltan campos obligatorios: Nombre de la app, Package ID, URL de descarga, URL/Base64 del Ícono, Descripción breve, Clasificación, Sistema Operativo e Idioma." 
        });
    }

    const appId = packageName;
    
    try {
        // 1. Subida de archivos (Base64 O URL directa) a GitHub
        const iconUrl = await uploadImageToGithub(iconBase64, appId, "icon.png", true);
        
        const screenshotUrls = [];
        // 💡 CORRECCIÓN: Limitar a 8 capturas de pantalla, y aceptar Base64 O URL
        for (let i = 0; i < Math.min(screenshotsBase64.length, 8); i++) {
            // Se usa un nombre genérico, la extensión será determinada por la función
            const ssUrl = await uploadImageToGithub(screenshotsBase64[i], appId, `screenshot_${i + 1}.png`, true); 
            if (ssUrl) screenshotUrls.push(ssUrl);
        }

        // 2. Creación de la metadata
        const metadata = {
            appId: appId,
            title: appName,
            icon: iconUrl,
            category: classification, // Usado como clasificación/categoría
            summary: briefDescription,
            description: fullDescription,
            developer: req.developer.developerName || req.developer.email,
            developerWebsite: website,
            language: language,
            externalDownloadUrl: directDownloadUrl,
            screenshots: screenshotUrls,
            video: youtubeUrl, 
            operatingSystem: operatingSystem, 
            author: author || req.developer.developerName || 'Desarrollador No Especificado', 
            // 💡 ESTADO DE LA APLICACIÓN
            status: "pending_review", 
            submittedBy: req.developer.userId, 
            developerName: req.developer.developerName || req.developer.email,
            submissionDate: new Date().toISOString(),
            source: "manual_submission",
            // Datos del catálogo (simulados)
            score: 0,
            ratings: 0,
            installs: "0+",
            version: version,
            apk_size: apk_size, // Tamaño en bytes, o 0
            updatedAt: new Date().getTime(),
            isPublic: false, // Por defecto al subir
        };
        
        // 3. Guardar la metadata en GitHub
        const commit = await saveMetadataToGithub(
            appId, 
            metadata, 
            true, // isPending = true
            `Manual Submission: ${appName} (${appId})`
        );
        
        // 💡 CLAVE: Reconstruir el archivo pendiente
        await rebuildPendingFile();

        res.json({
            ok: true,
            message: "✅ Aplicación enviada a revisión con datos manuales. Se almacenó el archivo `meta.json` y los archivos multimedia en GitHub.",
            appId: appId,
            status: "En revisión",
            commitUrl: commit.html_url
        });

    } catch (e) {
        console.error("Error al enviar app Manual:", e.message);
        // Devolver un error 413 si es un problema de payload muy grande
        const statusCode = e.message.includes("excede el límite de 2MB") ? 413 : 500;
        res.status(statusCode).json({ 
            ok: false, 
            error: "Error interno al procesar la solicitud: " + e.message 
        });
    }
});

/**
 * 💡 NUEVO ENDPOINT: Eliminar/Reemplazar Icono, Capturas, Imagen Destacada o Video.
 * PUT /api/dev/apps/:appId/media
 * 💡 MEJORA: Unificado con la edición de información básica
 * PUT /api/dev/apps/:appId/edit
 */
app.put("/api/dev/apps/:appId/edit", authenticateDeveloper, async (req, res) => {
    const { appId } = req.params;
    const { 
        iconBase64, // Puede ser Base64 o URL
        screenshotsBase64 = null, // null = no cambiar, [] = borrar todas, [base64, ...] = reemplazar
        youtubeUrl, 
        // Campos de texto para edición de información básica
        appName, briefDescription, fullDescription, classification, 
        operatingSystem, language, author, directDownloadUrl, version, apk_size 
    } = req.body;
    
    // 1. Determinar si la app está en PENDING o CATALOG
    let isPending = true;
    let currentMeta = await getAppMetadataFromGithub(appId, true); // Intentar en PENDING

    if (!currentMeta) {
        currentMeta = await getAppMetadataFromGithub(appId, false); // Intentar en CATALOG
        isPending = false;
    }

    if (!currentMeta) {
         return res.status(404).json({ ok: false, error: `Aplicación con ID '${appId}' no encontrada en estado pendiente o aprobado.` });
    }
    
    // 2. Validar que el desarrollador sea el propietario (o administrador, si se implementa)
    // Se usa el userId que es más robusto
    const developerMatch = (currentMeta.submittedBy === req.developer.userId);
                          
    if (!developerMatch) {
         return res.status(403).json({ 
             ok: false, 
             error: "Acceso denegado. No eres el desarrollador que subió esta aplicación." 
         });
    }

    let updates = {
        icon: currentMeta.icon,
        screenshots: currentMeta.screenshots || [],
        video: currentMeta.video,
        updatedAt: new Date().getTime(),
        // Campos de texto: Solo se actualiza si se envía el valor
        title: appName || currentMeta.title,
        summary: briefDescription || currentMeta.summary,
        description: fullDescription || currentMeta.description,
        category: classification || currentMeta.category,
        operatingSystem: operatingSystem || currentMeta.operatingSystem,
        language: language || currentMeta.language,
        author: author || currentMeta.author,
        externalDownloadUrl: directDownloadUrl || currentMeta.externalDownloadUrl,
        version: version || currentMeta.version,
        apk_size: apk_size || currentMeta.apk_size,
    };
    
    let commitMessage = `Update for ${appId}:`;
    let changesMade = false;
    
    // Si la app está APROBADA y el cambio es de versión/APK/descarga, se requiere nueva revisión
    if (!isPending && (version || directDownloadUrl)) {
         updates.status = "pending_update_review";
         commitMessage += " Version update submitted for review.";
         changesMade = true;
    }

    // --- 3. Actualizar ICONO ---
    if (iconBase64 !== undefined && iconBase64 !== null) {
        if (iconBase64.length > 0) {
            updates.icon = await uploadImageToGithub(iconBase64, appId, "icon.png", isPending);
            commitMessage += " Icon replaced.";
        } else {
            if (updates.icon && !updates.icon.startsWith('http')) {
                await deleteFileFromGithub(appId, "icon.png", isPending);
            }
            updates.icon = null;
            commitMessage += " Icon removed.";
        }
        changesMade = true;
    }

    // --- 4. Actualizar URL de VIDEO (YouTube) ---
    if (youtubeUrl !== undefined && youtubeUrl !== null && youtubeUrl !== currentMeta.video) {
        updates.video = (youtubeUrl.length > 0) ? youtubeUrl : null;
        commitMessage += updates.video ? " Video URL updated." : " Video URL removed.";
        changesMade = true;
    }
    
    // --- 5. Actualizar CAPTURAS DE PANTALLA ---
    if (screenshotsBase64 !== null) {
        // Borrar archivos antiguos
        for (let i = 1; i <= 8; i++) {
            await deleteFileFromGithub(appId, `screenshot_${i}.png`, isPending);
        }
        
        updates.screenshots = [];
        // Subir las nuevas capturas. 💡 CORRECCIÓN: Aplicar límite de 8 aquí también.
        for (let i = 0; i < Math.min(screenshotsBase64.length, 8); i++) {
            const ssUrl = await uploadImageToGithub(screenshotsBase64[i], appId, `screenshot_${i + 1}.png`, isPending);
            if (ssUrl) updates.screenshots.push(ssUrl);
        }

        commitMessage += updates.screenshots.length > 0 ? ` Screenshots replaced (${updates.screenshots.length} new).` : " Screenshots removed.";
        changesMade = true;
    }
    
    // 6. Comprobar si hay cambios en los campos de texto
    const textFields = ['title', 'summary', 'description', 'category', 'operatingSystem', 'language', 'author', 'externalDownloadUrl', 'version', 'apk_size'];
    textFields.forEach(field => {
        // Solo compara si el campo existe en el body (o se envía null/cadena vacía)
        if (req.body[field] !== undefined && req.body[field] !== null && req.body[field] !== currentMeta[field]) {
             // Si el campo enviado está vacío, solo actualizar si no lo estaba antes
             if (req.body[field].length === 0 && currentMeta[field] === undefined) return;
             
             // Si el campo tiene un valor, se actualiza
             updates[field] = req.body[field];
             
             // Si el campo de texto se actualizó, se considera un cambio
             if (updates[field] !== currentMeta[field]) {
                 commitMessage += ` ${field} updated.`;
                 changesMade = true;
             }
        }
    });


    if (!changesMade) {
        return res.status(200).json({ ok: true, message: "No se proporcionaron cambios para aplicar. Metadata sin modificar." });
    }

    // 7. Guardar la nueva metadata
    const newMeta = { ...currentMeta, ...updates };

    const commit = await saveMetadataToGithub(
        appId, 
        newMeta, 
        isPending, // Se guarda en la misma ruta, si es un cambio de versión se requerirá movimiento manual
        commitMessage
    );
    
    // 8. Reconstruir el catálogo y archivo pendiente si es necesario
    if (!isPending) {
         await rebuildCatalogFile();
    }
    // Si la app está pendiente, la metadata ya se actualizó en PENDING_PATH, actualizamos el archivo JSON
    if (isPending || newMeta.status === "pending_update_review") {
         await rebuildPendingFile();
    }
    
    res.json({
        ok: true,
        message: `✅ Aplicación actualizada exitosamente. Estado actual: ${newMeta.status}.`,
        appId: appId,
        commitUrl: commit.html_url,
        newMetadata: newMeta
    });

    try {
    } catch (e) {
        console.error("Error al actualizar media:", e.message);
        // Devolver un error 413 si es un problema de payload muy grande
        const statusCode = e.message.includes("excede el límite de 2MB") ? 413 : 500;
        res.status(statusCode).json({ 
            ok: false, 
            error: "Error interno al procesar la solicitud: " + e.message 
        });
    }
});

/**
 * 🚀 FUNCIÓN 3: Panel de Versiones, Me Gusta y Estadísticas
 * GET /api/dev/apps
 * 💡 CORRECCIÓN CLAVE: Implementa la lógica para leer apps pendientes y aprobadas de GitHub.
 */
app.get("/api/dev/apps", authenticateDeveloper, async (req, res) => {
    const developerUserId = req.developer.userId;
    
    try {
        let allDeveloperApps = [];
        
        // 1. Obtener todos los meta.json de CATALOG_PATH y PENDING_PATH
        let allMetaFiles = [];
        const pathsToSearch = [CATALOG_PATH, PENDING_PATH];

        for (const basePath of pathsToSearch) {
             let treeResponse;
             try {
                treeResponse = await octokit.git.getTree({
                    owner: G_OWNER,
                    repo: G_REPO,
                    tree_sha: 'HEAD', // Obtener el árbol más reciente
                    recursive: 'true',
                });
             } catch (e) {
                 console.warn(`Error al obtener árbol de GitHub para ${basePath}: ${e.message}`);
                 continue;
             }
             
             const metaFiles = treeResponse.data.tree.filter(item => 
                 item.path.startsWith(basePath + '/') && item.path.endsWith('/meta.json') && item.type === 'blob'
             );
             allMetaFiles.push(...metaFiles);
        }

        const developerAppsPromises = allMetaFiles.map(async (file) => {
            try {
                const blobResponse = await octokit.git.getBlob({ owner: G_OWNER, repo: G_REPO, file_sha: file.sha });
                const meta = JSON.parse(Buffer.from(blobResponse.data.content, "base64").toString("utf8"));
                
                // 🛑 FILTRO CLAVE: Filtrar solo las apps subidas por el desarrollador actual (por userId)
                if (meta.submittedBy === developerUserId) {
                    const stats = await getAppStatistics(meta.appId);
                    
                    // 💡 LÓGICA DE ESTADO CORREGIDA
                    let status = meta.status;
                    let message = "Detalles de la aplicación.";
                    
                    // a) Si no hay 'status' en el meta.json, lo inferimos
                    if (!status) {
                        const isInPendingPath = file.path.startsWith(PENDING_PATH + '/');
                        
                        if (isInPendingPath) {
                            // Si está en la carpeta de pendientes, siempre es 'Pending Review'
                            status = 'pending_review';
                        } else if (meta.isPublic === true) {
                            // Si está en la carpeta del catálogo y es público
                            status = 'approved';
                        } else {
                            // Si está en el catálogo, no es público, y no tiene status, algo anda mal, pero se asume pendiente.
                            status = 'pending_review'; 
                        }
                    }

                    // b) Asignación del mensaje según el estado final
                    if (status === 'approved') {
                        status = 'Aprobada';
                        message = `Reporte: ${stats.likes} Me Gusta, ${stats.dislikes} No Me Gusta, con una puntuación media de ${stats.score}.`;
                    } else if (status === 'rejected') {
                         status = 'Rechazada'; // Corrección para el problema de estado
                         message = `Rechazada. Razón: ${meta.reason || 'No especificada'}.`;
                    } else if (status === 'pending_update_review') {
                         status = 'Pendiente Actualización';
                         message = `Actualización de versión pendiente de revisión.`;
                    } else {
                         // Corregido: 'pending_review' o cualquier otro estado no aprobado
                         status = 'En revisión'; // Corrección para el problema de estado
                         message = "Esperando revisión del administrador.";
                    }

                    return {
                        appId: meta.appId,
                        title: meta.title,
                        // 💡 CORRECCIÓN CLAVE: Añadir el icono para el panel
                        icon: meta.icon, 
                        status: status, // Estado corregido
                        versions: [{ 
                            version: meta.version || '1.0.0', 
                            status: status, 
                            date: meta.updatedAt || meta.submissionDate
                        }],
                        stats: stats,
                        likes: stats.likes,
                        dislikes: stats.dislikes,
                        message: message,
                        submissionDate: meta.submissionDate,
                        source: meta.source
                    };
                }
                return null;
             } catch (e) {
                 console.warn(`No se pudo cargar meta.json para el desarrollador: ${file.path}: ${e.message}`);
                 return null;
             }
        });
        
        const finalAppsList = (await Promise.all(developerAppsPromises)).filter(app => app !== null);

        res.json({
            ok: true,
            developer: req.developer.developerName || req.developer.email,
            apps: finalAppsList,
            totalCount: finalAppsList.length,
            message: "Lista de aplicaciones con historial de versiones, estado y estadísticas (reales o simuladas).",
        });

    } catch (e) {
        console.error("Error al obtener apps del desarrollador:", e.message);
        res.status(500).json({ ok: false, error: e.message });
    }
});


/**
 * 🚀 FUNCIÓN 4: Eliminar aplicación del desarrollador
 * DELETE /api/dev/apps/:appId
 */
app.delete("/api/dev/apps/:appId", authenticateDeveloper, async (req, res) => {
    const { appId } = req.params;
    
    // Intentar encontrar en CATALOG_PATH primero (aprobadas o rechazadas)
    let isPending = false;
    let currentMeta = await getAppMetadataFromGithub(appId, false); 

    if (!currentMeta) {
        // Intentar en PENDING_PATH
        currentMeta = await getAppMetadataFromGithub(appId, true); 
        isPending = true;
    }

    if (!currentMeta) {
         return res.status(404).json({ ok: false, error: `Aplicación con ID '${appId}' no encontrada.` });
    }
    
    // Validar propiedad
    if (currentMeta.submittedBy !== req.developer.userId) {
         return res.status(403).json({ 
             ok: false, 
             error: "Acceso denegado. No eres el desarrollador que subió esta aplicación." 
         });
    }

    try {
        // Eliminar la carpeta completa (archivos multimedia + meta.json)
        const pathToDelete = isPending ? PENDING_PATH : CATALOG_PATH;
        await deleteAppFolderFromGithub(appId, isPending);

        // Reconstruir los archivos de catálogo/pendientes afectados
        if (!isPending) {
             await rebuildCatalogFile();
        }
        await rebuildPendingFile();

        res.json({
            ok: true,
            message: `✅ Aplicación '${currentMeta.title}' (${appId}) eliminada permanentemente del sistema (${pathToDelete}).`,
            appId: appId
        });

    } catch (e) {
        console.error("Error al eliminar app:", e.message);
        res.status(500).json({ 
            ok: false, 
            error: "Error interno al eliminar la aplicación de GitHub. " + e.message 
        });
    }
});


/* ----------------------------------------------------------------------------------
   ENDPOINTS DE PANEL DE ADMINISTRACIÓN
-------------------------------------------------------------------------------------*/

/**
 * 💡 NUEVO ENDPOINT: Listar aplicaciones pendientes para el panel de administración.
 * GET /api/admin/pending
 * 💡 CORRECCIÓN CLAVE: Este endpoint soluciona el problema de "El panel de aprobación no carga".
 */
app.get("/api/admin/pending", async (req, res) => {
    // NOTA DE SEGURIDAD: Aquí se debería validar si el usuario es Admin.
    
    try {
        const pendingData = await rebuildPendingFile(); // Forzar la reconstrucción
        const pendingAppsList = [];
        
        // Aplanar el objeto pending_apps_by_developer
        for (const developerId in pendingData.pending_apps_by_developer) {
            pendingAppsList.push(...pendingData.pending_apps_by_developer[developerId]);
        }
        
        // Mapear al formato de respuesta
        const formattedList = pendingAppsList.map(meta => ({
            appId: meta.appId,
            title: meta.title,
            developerName: meta.developerName || meta.author,
            submissionDate: meta.submissionDate,
            status: meta.status,
            source: meta.source,
            icon: meta.icon,
            briefDescription: meta.summary,
            externalDownloadUrl: meta.externalDownloadUrl
        }));

        res.json({
            ok: true,
            count: formattedList.length,
            apps: formattedList,
            message: `Mostrando ${formattedList.length} aplicaciones pendientes de revisión. (Fuente: Archivo apps_en_revision_data.json).`
        });

    } catch (e) {
        console.error("🚫 Error al obtener la lista de apps pendientes:", e.message);
        res.status(500).json({ ok: false, error: "Error interno al acceder a los datos de GitHub/Pendientes. Revise el token y los permisos." });
    }
});


/**
 * 🚀 FUNCIÓN 5: Aprobar o Rechazar una aplicación
 * POST /api/admin/review
 */
app.post("/api/admin/review", async (req, res) => {
    const { appId, action, reason } = req.body;
    
    if (!appId || !action || (action === 'reject' && !reason)) {
         return res.status(400).json({ ok: false, error: "Faltan campos obligatorios: appId, action, y reason (si se rechaza)." });
    }
    
    // NOTA DE SEGURIDAD: Aquí se debería validar si el usuario es Admin, pero se ha omitido a petición del usuario.
    
    const pendingFilePath = `${PENDING_PATH}/${appId}/meta.json`;

    try {
        // 1. Obtener la metadata PENDIENTE
        const fileData = await octokit.repos.getContent({ 
            owner: G_OWNER, 
            repo: G_REPO, 
            path: pendingFilePath 
        });
        const meta = JSON.parse(Buffer.from(fileData.data.content, "base64").toString("utf8"));
        
        if (action === 'approve') {
            meta.status = "approved";
            meta.isPublic = true;
            meta.approvedDate = new Date().toISOString();
            
            // 2. Guardar el meta.json APROBADO en la carpeta CATALOG_PATH
            const commitApprove = await saveMetadataToGithub(
                appId, 
                meta, 
                false, // isPending = false (Mover a CATALOG_PATH)
                `Approve: ${meta.title} (${appId}). Now public.`
            );

            // 3. Eliminar la carpeta PENDIENTE completa
            await deleteAppFolderFromGithub(appId, true);
            
            // 🛑 PASO CLAVE: Reconstruir el catálogo y el archivo pendiente
            await rebuildCatalogFile();
            await rebuildPendingFile();

            res.json({
                ok: true,
                message: "🎉 Aplicación APROBADA y publicada en el catálogo. Catálogo global actualizado.",
                appId: appId,
                commitUrl: commitApprove.html_url
            });

        } else if (action === 'reject') {
            meta.status = "rejected";
            meta.reason = reason;
            meta.rejectedDate = new Date().toISOString();
            
            // 1. Guardar la razón de rechazo en el meta.json, marcar como NO público y MOVERLO a CATALOG_PATH (para referencia del desarrollador)
             meta.isPublic = false;
             const commitReject = await saveMetadataToGithub(
                appId, 
                meta, 
                false, // isPending = false (Mover a CATALOG_PATH - para historial)
                `Reject: ${meta.title} (${appId}). Reason: ${reason}. Moved to catalog (private).`
            );
            
            // 2. Eliminar la carpeta PENDIENTE
             await deleteAppFolderFromGithub(appId, true);
             
            // 🛑 PASO CLAVE: Reconstruir el archivo pendiente
            await rebuildPendingFile();

            res.json({
                ok: true,
                message: `🚫 Aplicación RECHAZADA. Razón: ${reason}. Se movió al historial del desarrollador.`,
                appId: appId,
                commitUrl: commitReject.html_url
            });
        } else {
             res.status(400).json({ ok: false, error: "Acción no válida. Debe ser 'approve' o 'reject'." });
        }
    } catch (e) {
        console.error("Error al revisar app:", e.message);
        const status = e.status === 404 ? 404 : 500;
        res.status(status).json({ ok: false, error: e.message || "Error interno del servidor." });
    }
});


/* ----------------------------------------------------------------------------------
   ENDPOINTS DEL CATÁLOGO PÚBLICO (OPTIMIZADOS)
-------------------------------------------------------------------------------------*/

/**
 * 💡 ENDPOINT DE TODOS: Usa el catálogo pre-generado
 * GET /api/public/apps/all
 */
app.get("/api/public/apps/all", (req, res) => {
    // 💡 Usa la función para obtener el catálogo cacheado del archivo apps_data.json
    const catalog = getCatalogData();
    res.json(catalog);
});


/**
 * 💡 ENDPOINT DE DETALLES: Debe seguir leyendo de GitHub para dar *todos* los detalles.
 * GET /api/public/apps/:appId
 */
app.get("/api/public/apps/:appId", async (req, res) => {
    let { appId: inputId } = req.params;
    let actualAppId = inputId; 
    
    try {
        const appPath = `${CATALOG_PATH}/${actualAppId}`;
        let raw;
        
        // 1. Lectura del meta.json de GitHub (proceso lento, pero detallado)
        raw = await octokit.repos.getContent({ 
            owner: G_OWNER, 
            repo: G_REPO, 
            path: `${appPath}/meta.json` 
        });

        const meta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
        
        if (meta.isPublic === false) {
             throw new Error(`Aplicación con ID '${actualAppId}' no está disponible públicamente.`);
        }
        
        const stats = await getAppStatistics(actualAppId);

        // Esta vez devolvemos TODOS los datos de la metadata, no solo la versión reducida.
        const enhancedMeta = await enhanceAppMetadata(meta);

        const responseData = {
            ok: true, 
            app: meta, // Devolvemos la metadata completa de GitHub
            // Campos clave para la vista pública
            downloadUrl: meta.externalDownloadUrl,
            ...enhancedMeta, // Incluye score, likes, dislikes, etc.
            stats: stats, 
        };

        return res.json(responseData);

    } catch (e) {
        const errorMessage = e.message || "Error interno al obtener los detalles de la aplicación.";
        
        if (errorMessage.includes("not found") || e.status === 404) {
            return res.status(404).json({ ok: false, error: `Aplicación con ID '${inputId}' no encontrada.` });
        }

        console.error(`Error al obtener detalles de app ${inputId}:`, e);
        return res.status(500).json({ ok: false, error: errorMessage });
    }
});


/**
 * 💡 NUEVO: Endpoints de Interacción PÚBLICA (Like/Dislike)
 * POST /api/public/apps/:appId/:action
 * La acción puede ser 'like', 'dislike' o 'remove'.
 */
const handleLikeAction = async (appId, action, userId) => {
    if (!db) {
        throw new Error("Conexión a Firestore no disponible.");
    }
    
    if (!['like', 'dislike', 'remove'].includes(action)) {
         throw new Error("Acción no válida. Use 'like', 'dislike' o 'remove'.");
    }

    const docRef = db.collection('app_likes').doc(appId);

    let result;

    await db.runTransaction(async (t) => {
        const doc = await t.get(docRef);
        // La estructura de users ahora guarda el último voto
        let currentData = doc.exists ? doc.data() : { likes: 0, dislikes: 0, users: {} };
        let userAction = currentData.users[userId];
        
        // Limpiar la acción anterior
        if (userAction === 'like' && action !== 'like') {
            currentData.likes = Math.max(0, currentData.likes - 1);
        } else if (userAction === 'dislike' && action !== 'dislike') {
            currentData.dislikes = Math.max(0, currentData.dislikes - 1);
        }
        
        // Aplicar la nueva acción (solo si es diferente a la anterior)
        let newAction = userAction;
        if (action === 'like' && userAction !== 'like') {
            currentData.likes++;
            newAction = 'like';
        } else if (action === 'dislike' && userAction !== 'dislike') {
            currentData.dislikes++;
            newAction = 'dislike';
        } 
        
        // Caso: El usuario hace clic de nuevo en la misma acción (Toggle/Deshacer)
        if (userAction === action && action !== 'remove') {
            // Deshacer el voto si hace clic de nuevo
            delete currentData.users[userId];
            newAction = 'none'; // No hay acción
            if (action === 'like') {
                currentData.likes = Math.max(0, currentData.likes - 1);
            } else {
                currentData.dislikes = Math.max(0, currentData.dislikes - 1);
            }
        } else if (action === 'remove' && userAction) {
             // Si es 'remove', borra el voto
             delete currentData.users[userId];
             newAction = 'none';
        } else if (newAction !== 'none') {
             // Si hay nueva acción, actualizar
             currentData.users[userId] = newAction;
        }

        // Asegurarse de que no haya negativos
        currentData.likes = Math.max(0, currentData.likes);
        currentData.dislikes = Math.max(0, currentData.dislikes);

        t.set(docRef, currentData, { merge: true });
        result = currentData;
    });
    
    // Llamar a la reconstrucción del catálogo para reflejar la nueva puntuación
    rebuildCatalogFile(); 
    
    return result;
};

app.post("/api/public/apps/:appId/:action(like|dislike|remove)", async (req, res) => {
    const { appId, action } = req.params;
    // 💡 NOTA: En un entorno de producción, DEBERÍAS autenticar al usuario
    // y usar su ID real. Aquí usaremos un ID pseudo-aleatorio basado en la IP
    // o un hash del encabezado para simular un usuario anónimo, ya que no hay auth.
    const anonymousUserId = req.headers['x-forwarded-for'] || req.ip; 
    
    if (!appId) {
        return res.status(400).json({ ok: false, error: "Falta 'appId'." });
    }

    try {
        const newStats = await handleLikeAction(appId, action, anonymousUserId);
        
        // Recalcular score simple para la respuesta inmediata
        let score = 'N/A';
        if (newStats.likes + newStats.dislikes > 0) {
            const totalVotes = newStats.likes + newStats.dislikes;
            const rawScore = (newStats.likes * 5) / totalVotes; 
            score = Math.max(3.0, Math.min(5.0, rawScore)).toFixed(1);
        }
        
        res.json({
            ok: true,
            message: `Acción '${action}' registrada para la app ${appId}.`,
            stats: {
                likes: newStats.likes,
                dislikes: newStats.dislikes,
                score: score,
                ratings: newStats.likes + newStats.dislikes
            }
        });
    } catch (e) {
        console.error(`Error al procesar acción ${action} para ${appId}:`, e.message);
        res.status(500).json({ ok: false, error: e.message });
    }
});


/* ----------------------------------------------------------------------------------
   ENDPOINTS: API DE CONSULTAS
-------------------------------------------------------------------------------------*/

// 🛑 Endpoints de Consulta ELIMINADOS según la solicitud

// -------------------- RUTA RAÍZ Y ARRANQUE DEL SERVIDOR --------------------

app.get("/", (req, res) => {
  res.json({
    ok: true,
    mensaje: "🚀 Catálogo Público / API Consulta PE y Developer Console funcionando.",
    "developer-console": {
      docs: "/api/dev/me",
      submission_manual: "POST /api/dev/apps/submit/manual",
      submission_playstore: "POST /api/dev/apps/submit/playstore",
      edit_app: "PUT /api/dev/apps/:appId/edit", 
      delete_app: "DELETE /api/dev/apps/:appId",
      my_apps_list: "GET /api/dev/apps", 
      playstore_lookup: "GET /api/dev/apps/lookup/playstore?packageId={id}",
      playstore_search: "GET /api/dev/apps/search/playstore?query={name}"
    },
    "admin-console": {
        pending_list: "GET /api/admin/pending", 
        review_action: "POST /api/admin/review (approve/reject)"
    },
    "catalogo-publico": {
        full_catalog: "/api/public/apps/all",
        search: "/api/public/apps/search?query=...",
        popular: "/api/public/apps/popular",
        details: "/api/public/apps/:appId",
        interaccion: "/api/public/apps/:appId/:action (like|dislike|remove)" 
    },
    "endpoints-consulta": "🚫 Los endpoints de consulta GET /api/dni*, /api/ruc* y /api/sunarp fueron eliminados según la solicitud."
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
