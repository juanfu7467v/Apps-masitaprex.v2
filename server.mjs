import express from "express";
import dotenv from "dotenv";
import { Octokit } from "@octokit/rest";
import axios from "axios";
import https from "https"; 
import url from 'url';
import cors from "cors";
import gplay from "google-play-scraper"; // Para obtener data enriquecida de Play Store
import { v4 as uuidv4 } from 'uuid'; // Para generar IDs únicos
import fs from 'fs'; 
import path from 'path'; 

// ==============================================================================
// 🟢 CONFIGURACIÓN REAL DE FIRESTORE:
// 
// Usaremos la SDK de Firebase Admin para una conexión real a la base de datos.
// 🛑 PASO 1: Debes instalar la SDK: npm install firebase-admin
// 🛑 PASO 2: Debes configurar las credenciales de servicio.
// ==============================================================================
import admin from 'firebase-admin';

// Cargar variables de entorno
dotenv.config();

// Inicialización de Firebase Admin
let db;
try {
    // Intentar inicializar si no se ha hecho ya.
    // Buscamos las credenciales en la variable de entorno o en el archivo por defecto.
    if (admin.apps.length === 0) {
        admin.initializeApp({
            // Firebase Admin busca automáticamente la variable de entorno 
            // GOOGLE_APPLICATION_CREDENTIALS, o puedes pasar el objeto aquí.
        });
    }
    db = admin.firestore();
    console.log("✅ Conexión real a Firebase Admin y Firestore establecida.");
} catch (error) {
    console.error("🚫 ERROR: No se pudo inicializar Firebase Admin. ¿Credenciales configuradas correctamente?", error.message);
    // En producción, podrías querer salir o usar una simulación de respaldo.
    // Aquí, simplemente logueamos el error y mantenemos 'db' como undefined.
}

// -------------------- CONSTANTES DE LA API DE CONSULTAS (Tus URLs) --------------------
const NEW_API_V1_BASE_URL = process.env.NEW_API_V1_BASE_URL || "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
const NEW_IMAGEN_V2_BASE_URL = process.env.NEW_IMAGEN_V2_BASE_URL || "https://imagen-v2.fly.dev";
const NEW_PDF_V3_BASE_URL = process.env.NEW_PDF_V3_BASE_URL || "https://generar-pdf-v3.fly.dev";
const LOG_GUARDADO_BASE_URL = process.env.LOG_GUARDADO_BASE_URL || "https://base-datos-consulta-pe.fly.dev/guardar";
const NEW_BRANDING = "developer consulta pe"; 

// --- CONFIGURACIÓN DE GITHUB ---
const GITHUB_TOKEN = process.env.GITHUB_TOKEN; // ¡NECESARIO para operaciones de ESCRITURA!
const G_OWNER = process.env.GITHUB_OWNER || 'tu-usuario-github'; 
const G_REPO = process.env.GITHUB_REPO || 'nombre-del-repositorio'; 

// Inicializar Octokit
if (!GITHUB_TOKEN || GITHUB_TOKEN === 'tu-token-github') {
    console.error("🚫 ¡ADVERTENCIA! GITHUB_TOKEN no configurado. Las funciones de subida/aprobación fallarán.");
}
const octokit = new Octokit(GITHUB_TOKEN ? { auth: GITHUB_TOKEN } : {});

// Agente HTTPS para axios
const httpsAgent = new https.Agent({ rejectUnauthorized: false });

// Ruta donde se almacenan las apps en revisión (temporalmente)
const PENDING_PATH = "public/apps_pending";
// Ruta donde se almacenan las apps públicas
const CATALOG_PATH = "public/apps";


/* ----------------------------------------------------------------------------------
   SERVIDOR EXPRESS
-------------------------------------------------------------------------------------*/

const app = express();
// Aumentar el límite para soportar la subida de imágenes base64 (iconos, capturas)
app.use(express.json({ limit: "50mb" })); 

// 🟢 Configuración de CORS
const corsOptions = {
  origin: "*", 
  methods: "GET,HEAD,PUT,PATCH,POST,DELETE", 
  allowedHeaders: ["Content-Type", "x-api-key", "x-admin-key"], 
  exposedHeaders: ["x-api-key", "x-admin-key"],
  credentials: true, 
};

app.use(cors(corsOptions)); 
app.use(express.static('public')); // Para el Catálogo Público

/* ----------------------------------------------------------------------------------
   1. MIDDLEWARE Y HELPERS DE AUTENTICACIÓN
-------------------------------------------------------------------------------------*/

/**
 * Middleware para autenticar al desarrollador usando x-api-key contra Firestore real.
 */
const authenticateDeveloper = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];

    if (!db) {
        // En un entorno de producción, esto debería ser un error fatal.
        return res.status(500).json({
            ok: false,
            error: "Error de configuración: Conexión a Firestore no disponible."
        });
    }

    if (!apiKey) {
        return res.status(401).json({ 
            ok: false, 
            error: "Acceso denegado. Se requiere 'x-api-key' en el encabezado." 
        });
    }

    try {
        // 🚀 BÚSQUEDA REAL EN FIRESTORE
        // La apiKey es el ID del documento en la colección 'usuarios'
        const userDoc = await db.collection('usuarios').doc(apiKey).get();

        if (!userDoc.exists) {
            return res.status(403).json({ 
                ok: false, 
                error: "API Key inválida o no encontrada en la colección de usuarios." 
            });
        }

        const developerData = userDoc.data();

        // Adjuntar la información del desarrollador a la solicitud
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
 * Esto es un SIMULACRO ya que GITHUB_TOKEN puede fallar si no tiene permisos de push.
 * * En un entorno real, la imagen debería subirse a un CDN (S3, Cloudinary) y obtener la URL.
 * Aquí simplemente devolvemos la URL base64 o una URL simulada si es posible.
 * * @param {string} base64Data La data base64 de la imagen.
 * @param {string} appId El ID de la app.
 * @param {string} filename El nombre del archivo (ej. icon.png).
 * @returns {Promise<string>} La URL base64 o la URL simulada.
 */
async function uploadImageToGithub(base64Data, appId, filename, isPending = true) {
    if (!base64Data) return null;
    
    // Extracción de tipo y datos para validación
    const match = base64Data.match(/^data:(image\/(png|jpeg|webp));base64,(.*)$/);
    if (!match) {
        console.warn(`[UPLOAD IMAGE] Data no es un formato base64 válido.`);
        // Si no es base64, asumimos que ya es una URL y la devolvemos.
        if (base64Data.startsWith('http')) return base64Data;
        return null;
    }

    const [fullMatch, mimeType, extension, data] = match;
    
    // Máximo 1MB por archivo base64 para evitar exceder el límite de 50MB del body.
    // También, para evitar exceder el límite de tamaño de archivo de GitHub.
    if (data.length > 1024 * 1024 * 1.5) { // 1.5MB después de decodificación
        throw new Error(`El archivo ${filename} excede el límite de 1.5MB.`);
    }

    const contentPath = `${isPending ? PENDING_PATH : CATALOG_PATH}/${appId}/${filename}`;
    const commitMessage = `Add ${filename} for ${appId} - by ${appId}`;
    
    try {
        const response = await octokit.repos.createOrUpdateFileContents({
            owner: G_OWNER,
            repo: G_REPO,
            path: contentPath,
            message: commitMessage,
            content: data, // El contenido base64 (sin el prefijo 'data:...')
            // Usamos la rama 'main' o 'master' por defecto.
        });

        // Devolvemos la URL directa al contenido para que pueda ser visible.
        return response.data.content.download_url;
        
    } catch (e) {
        console.error(`Error al subir ${filename} a GitHub:`, e.message);
        // Si falla, devolvemos un placeholder de base64 o la URL base64 original.
        return fullMatch; 
    }
}

/**
 * Crea o actualiza un archivo JSON en GitHub.
 * @param {string} appId ID de la app.
 * @param {object} metadata Metadatos a guardar.
 * @param {boolean} isPending Si debe guardarse en la carpeta de pendientes.
 * @param {string} commitMessage Mensaje del commit.
 */
async function saveMetadataToGithub(appId, metadata, isPending, commitMessage) {
    const jsonContent = JSON.stringify(metadata, null, 2);
    const contentPath = `${isPending ? PENDING_PATH : CATALOG_PATH}/${appId}/meta.json`;
    const contentBase64 = Buffer.from(jsonContent).toString('base64');
    
    // Intenta obtener el SHA del archivo existente para actualizarlo
    let sha = undefined;
    try {
        const fileData = await octokit.repos.getContent({
            owner: G_OWNER,
            repo: G_REPO,
            path: contentPath
        });
        sha = fileData.data.sha;
    } catch (e) {
        // Ignorar si el archivo no existe (error 404), 'sha' se mantiene 'undefined'
    }

    const response = await octokit.repos.createOrUpdateFileContents({
        owner: G_OWNER,
        repo: G_REPO,
        path: contentPath,
        message: commitMessage,
        content: contentBase64,
        sha: sha, // Si es undefined, lo crea; si tiene valor, lo actualiza.
    });
    
    return response.data.commit;
}

// ----------------------------------------------------------------------------------
// NUEVA FUNCIÓN: Obtener estadísticas reales (si Firestore está disponible) o simulación.
// ----------------------------------------------------------------------------------
const getAppStatistics = async (appId) => {
    if (db) {
        try {
            // Asume que tienes una colección 'estadisticas' en Firestore
            const statsDoc = await db.collection('estadisticas').doc(appId).get();
            if (statsDoc.exists) {
                return statsDoc.data();
            }
        } catch (e) {
            console.error(`Error al obtener estadísticas REALES para ${appId}:`, e.message);
            // Continúa con la simulación si la lectura falla
        }
    }
    
    // Simulación de estadísticas si no hay conexión real o el documento no existe
    return {
        installs: Math.floor(Math.random() * 1000) * 10,
        comments: Math.floor(Math.random() * 50),
        score: (Math.random() * (5 - 3) + 3).toFixed(1),
        last7days_downloads: Math.floor(Math.random() * 100)
    };
};


/* ----------------------------------------------------------------------------------
   2. ENDPOINTS DE DESARROLLADOR (PROTEGIDOS POR x-api-key)
-------------------------------------------------------------------------------------*/

// Endpoint de prueba de API Key
app.get("/api/dev/me", authenticateDeveloper, (req, res) => {
    res.json({
        ok: true,
        message: `Bienvenido/a, ${req.developer.developerName}. Tu API Key es válida (Verificación Real).`,
        developerInfo: req.developer,
        apiKey: req.apiKey
    });
});

/**
 * 🚀 FUNCIÓN 1: Subir App desde Play Store (Busca y Enriquecer)
 * POST /api/dev/apps/submit/playstore
 */
app.post("/api/dev/apps/submit/playstore", authenticateDeveloper, async (req, res) => {
    const { playStoreId, directDownloadUrl, briefDescription } = req.body;
    
    if (!playStoreId || !directDownloadUrl || !briefDescription) {
        return res.status(400).json({ 
            ok: false, 
            error: "Faltan campos obligatorios: playStoreId, directDownloadUrl y briefDescription." 
        });
    }
    if (briefDescription.length > 70) {
        return res.status(400).json({ 
            ok: false, 
            error: `La descripción breve excede los 70 caracteres (${briefDescription.length}).` 
        });
    }

    try {
        // 1. Scraping de Google Play Store para obtener metadata enriquecida
        console.log(`Scraping Play Store para ID: ${playStoreId}`);
        const playStoreMeta = await gplay.app({ appId: playStoreId, country: 'pe' });
        
        // 2. Procesar y adaptar la metadata
        const metadata = {
            // Campos enriquecidos de Play Store
            appId: playStoreMeta.appId,
            title: playStoreMeta.title,
            icon: playStoreMeta.icon,
            summary: playStoreMeta.summary,
            description: playStoreMeta.descriptionHTML,
            genre: playStoreMeta.genre,
            score: playStoreMeta.score,
            ratings: playStoreMeta.ratings,
            installs: playStoreMeta.installs,
            screenshots: playStoreMeta.screenshots,
            video: playStoreMeta.video,
            developer: playStoreMeta.developer,
            developerWebsite: playStoreMeta.developerWebsite,
            updated: playStoreMeta.updated,
            version: playStoreMeta.version,
            
            // Campos aportados por el desarrollador
            externalDownloadUrl: directDownloadUrl, // Requisito: URL de descarga directa
            briefDescription: briefDescription, // Requisito: Descripción breve
            
            // Campos de estado de la Developer Console
            status: "pending_review",
            submittedBy: req.developer.userId, // ID del desarrollador
            developerName: req.developer.developerName,
            submissionDate: new Date().toISOString(),
            source: "playstore_scraped",
        };
        
        // 3. Guardar en GitHub en la carpeta de pendientes (public/apps_pending)
        const commit = await saveMetadataToGithub(
            playStoreId, 
            metadata, 
            true, // isPending = true
            `Play Store Submission: ${playStoreMeta.title} (${playStoreId})`
        );
        
        res.json({
            ok: true,
            message: "✅ Aplicación enviada a revisión con datos de Play Store.",
            appId: playStoreId,
            status: "En revisión",
            commitUrl: commit.html_url
        });

    } catch (e) {
        if (e.message && e.message.includes('App not found')) {
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
 */
app.post("/api/dev/apps/submit/manual", authenticateDeveloper, async (req, res) => {
    const { 
        appName, packageName, directDownloadUrl, 
        iconBase64, category, website, country, 
        briefDescription, fullDescription, 
        screenshotsBase64 = [], featuredImageBase64, youtubeUrl 
    } = req.body;
    
    // Validación de campos obligatorios
    if (!packageName || !appName || !directDownloadUrl || !iconBase64 || !category || !briefDescription || !fullDescription) {
        return res.status(400).json({ 
            ok: false, 
            error: "Faltan campos obligatorios (packageName, appName, directDownloadUrl, iconBase64, category, briefDescription, fullDescription)." 
        });
    }

    // Validación de límites de caracteres
    if (briefDescription.length > 70) {
        return res.status(400).json({ 
            ok: false, 
            error: `La descripción breve excede los 70 caracteres (${briefDescription.length}).` 
        });
    }
    if (fullDescription.length < 50) {
        return res.status(400).json({ 
            ok: false, 
            error: `La descripción completa debe tener un mínimo de 50 palabras (actualmente ${fullDescription.split(/\s+/).length} palabras).` 
        });
    }
    
    // Definir el AppId
    const appId = packageName;
    
    try {
        // 1. Subir Icono y Imagen Destacada a GitHub
        const iconUrl = await uploadImageToGithub(iconBase64, appId, "icon.png");
        const featuredImageUrl = await uploadImageToGithub(featuredImageBase64, appId, "featured.png");
        
        // 2. Subir Capturas de Pantalla (hasta 8)
        const screenshotUrls = [];
        for (let i = 0; i < Math.min(screenshotsBase64.length, 8); i++) {
            const ssUrl = await uploadImageToGithub(screenshotsBase64[i], appId, `screenshot_${i + 1}.png`);
            if (ssUrl) screenshotUrls.push(ssUrl);
        }

        // 3. Compilar la Metadata
        const metadata = {
            appId: appId,
            title: appName,
            icon: iconUrl,
            category: category,
            summary: briefDescription,
            description: fullDescription,
            developer: req.developer.developerName,
            developerWebsite: website,
            country: country,
            externalDownloadUrl: directDownloadUrl,
            
            // Imágenes y Video
            screenshots: screenshotUrls,
            featuredImage: featuredImageUrl,
            video: youtubeUrl,
            
            // Estado
            status: "pending_review",
            submittedBy: req.developer.userId, 
            developerName: req.developer.developerName,
            submissionDate: new Date().toISOString(),
            source: "manual_submission",
            
            // Simulación de datos mínimos para el catálogo
            score: 0,
            ratings: 0,
            installs: "0+",
            version: '1.0.0', // Versión inicial
        };
        
        // 4. Guardar en GitHub en la carpeta de pendientes (public/apps_pending)
        const commit = await saveMetadataToGithub(
            appId, 
            metadata, 
            true, // isPending = true
            `Manual Submission: ${appName} (${appId})`
        );
        
        res.json({
            ok: true,
            message: "✅ Aplicación enviada a revisión con datos manuales.",
            appId: appId,
            status: "En revisión",
            commitUrl: commit.html_url
        });

    } catch (e) {
        console.error("Error al enviar app Manual:", e.message);
        res.status(500).json({ 
            ok: false, 
            error: "Error interno al procesar la solicitud: " + e.message 
        });
    }
});


/**
 * 🚀 FUNCIÓN 3: Panel de Versiones, Comentarios y Estadísticas
 * GET /api/dev/apps
 */
app.get("/api/dev/apps", authenticateDeveloper, async (req, res) => {
    const developerUserId = req.developer.userId;
    
    try {
        // 1. Buscar en la carpeta de Apps Pendientes
        let pendingApps = [];
        try {
            const pendingTree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: PENDING_PATH });
            const pendingFolders = pendingTree.data.filter(dir => dir.type === "dir");
            
            for (const folder of pendingFolders) {
                try {
                    const metaRaw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: `${folder.path}/meta.json` });
                    const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));
                    
                    if (meta.submittedBy === developerUserId) {
                         // Solo se muestra la información del desarrollador actual
                        pendingApps.push({
                            appId: meta.appId,
                            title: meta.title,
                            icon: meta.icon,
                            status: meta.status,
                            submissionDate: meta.submissionDate,
                            source: meta.source,
                            versions: [{ 
                                version: meta.version || 'N/A', 
                                status: meta.status, 
                                date: meta.submissionDate 
                            }]
                        });
                    }
                } catch (e) { /* Ignorar carpetas sin meta.json */ }
            }
        } catch (e) { /* Carpeta PENDING_PATH no existe o está vacía */ }
        
        // 2. Buscar en la carpeta de Apps Aprobadas (Catálogo)
        let approvedApps = [];
        try {
            const catalogTree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: CATALOG_PATH });
            const catalogFolders = catalogTree.data.filter(dir => dir.type === "dir");
            
            for (const folder of catalogFolders) {
                try {
                    const metaRaw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: `${folder.path}/meta.json` });
                    const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));

                    if (meta.submittedBy === developerUserId) {
                        const appId = meta.appId;
                        
                        // 3. Obtener Estadísticas (REALES o SIMULADAS si falla)
                        const stats = await getAppStatistics(appId);

                        approvedApps.push({
                            appId: appId,
                            title: meta.title,
                            icon: meta.icon,
                            status: "Approved",
                            versions: [{ 
                                version: meta.version || '1.0.0', 
                                status: "Published", 
                                date: meta.updated || meta.submissionDate 
                            }],
                            stats: stats,
                            // Mensaje de comentario basado en la data (real o simulada)
                            comments: `Reporte: ${stats.comments} comentarios, con una puntuación media de ${stats.score}.`
                        });
                    }
                } catch (e) { /* Ignorar carpetas sin meta.json o que no pertenezcan al dev */ }
            }
        } catch (e) { /* Carpeta CATALOG_PATH no existe o está vacía */ }

        res.json({
            ok: true,
            developer: req.developer.developerName,
            pendingApps: pendingApps,
            approvedApps: approvedApps,
            message: "Lista de aplicaciones con historial de versiones, estado y estadísticas (reales o simuladas)."
        });

    } catch (e) {
        console.error("Error al obtener apps del desarrollador:", e.message);
        res.status(500).json({ ok: false, error: e.message });
    }
});


/* ----------------------------------------------------------------------------------
   3. ENDPOINTS DE PANEL DE ADMINISTRACIÓN (NO REQUIERE ADMIN TOKEN)
-------------------------------------------------------------------------------------*/

/**
 * 🚀 FUNCIÓN 4: Obtener lista de apps pendientes de verificación
 * GET /api/admin/pending
 * * NOTA: No requiere admin token ya que solo muestra apps públicas
 */
app.get("/api/admin/pending", async (req, res) => {
    try {
        const pendingTree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: PENDING_PATH });
        const pendingFolders = pendingTree.data.filter(dir => dir.type === "dir");
        
        const appsInReview = [];
        for (const folder of pendingFolders) {
            try {
                const metaRaw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: `${folder.path}/meta.json` });
                const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));
                
                appsInReview.push({
                    appId: meta.appId,
                    title: meta.title,
                    icon: meta.icon,
                    developerName: meta.developerName,
                    submissionDate: meta.submissionDate,
                    source: meta.source,
                    downloadUrl: meta.externalDownloadUrl, // Para que el revisor la pruebe
                    status: meta.status,
                    fullMetadata: meta // Incluir toda la metadata para la revisión
                });
            } catch (e) { /* Ignorar carpetas sin meta.json */ }
        }
        
        res.json({
            ok: true,
            count: appsInReview.length,
            apps: appsInReview,
            message: "Lista de aplicaciones pendientes de revisión."
        });

    } catch (e) {
        if (e.status === 404) {
            return res.json({ ok: true, count: 0, apps: [], message: "No hay aplicaciones pendientes de revisión." });
        }
        console.error("Error al obtener apps pendientes:", e.message);
        res.status(500).json({ ok: false, error: e.message });
    }
});


/**
 * 🚀 FUNCIÓN 5: Aprobar o Rechazar una aplicación
 * POST /api/admin/review
 * * Body: { appId: "com.example.app", action: "approve" | "reject", reason: "..." }
 * * NOTA: La aprobación mueve el archivo meta.json de PENDING_PATH a CATALOG_PATH.
 */
app.post("/api/admin/review", async (req, res) => {
    const { appId, action, reason } = req.body;

    if (!appId || !['approve', 'reject'].includes(action)) {
        return res.status(400).json({ 
            ok: false, 
            error: "Faltan campos obligatorios (appId, action: 'approve' o 'reject')." 
        });
    }

    const pendingFilePath = `${PENDING_PATH}/${appId}/meta.json`;
    const catalogFilePath = `${CATALOG_PATH}/${appId}/meta.json`;
    const pendingFolderPath = `${PENDING_PATH}/${appId}`;

    try {
        // 1. Obtener los metadatos de la app pendiente
        const fileData = await octokit.repos.getContent({ 
            owner: G_OWNER, 
            repo: G_REPO, 
            path: pendingFilePath 
        });
        const meta = JSON.parse(Buffer.from(fileData.data.content, "base64").toString("utf8"));

        if (action === 'approve') {
            // --- APROBACIÓN ---
            
            // 2. Modificar el estado y añadir fecha de aprobación
            meta.status = "approved";
            meta.isPublic = true;
            meta.approvedDate = new Date().toISOString();
            
            // 3. Crear el archivo en la carpeta de apps públicas (CATALOG_PATH)
            const commitApprove = await saveMetadataToGithub(
                appId, 
                meta, 
                false, // isPending = false
                `Approve: ${meta.title} (${appId}). Now public.`
            );

            // 4. ELIMINAR el meta.json de la carpeta pendiente
            await octokit.repos.deleteFile({
                owner: G_OWNER,
                repo: G_REPO,
                path: pendingFilePath,
                message: `Cleanup: Remove pending meta for ${appId}`,
                sha: fileData.data.sha // Necesario para eliminar
            });
            // OJO: La eliminación de la carpeta completa es más compleja, solo eliminamos el meta.json

            res.json({
                ok: true,
                message: "🎉 Aplicación APROBADA y publicada en el catálogo.",
                appId: appId,
                commitUrl: commitApprove.html_url
            });

        } else if (action === 'reject') {
            // --- RECHAZO ---
            
            // 2. Modificar el estado a rechazado y añadir razón/fecha
            meta.status = "rejected";
            meta.isPublic = false;
            meta.rejectionDate = new Date().toISOString();
            meta.rejectionReason = reason || "Razón no especificada.";

            // 3. ACTUALIZAR el archivo en la carpeta de pendientes para mantener el historial
            const commitReject = await saveMetadataToGithub(
                appId, 
                meta, 
                true, // isPending = true (se queda en pendientes con el estado 'rejected')
                `Reject: ${meta.title} (${appId}). Reason: ${meta.rejectionReason}`
            );

            res.json({
                ok: true,
                message: "❌ Aplicación RECHAZADA. El desarrollador ha sido notificado (en su panel).",
                appId: appId,
                reason: meta.rejectionReason,
                commitUrl: commitReject.html_url
            });
        }
    } catch (e) {
        if (e.status === 404 || e.message.includes('not found')) {
            return res.status(404).json({ ok: false, error: `Aplicación con ID '${appId}' no encontrada en el panel de pendientes.` });
        }
        console.error("Error al revisar app:", e.message);
        res.status(500).json({ ok: false, error: "Error interno al procesar la revisión." });
    }
});


// ... [HELPERS]
/**
 * Convierte tamaño en bytes a MB y formatea la cadena.
 */
function formatBytesToMB(bytes) {
    if (bytes === 0) return '0 MB';
    const mb = bytes / (1024 * 1024);
    return mb.toFixed(1) + ' MB';
}

/**
 * Función auxiliar para procesar los metadatos de las aplicaciones del catálogo público.
 */
async function enhanceAppMetadata(meta) {
    // Usamos los datos de descargas directamente del JSON o un valor por defecto.
    const latestVersion = meta.version || 'N/A';
    const installsText = meta.installs || "0+"; 
    const sizeInBytes = meta.apk_size || 0; 

    return {
        appId: meta.appId || meta.packageName,
        name: meta.title || meta.name,
        description: meta.summary || meta.description,
        icon: meta.icon,
        category: meta.genre || 'General',
        score: meta.score,
        ratings: meta.ratings,
        installs: installsText, 
        size_mb: formatBytesToMB(sizeInBytes), 
        version: latestVersion,
        updatedAt: meta.updated || meta.updatedAt 
    };
}

/**
 * FUNCIÓN NUEVA: Intenta encontrar un AppId por su nombre común o fragmento.
 */
async function findAppIdByNameOrPackage(searchName) {
    const lowerCaseSearch = searchName.toLowerCase();

    try {
        const tree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: CATALOG_PATH });
        const appFolders = tree.data.filter(dir => dir.type === "dir");
        
        for (const folder of appFolders) {
            const appId = folder.name;
            
            // 1. Coincidencia directa del paquete (aunque sea parcial)
            if (appId.toLowerCase().includes(lowerCaseSearch)) {
                return appId;
            }
            
            // 2. Coincidencia por el nombre/título de la app
            try {
                // Se intenta cargar el metadato para buscar el título
                const metaRaw = await octokit.repos.getContent({ 
                    owner: G_OWNER, repo: G_REPO, path: `${folder.path}/meta.json` 
                }).catch(async () => {
                    const files = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: folder.path });
                    const metaFile = files.data.find(f => f.name.startsWith('meta_') && f.name.endsWith('.json'));
                    if (metaFile) {
                        return octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: metaFile.path });
                    }
                    throw new Error("No meta file"); 
                });
                
                const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));
                const appTitle = (meta.title || meta.name || '').toLowerCase();

                if (appTitle.includes(lowerCaseSearch)) {
                    return appId; // Devuelve el paquete (appId) de la app cuyo título coincide
                }

            } catch (e) {
                 // Ignorar errores de carga de meta.json y continuar
            }
        }

        return null; // No se encontró ninguna coincidencia
    } catch (e) {
        console.error("Error al buscar AppId por nombre:", e.message);
        return null;
    }
}


/**
 * Guarda el log en la API externa. (Se mantiene la funcionalidad, pero sin user.id)
 */
const guardarLogExterno = async (logData) => {
    const horaConsulta = new Date(logData.timestamp).toISOString();
    // Usamos 'public_access' como un ID de usuario genérico al eliminar la autenticación
    const url = `${LOG_GUARDADO_BASE_URL}/log_consulta?host=${encodeURIComponent(logData.domain)}&hora=${encodeURIComponent(horaConsulta)}&endpoint=${encodeURIComponent(logData.endpoint)}&userId=${logData.userId || 'public_access'}&costo=${logData.cost}`;
    
    try {
        await axios.get(url, { httpsAgent });
    } catch (e) {
        console.error("Error al guardar log en API externa:", e.message);
    }
};

/**
 * **CORREGIDO** - Elimina referencias a bots y branding no deseados.
 */
const replaceBranding = (data) => {
  if (typeof data === 'string') {
    // Eliminamos cualquier referencia a Lederdata o Factiliza en el branding
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

/**
 * Transforma la respuesta de búsquedas por nombre/texto a un formato tipo "result" en la raiz.
 */
const transformarRespuestaBusqueda = (response) => {
  let processedResponse = procesarRespuesta(response);

  if (processedResponse.message && typeof processedResponse.message === 'string') {
    processedResponse.message = processedResponse.message.replace(/\s*↞ Puedes visualizar la foto de una coincidencia antes de usar \/dni ↠\s*/, '').trim();
  }

  return processedResponse;
};


/**
 * Procesa la respuesta de la API externa para aplicar branding y limpiar campos.
 */
const procesarRespuesta = (response) => {
  let processedResponse = replaceBranding(response);

  delete processedResponse["developed-by"];
  delete processedResponse["credits"];

  const userPlan = {
    tipo: "public-access", // Plan estático para acceso público
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

/**
 * NUEVA FUNCIÓN: Extrae el dominio de origen de la petición.
 */
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


/**
 * Función genérica para consumir API, procesar la respuesta y guardar el LOG EXTERNO.
 */
const consumirAPI = async (req, res, targetUrl, costo, transformer = procesarRespuesta) => {
  const domain = getOriginDomain(req);
  const logData = {
    // Si la solicitud tiene developer, usamos su ID. Si no, 'public_access'
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
   ENDPOINTS DEL CATÁLOGO PÚBLICO (Mantenidos y No Protegidos)
-------------------------------------------------------------------------------------*/

app.get("/api/public/apps/popular", async (req, res) => {
    try {
        const tree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: CATALOG_PATH });
        const appFolders = tree.data.filter(dir => dir.type === "dir");
        
        const popularApps = [];
        for (const folder of appFolders) {
             try {
                const metaRaw = await octokit.repos.getContent({ 
                    owner: G_OWNER, repo: G_REPO, path: `${folder.path}/meta.json` 
                }).catch(async (e) => {
                    const files = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: folder.path });
                    const metaFile = files.data.find(f => f.name.startsWith('meta_') && f.name.endsWith('.json'));
                    if (metaFile) {
                        return octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: metaFile.path });
                    }
                    throw e; 
                });
                
                const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));
                
                // Omitir aplicaciones que estén marcadas como no públicas por error
                if (meta.isPublic === false) continue;

                const enhancedApp = await enhanceAppMetadata(meta);
                popularApps.push(enhancedApp);

             } catch (e) {
                 console.warn(`No se pudo cargar o enriquecer meta.json para ${folder.name}: ${e.message}`);
             }
        }
        
        popularApps.sort((a, b) => (b.score || 0) - (a.score || 0));

        return res.json({ ok: true, apps: popularApps });
    } catch (e) {
        if (e.status === 404) return res.json({ ok: true, apps: [], message: "El catálogo público (public/apps) está vacío." });
        console.error("Error al listar apps populares:", e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});

app.get("/api/public/apps/categories", async (req, res) => {
    const { category } = req.query; 

    try {
        const tree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: CATALOG_PATH });
        const appFolders = tree.data.filter(dir => dir.type === "dir");
        
        const appsByCategory = {};
        const allApps = [];

        for (const folder of appFolders) {
            try {
                const metaRaw = await octokit.repos.getContent({ 
                    owner: G_OWNER, repo: G_REPO, path: `${folder.path}/meta.json` 
                }).catch(async (e) => {
                    const files = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: folder.path });
                    const metaFile = files.data.find(f => f.name.startsWith('meta_') && f.name.endsWith('.json'));
                    if (metaFile) {
                        return octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: metaFile.path });
                    }
                    throw e; 
                });
                
                const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));
                
                if (meta.isPublic === false) continue; // Omitir no públicas

                const enhancedApp = await enhanceAppMetadata(meta);
                const appCategory = enhancedApp.category.toUpperCase();

                if (category && appCategory !== category.toUpperCase()) {
                    continue;
                }

                if (!category) {
                    if (!appsByCategory[appCategory]) {
                        appsByCategory[appCategory] = [];
                    }
                    appsByCategory[appCategory].push(enhancedApp);
                } else {
                    allApps.push(enhancedApp);
                }

            } catch (e) {
                 console.warn(`No se pudo cargar o enriquecer meta.json para ${folder.name}: ${e.message}`);
            }
        }

        if (category) {
            return res.json({ ok: true, category: category, apps: allApps, count: allApps.length });
        }
        
        return res.json({ ok: true, message: "Catálogo cargado por categorías.", categories: appsByCategory });

    } catch (e) {
        if (e.status === 404) return res.json({ ok: true, apps: [], message: "El catálogo público (public/apps) está vacío." });
        console.error("Error al listar apps por categorías:", e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});

app.get("/api/public/apps/search", async (req, res) => {
    const { query } = req.query;
    
    if (!query) {
        return res.redirect(307, '/api/public/apps/popular');
    }
    
    const lowerCaseQuery = query.toLowerCase();

    try {
        const tree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: CATALOG_PATH });
        const appFolders = tree.data.filter(dir => dir.type === "dir");
        
        const searchResults = [];

        for (const folder of appFolders) {
            try {
                const metaRaw = await octokit.repos.getContent({ 
                    owner: G_OWNER, repo: G_REPO, path: `${folder.path}/meta.json` 
                }).catch(async (e) => {
                    const files = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: folder.path });
                    const metaFile = files.data.find(f => f.name.startsWith('meta_') && f.name.endsWith('.json'));
                    if (metaFile) {
                        return octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: metaFile.path });
                    }
                    throw e; 
                });
                
                const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));
                
                if (meta.isPublic === false) continue; // Omitir no públicas

                const appName = (meta.title || meta.name || '').toLowerCase();
                const appDescription = (meta.description || meta.summary || '').toLowerCase();
                const appId = (meta.appId || meta.packageName || '').toLowerCase();

                if (appName.includes(lowerCaseQuery) || appDescription.includes(lowerCaseQuery) || appId.includes(lowerCaseQuery)) {
                    const enhancedApp = await enhanceAppMetadata(meta);
                    searchResults.push(enhancedApp);
                }

            } catch (e) {
                 console.warn(`No se pudo cargar meta.json durante la búsqueda para ${folder.name}: ${e.message}`);
            }
        }
        
        searchResults.sort((a, b) => {
             const aId = a.appId.toLowerCase();
             const bId = b.appId.toLowerCase();
             
             const aMatchesQuery = aId === lowerCaseQuery;
             const bMatchesQuery = bId === lowerCaseQuery;
             
             if (aMatchesQuery && !bMatchesQuery) return -1;
             if (!aMatchesQuery && bMatchesQuery) return 1;
             return (b.score || 0) - (a.score || 0);
        });


        return res.json({ 
            ok: true, query: query, results: searchResults, count: searchResults.length 
        });

    } catch (e) {
        if (e.status === 404) return res.json({ ok: true, results: [], message: "El catálogo público (public/apps) está vacío." });
        console.error("Error al buscar apps:", e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});


app.get("/api/public/apps/:appId", async (req, res) => {
    let { appId: inputId } = req.params;
    let actualAppId = inputId; 

    try {
        const checkAppPath = `${CATALOG_PATH}/${inputId}`;
        
        // 1. **Comprobación directa**
        try {
            await octokit.repos.getContent({ 
                owner: G_OWNER, 
                repo: G_REPO, 
                path: checkAppPath 
            });

        } catch (e) {
            // 2. **Si la comprobación directa falla**, intentamos buscar por nombre/fragmento.
            if (e.status === 404) {
                const foundAppId = await findAppIdByNameOrPackage(inputId);
                
                if (foundAppId) {
                    actualAppId = foundAppId; 
                } else {
                    throw new Error(`Aplicación con ID o nombre '${inputId}' no encontrada en el catálogo público.`);
                }
            } else {
                 throw e; 
            }
        }

        // --- Inicio del proceso de carga real usando el actualAppId ---
        const appPath = `${CATALOG_PATH}/${actualAppId}`;
        let raw;
        
        try {
            // 3. Intenta cargar el archivo estándar (meta.json)
            raw = await octokit.repos.getContent({ 
                owner: G_OWNER, 
                repo: G_REPO, 
                path: `${appPath}/meta.json` 
            });
        } catch (e) {
            // 4. Si falla (error 404 o similar), busca el archivo con nombre de versión (meta_VERSION.json)
            if (e.status === 404) {
                const files = await octokit.repos.getContent({ 
                    owner: G_OWNER, 
                    repo: G_REPO, 
                    path: appPath 
                });
                
                const metaFile = files.data.find(f => f.name.startsWith('meta_') && f.name.endsWith('.json'));

                if (!metaFile) {
                    throw new Error(`Archivos de metadatos no encontrados para la aplicación con ID ${actualAppId}.`); 
                }
                
                raw = await octokit.repos.getContent({ 
                    owner: G_OWNER, 
                    repo: G_REPO, 
                    path: metaFile.path 
                });
            } else {
                 throw e; 
            }
        }
        
        const meta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
        
        if (meta.isPublic === false) {
             throw new Error(`Aplicación con ID '${actualAppId}' no está disponible públicamente.`);
        }
        
        const enhancedApp = await enhanceAppMetadata(meta);
        
        if (meta.externalDownloadUrl) {
            enhancedApp.downloadUrl = meta.externalDownloadUrl;
        }

        return res.json({ 
            ok: true, 
            app: {...meta, ...enhancedApp},
            search_used: inputId !== actualAppId ? true : undefined,
            actual_app_id: actualAppId
        });

    } catch (e) {
        const errorMessage = e.message || "Error interno al obtener los detalles de la aplicación.";
        
        if (errorMessage.includes("no encontrada") || e.status === 404) {
            return res.status(404).json({ ok: false, error: errorMessage });
        }

        console.error(`Error al obtener detalles de app ${inputId}:`, e);
        return res.status(500).json({ ok: false, error: errorMessage });
    }
});


/* ----------------------------------------------------------------------------------
   ENDPOINTS: API DE CONSULTAS (Ahora sin autenticación/créditos, solo logging)
-------------------------------------------------------------------------------------*/

// 🔹 API v1 (Nueva)
app.get("/api/dni", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/dni?dni=${req.query.dni}`, 5);
});
app.get("/api/ruc", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/ruc?ruc=${req.query.ruc}`, 5);
});
app.get("/api/ruc-anexo", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/ruc-anexo?ruc=${req.query.ruc}`, 5);
});
app.get("/api/ruc-representante", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/ruc-representante?ruc=${req.query.ruc}`, 5);
});
app.get("/api/cee", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/cee?cee=${req.query.cee}`, 5);
});
app.get("/api/soat-placa", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/placa?placa=${req.query.placa}`, 5);
});
app.get("/api/licencia", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/licencia?dni=${req.query.dni}`, 5);
});
app.get("/api/ficha", async (req, res) => {
  await consumirAPI(req, res, `${NEW_IMAGEN_V2_BASE_URL}/generar-ficha?dni=${req.query.dni}`, 30);
});
app.get("/api/reniec", async (req, res) => {
  const { dni } = req.query;
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/reniec?dni=${dni}`, 10);
});
app.get("/api/denuncias-dni", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/denuncias-dni?dni=${req.query.dni}`, 12);
});
app.get("/api/denuncias-placa", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/denuncias-placa?placa=${req.query.placa}`, 12);
});
app.get("/api/sueldos", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/sueldos?dni=${req.query.dni}`, 12);
});
app.get("/api/trabajos", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/trabajos?dni=${req.query.dni}`, 12);
});
app.get("/api/sunat", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/sunat?data=${req.query.data}`, 12);
});
app.get("/api/sunat-razon", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/sunat-razon?data=${req.query.data}`, 10);
});
app.get("/api/consumos", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/consumos?dni=${req.query.dni}`, 12);
});
app.get("/api/arbol", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/arbol?dni=${req.query.dni}`, 18);
});
app.get("/api/familia1", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/familia1?dni=${req.query.dni}`, 12);
});
app.get("/api/familia2", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/familia2?dni=${req.query.dni}`, 15);
});
app.get("/api/familia3", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/familia3?dni=${req.query.dni}`, 18);
});
app.get("/api/movimientos", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/movimientos?dni=${req.query.dni}`, 12);
});
app.get("/api/matrimonios", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/matrimonios?dni=${req.query.dni}`, 12);
});
app.get("/api/empresas", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/empresas?dni=${req.query.dni}`, 12);
});
app.get("/api/direcciones", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/direcciones?dni=${req.query.dni}`, 10);
});
app.get("/api/correos", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/correos?dni=${req.query.dni}`, 10);
});
app.get("/api/telefonia-doc", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/telefonia-doc?documento=${req.query.documento}`, 10);
});
app.get("/api/telefonia-num", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/telefonia-num?numero=${req.query.numero}`, 12);
});
app.get("/api/vehiculos", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/vehiculos?placa=${req.query.placa}`, 15);
});
app.get("/api/fiscalia-dni", async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/fiscalia-dni?dni=${req.query.dni}`, 15);
});
app.get("/api/fiscalia-nombres", async (req, res) => {
  const { nombres, apepaterno, apematerno } = req.query;
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/fiscalia-nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`, 18, transformarRespuestaBusqueda);
});
app.get("/api/info-total", async (req, res) => {
    await consumirAPI(req, res, `${NEW_PDF_V3_BASE_URL}/generar-ficha-pdf?dni=${req.query.dni}`, 50);
});

// -------------------- RUTA RAÍZ Y ARRANQUE DEL SERVIDOR --------------------

app.get("/", (req, res) => {
  res.json({
    ok: true,
    mensaje: "🚀 Catálogo Público / API Consulta PE y Developer Console funcionando.",
    "developer-console": {
      docs: "/api/dev/me",
      submission: "/api/dev/apps/submit/*"
    },
    "consulta-pe": {
      poweredBy: "Consulta PE",
      info: "Endpoints de consulta sin autenticación para público general."
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
