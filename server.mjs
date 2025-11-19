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
        // Esto es crucial para que la clave sea válida si fue guardada como una
        // variable de entorno de una sola línea.
        private_key: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
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
    console.error("🚫 ERROR: No se pudo inicializar Firebase Admin. Asegúrate de que todas las variables FIREBASE_* estén configuradas y sean válidas.", error.message);
    // Para depuración: si la clave es demasiado larga, puede ser que el shell/servidor
    // la esté truncando o escapando mal.
    if (process.env.FIREBASE_PRIVATE_KEY && process.env.FIREBASE_PRIVATE_KEY.length < 500) {
         console.warn("ADVERTENCIA: La clave privada parece ser demasiado corta. Revise la variable de entorno.");
    }
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
const CATALOG_FILE = path.join(process.cwd(), 'public', 'apps_data.json'); // El archivo único centralizado

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
 * Función central para reconstruir el archivo apps_data.json.
 * Debería llamarse cada vez que una app es APROBADA o ACTUALIZADA.
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

        // 3. Filtrar los archivos meta.json en la ruta del catálogo
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
                
                if (meta.isPublic === false) return null;

                // Enriquecer y limpiar solo los campos necesarios para el catálogo público
                const enhancedApp = enhanceAppMetadata(meta);
                
                // Incluir toda la metadata para la carga por AppID, pero en la lista completa
                // es mejor mantener la limpieza con enhancedApp para reducir el tamaño del JSON.
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
            count: allApps.length,
            apps: allApps,
            timestamp: new Date().toISOString(),
            message: `Catálogo reconstruido desde Git Tree de la rama '${branchName}'.`
        };

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
        const data = fs.readFileSync(CATALOG_FILE, 'utf8');
        const catalogData = JSON.parse(data);
        
        // Actualizar caché
        appsCatalogCache.data = catalogData;
        appsCatalogCache.timestamp = Date.now();

        return catalogData;
    } catch (e) {
        // El archivo no existe o no se puede leer (ej. primer arranque)
        console.warn(`Catálogo apps_data.json no encontrado o inaccesible: ${e.message}`);
        return { ok: true, count: 0, apps: [], message: "Catálogo vacío. Intente una reconstrucción manual o una subida/aprobación." };
    }
}

// Llama a la reconstrucción del catálogo al inicio para tenerlo listo
rebuildCatalogFile();


/**
 * Transforma metadata a formato público reducido.
 */
function formatBytesToMB(bytes) {
    if (bytes === 0) return '0 MB';
    const mb = bytes / (1024 * 1024);
    return mb.toFixed(1) + ' MB';
}

async function enhanceAppMetadata(meta) {
    const latestVersion = meta.version || 'N/A';
    const installsText = meta.installs || "0+"; 
    const sizeInBytes = meta.apk_size || 0; 

    // Aquí puedes incluir cualquier otro campo necesario para la vista de lista/catálogo
    return {
        appId: meta.appId || meta.packageName,
        name: meta.title || meta.name,
        description: meta.summary || meta.briefDescription, // Usar briefDescription si existe
        icon: meta.icon,
        category: meta.genre || meta.category || 'General',
        score: meta.score,
        ratings: meta.ratings,
        installs: installsText, 
        size_mb: formatBytesToMB(sizeInBytes), 
        version: latestVersion,
        updatedAt: meta.updated || meta.updatedAt 
    };
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
        }
    }
    
    // Simulación
    return {
        installs: Math.floor(Math.random() * 1000) * 10,
        likes: Math.floor(Math.random() * 50),
        dislikes: Math.floor(Math.random() * 5),
        score: (Math.random() * (5 - 3) + 3).toFixed(1),
        last7days_downloads: Math.floor(Math.random() * 100)
    };
};

/**
 * Middleware para autenticar al desarrollador usando x-api-key contra Firestore real.
 */
const authenticateDeveloper = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];

    if (!db) {
        return res.status(500).json({
            ok: false,
            error: "Error de configuración: Conexión a Firestore no disponible. Revise la inicialización."
        });
    }

    if (!apiKey) {
        return res.status(401).json({ 
            ok: false, 
            error: "Acceso denegado. Se requiere 'x-api-key' en el encabezado." 
        });
    }

    try {
        const userDoc = await db.collection('usuarios').doc(apiKey).get();

        if (!userDoc.exists) {
            return res.status(403).json({ 
                ok: false, 
                error: "API Key inválida o no encontrada en la colección de usuarios." 
            });
        }

        const developerData = userDoc.data();

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
 */
async function uploadImageToGithub(base64Data, appId, filename, isPending = true) {
    if (!base64Data) return null;
    
    const match = base64Data.match(/^data:(image\/(png|jpeg|webp));base64,(.*)$/);
    if (!match) {
        if (base64Data.startsWith('http')) return base64Data;
        return null;
    }

    const [fullMatch, mimeType, extension, data] = match;
    
    if (data.length > 1024 * 1024 * 1.5) { 
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
            content: data,
        });

        return response.data.content.download_url;
        
    } catch (e) {
        console.error(`Error al subir ${filename} a GitHub:`, e.message);
        return fullMatch; 
    }
}

/**
 * Crea o actualiza un archivo JSON en GitHub.
 */
async function saveMetadataToGithub(appId, metadata, isPending, commitMessage) {
    const jsonContent = JSON.stringify(metadata, null, 2);
    const contentPath = `${isPending ? PENDING_PATH : CATALOG_PATH}/${appId}/meta.json`;
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
app.use(express.json({ limit: "50mb" })); 

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
        message: `Bienvenido/a, ${req.developer.developerName}. Tu API Key es válida.`,
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
    // ... [Tu lógica original de validación y scraping]

    try {
        const playStoreMeta = await gplay.app({ appId: playStoreId, country: 'pe' });
        
        const metadata = {
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
            developer: playStoreMeta.developer,
            externalDownloadUrl: directDownloadUrl,
            briefDescription: briefDescription,
            status: "pending_review",
            submittedBy: req.developer.userId, 
            developerName: req.developer.developerName,
            submissionDate: new Date().toISOString(),
            source: "playstore_scraped",
            // Campos adicionales para la reconstrucción del catálogo
            updated: playStoreMeta.updated,
            version: playStoreMeta.version,
            apk_size: playStoreMeta.size ? parseFloat(playStoreMeta.size.replace(/[,.]/g, '').replace('MB', '')) * 1024 * 1024 : 0,
        };
        
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
        screenshotsBase64 = [], featuredImageBase64, youtubeUrl,
        version = '1.0.0', apk_size = 0 // Nuevos campos opcionales
    } = req.body;
    
    // ... [Tu lógica original de validación]
    
    const appId = packageName;
    
    try {
        const iconUrl = await uploadImageToGithub(iconBase64, appId, "icon.png");
        const featuredImageUrl = await uploadImageToGithub(featuredImageBase64, appId, "featured.png");
        
        const screenshotUrls = [];
        for (let i = 0; i < Math.min(screenshotsBase64.length, 8); i++) {
            const ssUrl = await uploadImageToGithub(screenshotsBase64[i], appId, `screenshot_${i + 1}.png`);
            if (ssUrl) screenshotUrls.push(ssUrl);
        }

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
            screenshots: screenshotUrls,
            featuredImage: featuredImageUrl,
            video: youtubeUrl,
            status: "pending_review",
            submittedBy: req.developer.userId, 
            developerName: req.developer.developerName,
            submissionDate: new Date().toISOString(),
            source: "manual_submission",
            // Datos del catálogo (simulados)
            score: 0,
            ratings: 0,
            installs: "0+",
            version: version,
            apk_size: apk_size, // Tamaño en bytes, o 0
            updatedAt: new Date().getTime(),
        };
        
        const commit = await saveMetadataToGithub(
            appId, 
            metadata, 
            true, // isPending = true
            `Manual Submission: ${appName} (${appId})`
        );
        
        res.json({
            ok: true,
            message: "✅ Aplicación enviada a revisión con datos manuales. Se almacenó el archivo `meta.json` en GitHub.",
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
 * 🚀 FUNCIÓN 3: Panel de Versiones, Me Gusta y Estadísticas
 * GET /api/dev/apps
 */
app.get("/api/dev/apps", authenticateDeveloper, async (req, res) => {
    const developerUserId = req.developer.userId;
    
    try {
        // ... [Tu lógica original para obtener apps pendientes y aprobadas]
        let pendingApps = [];
        let approvedApps = [];
        // [CÓDIGO DE LECTURA DE APPS PENDIENTES Y APROBADAS (USANDO OCTOKIT) - MANTENER]

        // Simulando la obtención, ya que el código de lectura de Octokit está arriba
        // Reemplaza esta sección con tu lógica completa de lectura de GitHub:
        /* ... TU CÓDIGO DE LECTURA DE GITHUB AQUÍ ...
         ... Asegúrate de obtener el `meta.json` de cada app aprobada y pendiente
         ... y filtrarlas por `meta.submittedBy === developerUserId`
        */
        
        // **INICIO SIMULACIÓN** (Reemplazar con la lógica real de GitHub)
        const appsData = getCatalogData();
        const developerApps = appsData.apps.filter(app => app.developerName === req.developer.developerName);

        for (const app of developerApps) {
            const stats = await getAppStatistics(app.appId);
            approvedApps.push({
                appId: app.appId,
                title: app.name,
                icon: app.icon,
                status: "Approved",
                versions: [{ 
                    version: app.version || '1.0.0', 
                    status: "Published", 
                    date: app.updatedAt
                }],
                stats: stats,
                likes: stats.likes,
                dislikes: stats.dislikes,
                message: `Reporte: ${stats.likes} Me Gusta, ${stats.dislikes} No Me Gusta, con una puntuación media de ${stats.score}.`
            });
        }
        // **FIN SIMULACIÓN**
        
        // ----------------------------------------------------------------------------------
        // NUEVO: Endpoints de Me Gusta (LIKE/DISLIKE)
        // ----------------------------------------------------------------------------------

        // Reemplazaremos la lógica de comentarios con una simulación de Likes/Dislikes
        // Si tienes una colección 'likes' en Firestore, esta es la lógica real:
        const handleLikeAction = async (appId, action) => {
            if (!db) return; // Si Firestore no está, ignoramos

            const docRef = db.collection('app_likes').doc(appId);
            const developerId = req.developer.userId;

            await db.runTransaction(async (t) => {
                const doc = await t.get(docRef);
                let currentData = doc.exists ? doc.data() : { likes: 0, dislikes: 0, users: {} };
                let userAction = currentData.users[developerId];
                
                // Limpiar la acción anterior
                if (userAction === 'like' && action !== 'like') {
                    currentData.likes--;
                } else if (userAction === 'dislike' && action !== 'dislike') {
                    currentData.dislikes--;
                }

                // Aplicar la nueva acción
                if (action === 'like' && userAction !== 'like') {
                    currentData.likes++;
                    currentData.users[developerId] = 'like';
                } else if (action === 'dislike' && userAction !== 'dislike') {
                    currentData.dislikes++;
                    currentData.users[developerId] = 'dislike';
                } else if (action === 'remove' && userAction) {
                    delete currentData.users[developerId];
                }
                
                t.set(docRef, currentData, { merge: true });
                return currentData;
            });
        };
        // [La lógica de estos endpoints debe ser implementada en rutas POST separadas si es necesario.]

        res.json({
            ok: true,
            developer: req.developer.developerName,
            pendingApps: pendingApps,
            approvedApps: approvedApps,
            message: "Lista de aplicaciones con historial de versiones, estado y estadísticas (reales o simuladas).",
            // Sugerencia: Enviar un mensaje al desarrollador sobre los nuevos endpoints de Like/Dislike
        });

    } catch (e) {
        console.error("Error al obtener apps del desarrollador:", e.message);
        res.status(500).json({ ok: false, error: e.message });
    }
});


/* ----------------------------------------------------------------------------------
   ENDPOINTS DE PANEL DE ADMINISTRACIÓN
-------------------------------------------------------------------------------------*/

app.get("/api/admin/pending", async (req, res) => {
    // ... [Tu lógica original de listado de apps pendientes]
    // Esta parte sigue siendo lenta y debe mantenerse ya que necesita leer la carpeta en GitHub.
    // Solo se usa por la administración, por lo que su lentitud es tolerable.
    // ...
});


/**
 * 🚀 FUNCIÓN 5: Aprobar o Rechazar una aplicación
 * POST /api/admin/review
 * **MEJORA:** Llama a rebuildCatalogFile() al aprobar.
 */
app.post("/api/admin/review", async (req, res) => {
    const { appId, action, reason } = req.body;
    // ... [Tu lógica original de validación]
    
    const pendingFilePath = `${PENDING_PATH}/${appId}/meta.json`;

    try {
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
            
            const commitApprove = await saveMetadataToGithub(
                appId, 
                meta, 
                false, // isPending = false
                `Approve: ${meta.title} (${appId}). Now public.`
            );

            await octokit.repos.deleteFile({
                owner: G_OWNER,
                repo: G_REPO,
                path: pendingFilePath,
                message: `Cleanup: Remove pending meta for ${appId}`,
                sha: fileData.data.sha 
            });
            
            // 🛑 PASO CLAVE: Reconstruir el catálogo para que la app esté disponible al instante
            await rebuildCatalogFile();

            res.json({
                ok: true,
                message: "🎉 Aplicación APROBADA y publicada en el catálogo. Catálogo global actualizado.",
                appId: appId,
                commitUrl: commitApprove.html_url
            });

        } else if (action === 'reject') {
            // ... [Tu lógica original de rechazo]
            // ... (No requiere reconstrucción del catálogo)
        }
    } catch (e) {
        // ... [Tu manejo de errores original]
    }
});


/* ----------------------------------------------------------------------------------
   ENDPOINTS DEL CATÁLOGO PÚBLICO (OPTIMIZADOS)
-------------------------------------------------------------------------------------*/

/**
 * 🚀 OPTIMIZADO: Carga todas las apps desde el archivo apps_data.json
 * GET /api/public/apps/all
 */
app.get("/api/public/apps/all", async (req, res) => {
    // Lectura casi instantánea
    const catalogData = getCatalogData();
    
    // Si la cache está vacía, intentamos reconstruir (aunque se hizo al inicio)
    if (catalogData.count === 0 && !appsCatalogCache.data) {
        await rebuildCatalogFile();
        return res.json(getCatalogData());
    }

    return res.json(catalogData);
});


/**
 * 🚀 OPTIMIZADO: Obtener lista de apps populares (ordenado localmente)
 * GET /api/public/apps/popular
 */
app.get("/api/public/apps/popular", async (req, res) => {
    const catalogData = getCatalogData();
    const popularApps = [...catalogData.apps] // Copia para no mutar la cache
        .sort((a, b) => (b.score || 0) - (a.score || 0)); // Ordenar por puntuación

    return res.json({ 
        ok: true, 
        apps: popularApps, 
        count: popularApps.length, 
        message: "Catálogo popular cargado desde la caché (velocidad extrema)." 
    });
});


/**
 * 🚀 OPTIMIZADO: Búsqueda rápida
 * GET /api/public/apps/search
 */
app.get("/api/public/apps/search", async (req, res) => {
    const { query } = req.query;
    
    if (!query) {
        return res.redirect(307, '/api/public/apps/popular');
    }
    
    const lowerCaseQuery = query.toLowerCase();
    const catalogData = getCatalogData();
    
    const searchResults = catalogData.apps.filter(app => {
        const appName = (app.name || '').toLowerCase();
        const appDescription = (app.description || '').toLowerCase();
        const appId = (app.appId || '').toLowerCase();

        return appName.includes(lowerCaseQuery) || 
               appDescription.includes(lowerCaseQuery) || 
               appId.includes(lowerCaseQuery);
    });
    
    searchResults.sort((a, b) => (b.score || 0) - (a.score || 0));

    return res.json({ 
        ok: true, 
        query: query, 
        results: searchResults, 
        count: searchResults.length 
    });
});


/**
 * 🛑 ENDPOINT NO OPTIMIZADO: Debe seguir leyendo de GitHub para dar *todos* los detalles.
 * GET /api/public/apps/:appId
 * Este endpoint es tolerable que sea lento, ya que es una carga individual y no masiva.
 */
app.get("/api/public/apps/:appId", async (req, res) => {
    let { appId: inputId } = req.params;
    let actualAppId = inputId; 
    
    // El proceso de carga detallada debe seguir siendo una lectura a GitHub.
    // Solo los endpoints masivos (all, popular, search) se optimizan.
    // ... [Mantén tu lógica original de carga detallada de GitHub aquí]
    // Para el ejemplo, la mantengo, aunque está incompleta en tu fragmento original.
    
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
        
        // Esta vez devolvemos TODOS los datos de la metadata, no solo la versión reducida.
        const responseData = {
            ok: true, 
            app: meta, // Devolvemos la metadata completa de GitHub
            // Si la metadata tiene URL de descarga, la exponemos
            downloadUrl: meta.externalDownloadUrl,
            // Re-ejecutamos enhanceAppMetadata para tener los campos formateados también
            ...await enhanceAppMetadata(meta) 
        };

        return res.json(responseData);

    } catch (e) {
        const errorMessage = e.message || "Error interno al obtener los detalles de la aplicación.";
        
        if (errorMessage.includes("not found") || e.status === 404) {
            return res.status(404).json({ ok: false, error: errorMessage });
        }

        console.error(`Error al obtener detalles de app ${inputId}:`, e);
        return res.status(500).json({ ok: false, error: errorMessage });
    }
});


/* ----------------------------------------------------------------------------------
   ENDPOINTS: API DE CONSULTAS
-------------------------------------------------------------------------------------*/

// 🔹 API v1 (Nueva) - Se mantienen igual
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
// ... [RESTO DE ENDPOINTS DE CONSULTA (MANTENER)]

// -------------------- RUTA RAÍZ Y ARRANQUE DEL SERVIDOR --------------------

app.get("/", (req, res) => {
  res.json({
    ok: true,
    mensaje: "🚀 Catálogo Público / API Consulta PE y Developer Console funcionando.",
    "developer-console": {
      docs: "/api/dev/me",
      submission: "/api/dev/apps/submit/*"
    },
    "catalogo-publico": {
        full_catalog: "/api/public/apps/all",
        search: "/api/public/apps/search?query=...",
        popular: "/api/public/apps/popular",
        details: "/api/public/apps/:appId"
    }
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
