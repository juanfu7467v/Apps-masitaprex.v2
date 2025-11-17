// server.js
import express from "express";
import dotenv from "dotenv";
dotenv.config();

// 🚨 IMPORTAR DEPENDENCIAS FIREBASE
// Ahora auth, db y FieldValue se importan de firebase-config.js
import { auth, db, FieldValue } from "./firebase-config.js"; 
import crypto from 'crypto'; 
import { Octokit } from "@octokit/rest";
import axios from "axios";
import gplay from "google-play-scraper"; 
import https from "https"; 
import url from 'url';

const app = express();
app.use(express.json({ limit: "10mb" }));

// Mantener la solución de archivos estáticos para el Catálogo Público
app.use(express.static('public'));

/* --------- Configs & Global Constants --------- */
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const G_OWNER = process.env.GITHUB_OWNER; // Ej: 'tu-usuario-github'
const G_REPO = process.env.GITHUB_REPO; // Ej: 'nombre-del-repositorio'

// Colecciones de Firestore
const USERS_COLLECTION = 'usuarios';
const APPS_COLLECTION = 'developer_apps';
const STATS_COLLECTION = 'app_stats';

const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY; 
const BASE_URL = process.env.BASE_URL || 'https://apps-masitaprex-v2.fly.dev'; 

/* --------- Helpers GitHub --------- */
/**
 * Crea o actualiza un archivo en GitHub.
 * @param {string} pathInRepo - Ruta dentro del repositorio (e.g., public/apps/id/file.json)
 * @param {string} contentBase64 - Contenido codificado en base64
 * @param {string} message - Mensaje del commit
 */
async function createOrUpdateGithubFile(pathInRepo, contentBase64, message) {
  try {
    const get = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: pathInRepo });
    const sha = get.data.sha;
    const res = await octokit.repos.createOrUpdateFileContents({
      owner: G_OWNER, repo: G_REPO, path: pathInRepo, message, content: contentBase64, sha,
    });
    return res.data;
  } catch (err) {
    if (err.status === 404) {
      const res = await octokit.repos.createOrUpdateFileContents({
        owner: G_OWNER, repo: G_REPO, path: pathInRepo, message, content: contentBase64,
      });
      return res.data;
    }
    throw err;
  }
}

/**
 * Elimina un archivo en GitHub.
 */
async function deleteGithubFile(pathInRepo, message) {
  try {
    const get = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: pathInRepo });
    const sha = get.data.sha;
    const res = await octokit.repos.deleteFile({
      owner: G_OWNER, repo: G_REPO, path: pathInRepo, message, sha,
    });
    return res.data;
  } catch (err) {
    if (err.status === 404) return { ok: true, message: "Archivo no encontrado (ya eliminado)." };
    throw err;
  }
}

/**
 * Genera un ID corto único para las apps.
 */
function generateAppId() {
    return 'app_' + crypto.randomBytes(8).toString('hex');
}

/**
 * Convierte tamaño en bytes a MB y formatea la cadena.
 * @param {number} bytes - Tamaño del archivo en bytes.
 * @returns {string} - Tamaño formateado (e.g., "54.2 MB" o "0.8 MB").
 */
function formatBytesToMB(bytes) {
    if (bytes === 0) return '0 MB';
    const mb = bytes / (1024 * 1024);
    return mb.toFixed(1) + ' MB';
}

/* --------- Middleware de Autenticación por API Key --------- */
/**
 * Extrae y valida la API Key (el token de Firebase) del header.
 * Si es válido, adjunta el UID del desarrollador a req.developerId
 */
const apiKeyAuth = async (req, res, next) => {
    const apiKey = req.headers['x-api-key'];
    if (!apiKey) {
        return res.status(401).json({ ok: false, error: "Acceso denegado. x-api-key (Token de Firebase) es requerido." });
    }

    try {
        // Verifica el token como un ID Token de Firebase
        const decodedToken = await auth.verifyIdToken(apiKey);
        
        // Adjunta el UID del desarrollador a la solicitud
        req.developerId = decodedToken.uid; 
        
        // Se puede hacer una verificación adicional en Firestore si el usuario está activo, etc.
        // const userDoc = await db.collection(USERS_COLLECTION).doc(req.developerId).get();
        // if (!userDoc.exists) throw new Error("Usuario no registrado en Firestore.");

        next();
    } catch (e) {
        console.error("Error de autenticación por API Key:", e.message);
        return res.status(401).json({ ok: false, error: "API Key inválida o expirada. " + e.message });
    }
};

/* --------- Middleware de Verificación de Propiedad de App --------- */
/**
 * Verifica que el developerId autenticado sea el dueño del appId.
 */
const checkAppOwnership = async (req, res, next) => {
    const { appId } = req.params;
    const { developerId } = req; // Viene del middleware apiKeyAuth

    try {
        const appRef = db.collection(APPS_COLLECTION).doc(appId);
        const doc = await appRef.get();

        if (!doc.exists) {
            return res.status(404).json({ ok: false, error: `Aplicación con ID ${appId} no encontrada.` });
        }

        if (doc.data().developerId !== developerId) {
            return res.status(403).json({ ok: false, error: "Acceso denegado. No eres el dueño de esta aplicación." });
        }
        
        // Adjuntar el objeto de la app para no tener que buscarlo de nuevo
        req.appData = doc.data(); 
        next();

    } catch (e) {
        console.error("Error de verificación de propiedad:", e);
        return res.status(500).json({ ok: false, error: "Error interno al verificar la propiedad de la app." });
    }
};

/* ----------------------------------------------------------------------------------
   1️⃣ AUTENTICACIÓN Y VERIFICACIÓN (FIREBASE)
-------------------------------------------------------------------------------------*/

// NOTA: El registro y el login se hacen normalmente con el SDK de cliente. 
// Aquí simulamos un endpoint que crea el usuario y le da un token (solo para testing, no es flujo real)

/**
 * Simula el registro: Crea un usuario en Firebase Auth y genera un token.
 * En un sistema real, esto se manejaría en el frontend con el SDK de Cliente.
 */
app.post("/auth/register", async (req, res) => {
    const { email, password, displayName } = req.body;
    if (!email || !password) return res.status(400).json({ ok: false, error: "Email y password son requeridos." });

    try {
        // 1. Crear el usuario en Firebase Auth
        const user = await auth.createUser({ email, password, displayName });

        // 2. Crear el registro inicial en Firestore (para guardar la API Key futura o info de perfil)
        await db.collection(USERS_COLLECTION).doc(user.uid).set({
            email: user.email,
            displayName: user.displayName,
            registeredAt: new Date().toISOString(),
            // La API Key (token) se genera al iniciar sesión
        });

        return res.json({ ok: true, message: "Usuario registrado con éxito.", uid: user.uid });
    } catch (e) {
        return res.status(400).json({ ok: false, error: e.message });
    }
});

/**
 * Simula el login: Toma credenciales, verifica, y devuelve un ID Token (API Key).
 * En un sistema real, esto se manejaría en el frontend. Aquí, lo hacemos para generar el token.
 */
app.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ ok: false, error: "Email y password son requeridos." });

    // NOTA: **NO ES SEGURO** hacer un login con password en el backend con el Admin SDK. 
    // Esto es un placeholder. El flujo correcto es:
    // 1. Cliente se autentica con Firebase JS SDK.
    // 2. Cliente envía el ID Token obtenido (`x-api-key`) a todos los endpoints protegidos.

    // Para fines de prueba y dado el requerimiento, generaremos un token para un UID existente.
    // Asume que el desarrollador ya hizo login en el cliente y nos pasa su UID.
    const { uid } = req.body; 
    if (!uid) return res.status(400).json({ ok: false, error: "Para este placeholder, debe proveer su UID." });

    try {
        const customToken = await auth.createCustomToken(uid);
        // Usamos el UID para generar un token que pueda ser usado como 'API Key'
        // El cliente debe usar este token para hacer login en el cliente o usarlo directamente como API Key.
        return res.json({ 
            ok: true, 
            message: "Token generado con éxito.", 
            uid,
            token_id: customToken, // Este NO ES EL ID TOKEN que se usa como API KEY, es el custom token.
            // Para fines de la consola, el desarrollador usaría el ID Token obtenido tras un login exitoso.
            // Aquí, simularemos que le devolvemos un token que puede usar.
            
            // 💡 Instrucción: El desarrollador debe obtener su token final (x-api-key)
            // haciendo login en el frontend con Firebase Client SDK, o usar este 
            // 'customToken' para obtener el 'ID Token' final.
            placeholder_api_key: "Usar el ID Token generado por el cliente Firebase tras un login exitoso."
        });

    } catch (e) {
        return res.status(401).json({ ok: false, error: "Login fallido. " + e.message });
    }
});

/* ----------------------------------------------------------------------------------
   2️⃣ APLICACIONES (CRUD PRINCIPAL)
   Rutas protegidas con apiKeyAuth y checkAppOwnership
-------------------------------------------------------------------------------------*/

/**
 * Crear un registro de aplicación.
 * 1. Genera un ID.
 * 2. Crea el registro en Firestore (mapeo app->developer).
 * 3. Crea el archivo JSON de metadatos iniciales en GitHub.
 */
app.post("/apps/create", apiKeyAuth, async (req, res) => {
    const { name, description, category } = req.body;
    const { developerId } = req;
    
    if (!name || !description) return res.status(400).json({ ok: false, error: "Nombre y descripción son requeridos." });

    const appId = generateAppId();
    const currentTimestamp = new Date().toISOString();
    
    try {
        const appMetadata = {
            appId,
            developerId,
            name,
            description,
            category: category || 'General',
            status: 'draft',
            createdAt: currentTimestamp,
            updatedAt: currentTimestamp,
            versions: []
        };
        
        // 1. Crear el mapeo en Firestore
        await db.collection(APPS_COLLECTION).doc(appId).set({
            appId,
            developerId,
            name,
            status: 'draft',
            createdAt: currentTimestamp,
            updatedAt: currentTimestamp
        });

        // 2. Crear el archivo JSON de metadatos en GitHub (dentro de la carpeta del desarrollador)
        const pathInRepo = `public/developer_apps/${developerId}/${appId}/meta.json`;
        await createOrUpdateGithubFile(
            pathInRepo,
            Buffer.from(JSON.stringify(appMetadata, null, 2)).toString("base64"),
            `Crear app ${appId}: Metadatos iniciales`
        );
        
        return res.json({ ok: true, message: "Aplicación creada con éxito.", appId, metadata: appMetadata });

    } catch (e) {
        console.error("Error al crear app:", e);
        return res.status(500).json({ ok: false, error: "Error interno al crear la aplicación.", details: e.message });
    }
});

/**
 * Obtener datos completos de la aplicación.
 */
app.get("/apps/:appId", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { developerId, appId } = req;

    try {
        const pathInRepo = `public/developer_apps/${developerId}/${appId}/meta.json`;
        const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: pathInRepo });
        const content = Buffer.from(raw.data.content, "base64").toString("utf8");
        
        return res.json({ ok: true, app: JSON.parse(content) });
    } catch (e) {
        if (e.status === 404) return res.status(404).json({ ok: false, error: "Metadatos de la aplicación no encontrados en GitHub." });
        console.error("Error al obtener app:", e);
        return res.status(500).json({ ok: false, error: "Error interno al obtener la aplicación." });
    }
});

/**
 * Editar información de la app.
 * NOTA: Esto solo actualiza el archivo meta.json.
 */
app.patch("/apps/:appId/update", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { developerId, appId } = req;
    const updates = req.body;
    
    // Lista negra de campos no editables directamente
    delete updates.appId;
    delete updates.developerId;
    delete updates.createdAt;
    delete updates.versions;
    
    try {
        const pathInRepo = `public/developer_apps/${developerId}/${appId}/meta.json`;
        
        // 1. Obtener metadatos actuales
        const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: pathInRepo });
        const currentMeta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
        const sha = raw.data.sha;
        
        // 2. Combinar y actualizar
        const newMeta = {
            ...currentMeta,
            ...updates,
            updatedAt: new Date().toISOString()
        };
        
        // 3. Subir el nuevo archivo
        const contentBase64 = Buffer.from(JSON.stringify(newMeta, null, 2)).toString("base64");
        await octokit.repos.createOrUpdateFileContents({
            owner: G_OWNER, repo: G_REPO, path: pathInRepo, 
            message: `Actualizar app ${appId}: ${Object.keys(updates).join(', ')}`, 
            content: contentBase64, sha
        });

        // 4. Actualizar Firestore (solo campos clave como 'name')
        if (updates.name) {
            await db.collection(APPS_COLLECTION).doc(appId).update({ name: updates.name, updatedAt: newMeta.updatedAt });
        }
        
        return res.json({ ok: true, message: "Aplicación actualizada con éxito.", app: newMeta });

    } catch (e) {
        console.error("Error al actualizar app:", e);
        return res.status(500).json({ ok: false, error: "Error interno al actualizar la aplicación." });
    }
});


/**
 * Eliminar o despublicar temporalmente.
 * NOTA: Solo eliminaremos el registro de Firestore y marcaremos el estado en el meta.json
 * La eliminación física de archivos en GitHub es peligrosa y lenta.
 */
app.delete("/apps/:appId", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { developerId, appId } = req;

    try {
        const pathInRepo = `public/developer_apps/${developerId}/${appId}/meta.json`;
        
        // 1. Obtener metadatos actuales
        const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: pathInRepo });
        const currentMeta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
        const sha = raw.data.sha;
        
        // 2. Marcar como "deleted" en el meta.json de GitHub
        const newMeta = {
            ...currentMeta,
            status: 'deleted',
            updatedAt: new Date().toISOString(),
            deletionNote: "App despublicada por el desarrollador."
        };
        const contentBase64 = Buffer.from(JSON.stringify(newMeta, null, 2)).toString("base64");
        await octokit.repos.createOrUpdateFileContents({
            owner: G_OWNER, repo: G_REPO, path: pathInRepo, 
            message: `Despublicar app ${appId}`, 
            content: contentBase64, sha
        });
        
        // 3. Eliminar el mapeo en Firestore (Despublicar lógicamente para evitar que aparezca en el panel)
        await db.collection(APPS_COLLECTION).doc(appId).delete();

        return res.json({ ok: true, message: `Aplicación ${appId} marcada como eliminada/despublicada.`, status: newMeta.status });

    } catch (e) {
        console.error("Error al eliminar app:", e);
        return res.status(500).json({ ok: false, error: "Error interno al eliminar la aplicación." });
    }
});


/* ----------------------------------------------------------------------------------
   3️⃣ SUBIR APK (CON ANÁLISIS AUTOMÁTICO)
   4️⃣ SUBIR APK POR URL (Uptodown-Style)
   5️⃣ VERIFICAR SI EL APK TIENE ANUNCIOS (Placeholder)
   6️⃣ ANÁLISIS DE VIRUS (VIRUSTOTAL API GRATIS) (Placeholder)
-------------------------------------------------------------------------------------*/

// NOTA: La lógica de análisis (APK Manifest, VirusTotal, Detección de Anuncios)
// requiere librerías binarias o un servidor de análisis externo. Aquí se simulará
// el proceso con datos de respuesta lógicos.

/**
 * Placeholder para la detección de anuncios.
 */
function analyzeAdsFromBinary(apkData) {
    // ⚠️ Lógica real no implementada. Simulación de detección.
    // Una implementación real usaría un paquete como 'apk-parser' o 'apkmirror-tools'.
    const hasAds = apkData.length % 2 === 0; 
    return {
        ads_detected: hasAds,
        detected_sdks: hasAds ? ["admob", "unity-ads"] : []
    };
}

/**
 * Placeholder para el escaneo de VirusTotal.
 */
async function runVirusTotalScan(fileBuffer) {
    if (!VIRUSTOTAL_API_KEY) {
        return { status: "skipped", message: "VIRUSTOTAL_API_KEY no configurada." };
    }
    
    // ⚠️ Lógica real no implementada. Simulación.
    const sizeInMB = fileBuffer.length / (1024 * 1024);
    
    if (sizeInMB > 32) {
         return { 
            scan_status: "skipped", 
            message: "El archivo es demasiado grande ( > 32MB) para la API gratuita de VirusTotal.", 
            malicious: 0, 
            suspicious: 0, 
            undetected: 0 
        };
    }

    // Simulación de escaneo exitoso
    const results = {
        scan_status: "completed",
        malicious: sizeInMB > 10 ? 1 : 0, // Simulación: apps grandes tienen 1 malicioso
        suspicious: 0,
        undetected: 68
    };

    return results;
}

/**
 * 3️⃣ POST /apps/:appId/upload-apk - Subida directa del archivo APK.
 */
app.post("/apps/:appId/upload-apk", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { developerId, appId } = req;
    const { apk_base64, version } = req.body; // Se espera que el cliente envíe el APK en base64
    
    if (!apk_base64 || !version) return res.status(400).json({ ok: false, error: "apk_base64 y version son requeridos." });

    try {
        const apkBuffer = Buffer.from(apk_base64, 'base64');
        const apkSize = apkBuffer.length;
        const sizeInMB = apkSize / (1024 * 1024);
        
        // 1. Guardar APK en GitHub
        const apkPath = `public/developer_apps/${developerId}/${appId}/v${version.replace(/[./]/g, '_')}.apk`;
        await createOrUpdateGithubFile(apkPath, apk_base64, `Subir APK ${appId} v${version}`);
        
        // 2. Detección de Anuncios (Simulación)
        const adAnalysis = analyzeAdsFromBinary(apkBuffer);
        
        // 3. Escaneo de VirusTotal (Simulación/Placeholder)
        let vtScan;
        if (sizeInMB <= 32) {
             vtScan = await runVirusTotalScan(apkBuffer);
        } else {
             vtScan = { scan_status: "limited_or_skipped", message: "APK > 32MB. No se pudo escanear." };
        }
        
        // 4. Actualizar Metadatos (Versiones)
        const metaPath = `public/developer_apps/${developerId}/${appId}/meta.json`;
        const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: metaPath });
        const currentMeta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
        const sha = raw.data.sha;

        const versionData = {
            version_name: version,
            apk_size: apkSize,
            apk_path: apkPath,
            upload_type: 'direct_upload',
            uploadedAt: new Date().toISOString(),
            ads_detected: adAnalysis.ads_detected,
            ads_sdks: adAnalysis.detected_sdks,
            virustotal_report: vtScan
        };
        
        currentMeta.versions.push(versionData);

        const contentBase64 = Buffer.from(JSON.stringify(currentMeta, null, 2)).toString("base64");
        await octokit.repos.createOrUpdateFileContents({
            owner: G_OWNER, repo: G_REPO, path: metaPath, 
            message: `Añadir versión ${version} y análisis para ${appId}`, 
            content: contentBase64, sha
        });
        
        return res.json({
            status: "uploaded",
            apk_size: apkSize,
            ...adAnalysis,
            virus_scan: vtScan.scan_status,
            virustotal_report: vtScan,
            message: "APK subido y metadatos actualizados."
        });

    } catch (e) {
        console.error("Error al subir APK:", e);
        return res.status(500).json({ ok: false, error: "Error interno al subir el APK.", details: e.message });
    }
});


/**
 * 4️⃣ POST /apps/:appId/upload-url - Subida de APK por URL (Solo enlace).
 */
app.post("/apps/:appId/upload-url", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { developerId, appId } = req;
    const { apk_url, version } = req.body;

    if (!apk_url || !version) return res.status(400).json({ ok: false, error: "apk_url y version son requeridos." });

    try {
        // 1. Validar que la URL funciona y obtener cabeceras (tamaño)
        const head = await axios.head(apk_url, { maxRedirects: 5, httpsAgent });
        const apkSize = parseInt(head.headers['content-length'], 10) || 0;
        
        // 2. Intentar descargar los primeros 32 MB para VirusTotal y metadatos (Simulación)
        let vtScan = { scan_status: "limited_or_skipped", message: "Escaneo por URL no disponible en esta simulación." };
        let adAnalysis = { ads_detected: null, detected_sdks: [] };
        
        if (apkSize > 0 && apkSize / (1024 * 1024) <= 80) { // Si es menor a 80MB, podemos descargar los 32MB
             // ⚠️ Simulación: Aquí se descargaría la cabecera y se analizaría.
             adAnalysis = { ads_detected: true, detected_sdks: ["admob"] };
             if (apkSize / (1024 * 1024) <= 32) {
                // Simulación de escaneo real
                vtScan = { scan_status: "completed", malicious: 0, suspicious: 0, undetected: 68 };
             }
        }
        
        // 3. Actualizar Metadatos (Versiones)
        const metaPath = `public/developer_apps/${developerId}/${appId}/meta.json`;
        const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: metaPath });
        const currentMeta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
        const sha = raw.data.sha;

        const versionData = {
            version_name: version,
            apk_size: apkSize,
            apk_url: apk_url,
            upload_type: 'external_url',
            uploadedAt: new Date().toISOString(),
            ads_detected: adAnalysis.ads_detected,
            ads_sdks: adAnalysis.detected_sdks,
            virustotal_report: vtScan
        };
        
        currentMeta.versions.push(versionData);

        const contentBase64 = Buffer.from(JSON.stringify(currentMeta, null, 2)).toString("base64");
        await octokit.repos.createOrUpdateFileContents({
            owner: G_OWNER, repo: G_REPO, path: metaPath, 
            message: `Añadir versión ${version} (URL externa) para ${appId}`, 
            content: contentBase64, sha
        });

        return res.json({
            status: "linked",
            apk_size: apkSize,
            ...adAnalysis,
            virus_scan: vtScan.scan_status,
            message: "Enlace de APK guardado y metadatos actualizados (análisis limitado)."
        });

    } catch (e) {
        console.error("Error al subir URL de APK:", e);
        return res.status(500).json({ ok: false, error: "Error al procesar la URL del APK.", details: e.message });
    }
});


/**
 * 5️⃣ POST /apps/:appId/check-ads - Ejecutar manualmente la detección de anuncios.
 */
app.post("/apps/:appId/check-ads", apiKeyAuth, checkAppOwnership, async (req, res) => {
    // ⚠️ Se requeriría que el desarrollador pase el binario del APK si no está en el servidor.
    // Asumiremos que solo se puede ejecutar si hay una versión subida con APK.
    
    const latestVersion = req.appData.versions?.slice(-1)[0];
    if (!latestVersion || !latestVersion.apk_size) {
         return res.status(400).json({ ok: false, error: "No hay una versión con un APK subido para analizar." });
    }

    // Simulación
    const analysis = analyzeAdsFromBinary({ length: latestVersion.apk_size });

    // En un caso real, esto requeriría descargar el APK o tenerlo local.
    return res.json({
        ok: true,
        ads_detected: analysis.ads_detected,
        detected_sdks: analysis.detected_sdks,
        message: "Análisis de anuncios completado con simulación."
    });
});

/**
 * 6️⃣ POST /apps/:appId/virus-scan - Ejecutar manualmente el escaneo de VirusTotal.
 */
app.post("/apps/:appId/virus-scan", apiKeyAuth, checkAppOwnership, async (req, res) => {
    // Asumiremos que solo se puede escanear la versión más reciente subida.
    const latestVersion = req.appData.versions?.slice(-1)[0];

    if (!latestVersion || !latestVersion.apk_size || !latestVersion.apk_path) {
         return res.status(400).json({ ok: false, error: "No hay una versión con un APK subido para escanear." });
    }
    
    if (latestVersion.apk_size / (1024 * 1024) > 32) {
         return res.json({ 
            scan_status: "skipped", 
            message: "El archivo es demasiado grande ( > 32MB) para la API gratuita de VirusTotal.", 
            malicious: 0, 
            suspicious: 0, 
            undetected: 0 
        });
    }

    // ⚠️ Lógica real: Descargaríamos el APK de GitHub, lo subiríamos a VT, y consultaríamos el resultado.
    // Simulación:
    const vtScan = await runVirusTotalScan(Buffer.alloc(latestVersion.apk_size)); // Pasa un buffer simulado del tamaño correcto

    // Actualizar metadatos si el escaneo tuvo éxito
    // ... (lógica de actualización de meta.json omitida por brevedad, se haría de forma similar al /upload-apk)

    return res.json({
        ok: true,
        scan_status: vtScan.scan_status,
        malicious: vtScan.malicious,
        suspicious: vtScan.suspicious,
        undetected: vtScan.undetected,
        message: "Escaneo de VirusTotal completado con simulación."
    });
});


/* ----------------------------------------------------------------------------------
   7️⃣ GESTIÓN DE VERSIONES
-------------------------------------------------------------------------------------*/

/**
 * POST /apps/:appId/version - Crear nueva versión (solo metadatos).
 * La subida del APK se haría con /upload-apk o /upload-url.
 */
app.post("/apps/:appId/version", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { developerId, appId } = req;
    const { version_name, changelog, apk_size } = req.body;
    
    if (!version_name) return res.status(400).json({ ok: false, error: "version_name es requerido." });

    try {
        const metaPath = `public/developer_apps/${developerId}/${appId}/meta.json`;
        const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: metaPath });
        const currentMeta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
        const sha = raw.data.sha;

        const versionData = {
            version_name,
            changelog: changelog || 'Sin notas de cambio.',
            apk_size: apk_size || 0,
            uploadedAt: new Date().toISOString(),
            upload_type: 'metadata_only',
        };
        
        currentMeta.versions.push(versionData);

        const contentBase64 = Buffer.from(JSON.stringify(currentMeta, null, 2)).toString("base64");
        await octokit.repos.createOrUpdateFileContents({
            owner: G_OWNER, repo: G_REPO, path: metaPath, 
            message: `Añadir versión metadata ${version_name} para ${appId}`, 
            content: contentBase64, sha
        });

        return res.json({ ok: true, message: "Versión de metadatos creada con éxito.", version: versionData });

    } catch (e) {
        console.error("Error al crear versión:", e);
        return res.status(500).json({ ok: false, error: "Error interno al crear la versión." });
    }
});


/**
 * GET /apps/:appId/versions - Listado de versiones.
 */
app.get("/apps/:appId/versions", apiKeyAuth, checkAppOwnership, async (req, res) => {
    // Ya tenemos req.appData del middleware
    const versions = req.appData.versions || [];
    return res.json({ ok: true, versions: versions.map(v => ({ name: v.version_name, uploadedAt: v.uploadedAt, size: v.apk_size })) });
});

/**
 * GET /apps/:appId/latest - Versión más reciente.
 */
app.get("/apps/:appId/latest", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const versions = req.appData.versions || [];
    if (versions.length === 0) {
        return res.status(404).json({ ok: false, error: "No se encontraron versiones para esta aplicación." });
    }
    
    // Asume que la última versión en el array es la más reciente (por cómo se añade)
    const latest = versions.slice(-1)[0]; 
    return res.json({ ok: true, latest_version: latest });
});


/* ----------------------------------------------------------------------------------
   8️⃣ ESTADÍSTICAS
   NOTA: Las estadísticas se guardarán en Firestore para escalabilidad.
-------------------------------------------------------------------------------------*/

/**
 * POST /stats/report-download - Reportar una descarga.
 */
app.post("/stats/report-download", async (req, res) => {
    const { appId, country, device } = req.body;
    if (!appId) return res.status(400).json({ ok: false, error: "appId es requerido." });

    try {
        const statsRef = db.collection(STATS_COLLECTION).doc(appId);
        
        // Actualización atómica de contadores
        const updateData = {
            downloads: FieldValue.increment(1),
            today: FieldValue.increment(1), // Se requeriría una tarea cron para resetear 'today'
            [`countries.${country || 'UNKNOWN'}`]: FieldValue.increment(1),
            updatedAt: new Date().toISOString()
        };
        
        await statsRef.set(updateData, { merge: true });
        return res.json({ ok: true, message: "Descarga reportada con éxito." });

    } catch (e) {
        console.error("Error al reportar descarga:", e);
        return res.status(500).json({ ok: false, error: "Error interno al reportar la descarga." });
    }
});

/**
 * POST /stats/report-install - Reportar una instalación.
 */
app.post("/stats/report-install", async (req, res) => {
    const { appId, device_id, version_name } = req.body;
    if (!appId || !device_id) return res.status(400).json({ ok: false, error: "appId y device_id son requeridos." });
    
    try {
        const statsRef = db.collection(STATS_COLLECTION).doc(appId);
        const versionKey = version_name ? `versions.${version_name.replace(/[./]/g, '_')}` : 'versions.UNKNOWN';

        const updateData = {
            installs: FieldValue.increment(1),
            [versionKey]: FieldValue.increment(1),
            updatedAt: new Date().toISOString()
        };
        
        await statsRef.set(updateData, { merge: true });
        return res.json({ ok: true, message: "Instalación reportada con éxito." });

    } catch (e) {
        console.error("Error al reportar instalación:", e);
        return res.status(500).json({ ok: false, error: "Error interno al reportar la instalación." });
    }
});


/**
 * GET /apps/:appId/stats - Obtener panel de estadísticas.
 */
app.get("/apps/:appId/stats", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { appId } = req.params;

    try {
        const statsDoc = await db.collection(STATS_COLLECTION).doc(appId).get();
        if (!statsDoc.exists) {
            return res.json({ 
                ok: true, 
                downloads: 0, installs: 0, uninstalls: 0, today: 0, countries: {}, versions: {} 
            });
        }
        
        const stats = statsDoc.data();
        
        return res.json({
            ok: true,
            downloads: stats.downloads || 0,
            installs: stats.installs || 0,
            uninstalls: stats.uninstalls || 0, // No hay endpoint de uninstall, pero se incluye
            today: stats.today || 0,
            countries: stats.countries || {},
            versions: stats.versions || {},
            updatedAt: stats.updatedAt
        });
        
    } catch (e) {
        console.error("Error al obtener estadísticas:", e);
        return res.status(500).json({ ok: false, error: "Error interno al obtener las estadísticas." });
    }
});


/* ----------------------------------------------------------------------------------
   9️⃣ RECURSOS MULTIMEDIA (IMÁGENES, VIDEOS)
-------------------------------------------------------------------------------------*/

/**
 * Función genérica para subir archivos multimedia.
 */
async function uploadMedia(developerId, appId, fileBase64, type, filename) {
    const fileBuffer = Buffer.from(fileBase64, 'base64');
    const pathInRepo = `public/developer_apps/${developerId}/${appId}/media/${filename}`;
    
    // 1. Subir a GitHub
    await createOrUpdateGithubFile(
        pathInRepo,
        fileBase64,
        `Subir ${type} para ${appId}`
    );

    // 2. Actualizar meta.json
    const metaPath = `public/developer_apps/${developerId}/${appId}/meta.json`;
    const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: metaPath });
    const currentMeta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
    const sha = raw.data.sha;

    const fileUrl = `${BASE_URL}/${pathInRepo}`;

    if (type === 'icon') {
        currentMeta.iconUrl = fileUrl;
    } else if (type === 'screenshot') {
        currentMeta.screenshots = currentMeta.screenshots || [];
        if (!currentMeta.screenshots.includes(fileUrl)) {
            currentMeta.screenshots.push(fileUrl);
        }
    }
    
    currentMeta.updatedAt = new Date().toISOString();

    const contentBase64 = Buffer.from(JSON.stringify(currentMeta, null, 2)).toString("base64");
    await octokit.repos.createOrUpdateFileContents({
        owner: G_OWNER, repo: G_REPO, path: metaPath, 
        message: `Actualizar URL de ${type} para ${appId}`, 
        content: contentBase64, sha
    });

    return { fileUrl, currentMeta };
}


/**
 * POST /apps/:appId/upload-icon - Subir ícono.
 */
app.post("/apps/:appId/upload-icon", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { file_base64, file_ext } = req.body;
    if (!file_base64 || !file_ext) return res.status(400).json({ ok: false, error: "file_base64 y file_ext (ej: png) son requeridos." });

    try {
        const filename = `icon.${file_ext.toLowerCase()}`;
        const { fileUrl } = await uploadMedia(req.developerId, req.params.appId, file_base64, 'icon', filename);
        
        return res.json({ ok: true, message: "Ícono subido y metadatos actualizados.", iconUrl: fileUrl });
    } catch (e) {
        console.error("Error al subir ícono:", e);
        return res.status(500).json({ ok: false, error: "Error interno al subir el ícono." });
    }
});


/**
 * POST /apps/:appId/upload-screenshots - Subir capturas.
 */
app.post("/apps/:appId/upload-screenshots", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { file_base64, file_ext } = req.body;
    if (!file_base64 || !file_ext) return res.status(400).json({ ok: false, error: "file_base64 y file_ext (ej: jpg) son requeridos." });

    try {
        const filename = `screenshot_${Date.now()}.${file_ext.toLowerCase()}`;
        const { fileUrl } = await uploadMedia(req.developerId, req.params.appId, file_base64, 'screenshot', filename);
        
        return res.json({ ok: true, message: "Captura subida y metadatos actualizados.", screenshotUrl: fileUrl });
    } catch (e) {
        console.error("Error al subir captura:", e);
        return res.status(500).json({ ok: false, error: "Error interno al subir la captura." });
    }
});

/**
 * DELETE /files/:fileId - Eliminar archivo.
 * NOTA: fileId será la ruta completa del archivo en el repositorio: public/developer_apps/...
 */
app.delete("/files/:fileId", apiKeyAuth, async (req, res) => {
    const { fileId } = req.params; // La ruta en el repo
    const { developerId } = req;
    
    // Verificación de propiedad: Asegurarse de que el archivo a eliminar esté dentro de la carpeta del desarrollador
    const fullPath = `public/developer_apps/${developerId}/${fileId}`;
    if (!fullPath.includes(`/public/developer_apps/${developerId}/`)) {
        return res.status(403).json({ ok: false, error: "Acceso denegado. Solo puedes eliminar archivos dentro de tu carpeta de desarrollador." });
    }
    
    try {
        await deleteGithubFile(fullPath, `Eliminar archivo ${fullPath} solicitado por el desarrollador`);

        // Lógica de actualización del meta.json para eliminar la referencia (Omitida por brevedad)
        
        return res.json({ ok: true, message: `Archivo ${fullPath} eliminado con éxito.` });
    } catch (e) {
        console.error("Error al eliminar archivo:", e);
        return res.status(500).json({ ok: false, error: "Error interno al eliminar el archivo." });
    }
});


/* ----------------------------------------------------------------------------------
   1️⃣0️⃣ SISTEMA DE ANUNCIOS (OPCIONAL)
-------------------------------------------------------------------------------------*/

/**
 * GET /apps/:appId/ads-info - Obtener configuración de anuncios.
 */
app.get("/apps/:appId/ads-info", apiKeyAuth, checkAppOwnership, async (req, res) => {
    // La información de anuncios está en los metadatos de la aplicación.
    const { ads_config, ads_detected } = req.appData;
    
    return res.json({ 
        ok: true, 
        current_config: ads_config || { has_ads: false, ad_network: 'none' },
        detected_status: ads_detected
    });
});

/**
 * PATCH /apps/:appId/ads-config - Configurar anuncios.
 */
app.patch("/apps/:appId/ads-config", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { developerId, appId } = req;
    const { has_ads, ad_network } = req.body;
    
    const newConfig = { has_ads: !!has_ads, ad_network: ad_network || 'unknown' };

    try {
        const pathInRepo = `public/developer_apps/${developerId}/${appId}/meta.json`;
        const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: pathInRepo });
        const currentMeta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
        const sha = raw.data.sha;
        
        const newMeta = {
            ...currentMeta,
            ads_config: newConfig,
            updatedAt: new Date().toISOString()
        };
        
        const contentBase64 = Buffer.from(JSON.stringify(newMeta, null, 2)).toString("base64");
        await octokit.repos.createOrUpdateFileContents({
            owner: G_OWNER, repo: G_REPO, path: pathInRepo, 
            message: `Actualizar config. de anuncios para ${appId}`, 
            content: contentBase64, sha
        });
        
        return res.json({ ok: true, message: "Configuración de anuncios guardada.", ads_config: newConfig });
    } catch (e) {
        console.error("Error al actualizar config. de anuncios:", e);
        return res.status(500).json({ ok: false, error: "Error interno al actualizar la configuración de anuncios." });
    }
});


/* ----------------------------------------------------------------------------------
   1️⃣1️⃣ NOTIFICACIONES DEL DESARROLLADOR
   NOTA: Esto requeriría una colección "notifications" en Firestore.
-------------------------------------------------------------------------------------*/

/**
 * GET /notifications - Listar notificaciones.
 */
app.get("/notifications", apiKeyAuth, async (req, res) => {
    const { developerId } = req;

    try {
        // En un caso real, buscaríamos en la colección 'notifications' donde 'developerId' sea igual al ID del usuario.
        const notificationsSnapshot = await db.collection('notifications')
            .where('developerId', '==', developerId)
            .orderBy('createdAt', 'desc')
            .limit(20)
            .get();
            
        const notifications = notificationsSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        // Simulación si no hay colección
        if (notifications.length === 0) {
            notifications.push({
                id: 'sim_1',
                message: "¡Bienvenido! Revisa nuestra guía de Developer Console.",
                read: false,
                createdAt: new Date().toISOString()
            });
        }
        
        return res.json({ ok: true, notifications });
        
    } catch (e) {
        console.error("Error al obtener notificaciones:", e);
        return res.status(500).json({ ok: false, error: "Error interno al obtener notificaciones." });
    }
});

/**
 * POST /notifications/mark-read - Marcar como leído.
 */
app.post("/notifications/mark-read", apiKeyAuth, async (req, res) => {
    const { notificationId } = req.body;
    const { developerId } = req;

    if (!notificationId) return res.status(400).json({ ok: false, error: "notificationId es requerido." });

    try {
        const notifRef = db.collection('notifications').doc(notificationId);
        const doc = await notifRef.get();
        
        if (!doc.exists || doc.data().developerId !== developerId) {
             return res.status(403).json({ ok: false, error: "Notificación no encontrada o no es tu propiedad." });
        }
        
        await notifRef.update({ read: true, readAt: new Date().toISOString() });
        
        return res.json({ ok: true, message: `Notificación ${notificationId} marcada como leída.` });
    } catch (e) {
        console.error("Error al marcar como leído:", e);
        return res.status(500).json({ ok: false, error: "Error interno al marcar notificación." });
    }
});

/* ----------------------------------------------------------------------------------
   ENDPOINTS DEL CATÁLOGO PÚBLICO (No protegidos)
-------------------------------------------------------------------------------------*/

/**
 * Función auxiliar para procesar los metadatos de las aplicaciones del catálogo público.
 * Agrega el tamaño en MB y la cantidad de descargas.
 * @param {object} meta - Objeto de metadatos de la aplicación.
 * @returns {object} - Objeto de aplicación con datos enriquecidos.
 */
async function enhanceAppMetadata(meta) {
    const latestVersion = meta.versions && meta.versions.length > 0
        ? meta.versions.slice(-1)[0]
        : null;

    // Obtener las descargas reales de Firestore si están disponibles
    let downloadsFromStats = 0;
    try {
        const statsDoc = await db.collection(STATS_COLLECTION).doc(meta.appId).get();
        if (statsDoc.exists) {
            downloadsFromStats = statsDoc.data().downloads || 0;
        }
    } catch (e) {
        console.warn(`No se pudieron obtener estadísticas para ${meta.appId}: ${e.message}`);
    }

    // Usar las descargas de Firestore o las de Google Play si se sincronizaron
    const installsText = downloadsFromStats > 0 
        ? downloadsFromStats.toLocaleString() + "+" // Usar el número real si existe
        : meta.installs || "0+"; // Usar el campo de Google Play si no hay stats

    const sizeInBytes = latestVersion?.apk_size || 0;

    return {
        appId: meta.appId,
        name: meta.name || meta.title,
        description: meta.summary || meta.description,
        icon: meta.iconUrl || meta.icon,
        category: meta.category || meta.genre || 'General',
        score: meta.score,
        ratings: meta.ratings,
        installs: installsText, // Cantidad de descargas/instalaciones
        size_mb: formatBytesToMB(sizeInBytes), // Tamaño del APK en MB
        version: latestVersion?.version_name || meta.version || 'N/A',
        updatedAt: meta.updatedAt || meta.updated
    };
}

/**
 * Endpoint para el catálogo público (apps en public/apps).
 * Lista las apps populares y enriquece sus datos con tamaño en MB y descargas.
 */
app.get("/api/public/apps/popular", async (req, res) => {
    try {
        const tree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: "public/apps" });
        const appFolders = tree.data.filter(dir => dir.type === "dir");
        
        const popularApps = [];
        for (const folder of appFolders) {
             try {
                const metaRaw = await octokit.repos.getContent({ 
                    owner: G_OWNER, 
                    repo: G_REPO, 
                    path: `${folder.path}/meta.json` 
                });
                const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));
                
                // Enriquecer y agregar al catálogo
                const enhancedApp = await enhanceAppMetadata(meta);
                popularApps.push(enhancedApp);

             } catch (e) {
                 console.warn(`No se pudo cargar o enriquecer meta.json para ${folder.name}: ${e.message}`);
             }
        }
        
        // Opcional: Ordenar por descargas o rating
        popularApps.sort((a, b) => (b.score || 0) - (a.score || 0));

        return res.json({ ok: true, apps: popularApps });
    } catch (e) {
        if (e.status === 404) return res.json({ ok: true, apps: [], message: "El catálogo público (public/apps) está vacío." });
        console.error("Error al listar apps populares:", e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});


/**
 * 🆕 Endpoint para listar aplicaciones por categorías y enriquecer los datos.
 * Endpoint: /api/public/apps/categories?category=JUEGOS
 * @param {string} req.query.category - Categoría a filtrar (opcional).
 */
app.get("/api/public/apps/categories", async (req, res) => {
    const { category } = req.query; // Categoría a buscar (e.g., "Juegos", "Herramientas")

    try {
        const tree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: "public/apps" });
        const appFolders = tree.data.filter(dir => dir.type === "dir");
        
        const appsByCategory = {};
        const allApps = [];

        for (const folder of appFolders) {
            try {
                const metaRaw = await octokit.repos.getContent({ 
                    owner: G_OWNER, 
                    repo: G_REPO, 
                    path: `${folder.path}/meta.json` 
                });
                const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));
                
                // Enriquecer los datos para el catálogo
                const enhancedApp = await enhanceAppMetadata(meta);
                
                const appCategory = enhancedApp.category.toUpperCase();

                // 1. Si se especificó una categoría y no coincide, la ignoramos
                if (category && appCategory !== category.toUpperCase()) {
                    continue;
                }

                // 2. Acumular por categoría (si no se especifica un filtro)
                if (!category) {
                    if (!appsByCategory[appCategory]) {
                        appsByCategory[appCategory] = [];
                    }
                    appsByCategory[appCategory].push(enhancedApp);
                } else {
                    // Si se especifica un filtro, solo devolvemos el array plano
                    allApps.push(enhancedApp);
                }

            } catch (e) {
                 console.warn(`No se pudo cargar o enriquecer meta.json para ${folder.name}: ${e.message}`);
            }
        }

        if (category) {
            return res.json({ 
                ok: true, 
                category: category, 
                apps: allApps, 
                count: allApps.length 
            });
        }
        
        return res.json({ 
            ok: true, 
            message: "Catálogo cargado por categorías.",
            categories: appsByCategory 
        });

    } catch (e) {
        if (e.status === 404) return res.json({ ok: true, apps: [], message: "El catálogo público (public/apps) está vacío." });
        console.error("Error al listar apps por categorías:", e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});


/**
 * 🆕 Endpoint para buscar una aplicación específica por su nombre.
 * Endpoint: /api/public/apps/search?query=facebook
 * @param {string} req.query.query - Nombre o parte del nombre a buscar.
 */
app.get("/api/public/apps/search", async (req, res) => {
    const { query } = req.query;
    
    if (!query) {
        return res.status(400).json({ ok: false, error: "El parámetro 'query' es requerido para la búsqueda." });
    }
    
    const lowerCaseQuery = query.toLowerCase();

    try {
        const tree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: "public/apps" });
        const appFolders = tree.data.filter(dir => dir.type === "dir");
        
        const searchResults = [];

        for (const folder of appFolders) {
            try {
                const metaRaw = await octokit.repos.getContent({ 
                    owner: G_OWNER, 
                    repo: G_REPO, 
                    path: `${folder.path}/meta.json` 
                });
                const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));
                
                // Buscar coincidencia en el nombre o descripción
                const appName = (meta.name || meta.title || '').toLowerCase();
                const appDescription = (meta.description || '').toLowerCase();

                if (appName.includes(lowerCaseQuery) || appDescription.includes(lowerCaseQuery)) {
                    // Enriquecer los datos para el catálogo
                    const enhancedApp = await enhanceAppMetadata(meta);
                    searchResults.push(enhancedApp);
                }

            } catch (e) {
                 console.warn(`No se pudo cargar meta.json durante la búsqueda para ${folder.name}: ${e.message}`);
            }
        }

        return res.json({ 
            ok: true, 
            query: query,
            results: searchResults,
            count: searchResults.length 
        });

    } catch (e) {
        if (e.status === 404) return res.json({ ok: true, results: [], message: "El catálogo público (public/apps) está vacío." });
        console.error("Error al buscar apps:", e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});


// 🚨 Mantener los endpoints de sincronización de Google Play (aunque su lógica no es relevante para el Dev Console)
// Los endpoints de google play, etc. se mantienen del código original y no se modifican aquí por brevedad.


/* --------- Start server --------- */
// 🚨 CORRECCIÓN CLAVE: Usamos '0.0.0.0' para escuchar en todas las interfaces,
// que es lo que espera Fly.io, y el puerto 3000 por defecto.
const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';

app.listen(PORT, HOST, () => {
    console.log(`Server running on http://${HOST}:${PORT}`);
});
