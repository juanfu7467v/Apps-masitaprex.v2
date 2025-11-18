import express from "express";
import dotenv from "dotenv";
import * as admin from 'firebase-admin'; // 🚨 IMPORTADO EL SDK ADMIN
import crypto from 'crypto'; 
import { Octokit } from "@octokit/rest";
import axios from "axios";
import https from "https"; 
import url from 'url';
import cors from "cors";
import gplay from "google-play-scraper"; // Mantener por si se usa en funciones futuras

// Cargar variables de entorno
dotenv.config();

// -------------------- CONSTANTES DE LA API DE CONSULTAS (Tus URLs) --------------------
const NEW_API_V1_BASE_URL = process.env.NEW_API_V1_BASE_URL || "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
const NEW_IMAGEN_V2_BASE_URL = process.env.NEW_IMAGEN_V2_BASE_URL || "https://imagen-v2.fly.dev";
const NEW_PDF_V3_BASE_URL = process.env.NEW_PDF_V3_BASE_URL || "https://generar-pdf-v3.fly.dev";
const NEW_FACTILIZA_BASE_URL = process.env.NEW_FACTILIZA_BASE_URL || "https://web-production-75681.up.railway.app";
const LOG_GUARDADO_BASE_URL = process.env.LOG_GUARDADO_BASE_URL || "https://base-datos-consulta-pe.fly.dev/guardar";
const NEW_BRANDING = "developer consulta pe";

// --- CLAVE SECRETA DE ADMINISTRADOR ---
const ADMIN_API_KEY = process.env.ADMIN_API_KEY;
if (!ADMIN_API_KEY) {
  console.error("FATAL ERROR: ADMIN_API_KEY no está definida en el entorno. Acceso al panel deshabilitado.");
}


/* ----------------------------------------------------------------------------------
   FIREBASE ADMIN SDK
-------------------------------------------------------------------------------------*/

// Obtener el JSON del service account
const SERVICE_ACCOUNT_JSON = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;

// 🛑 VERIFICACIÓN CRÍTICA
if (!SERVICE_ACCOUNT_JSON && !admin.apps.length) {
    // Si no está el JSON, intenta usar la configuración por defecto de tu código anterior (si las vars están en el entorno)
    const serviceAccount = {
        type: process.env.FIREBASE_TYPE,
        project_id: process.env.FIREBASE_PROJECT_ID,
        private_key_id: process.env.FIREBASE_PRIVATE_KEY_ID,
        private_key: process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, "\n"),
        client_email: process.env.FIREBASE_CLIENT_EMAIL,
        client_id: process.env.FIREBASE_CLIENT_ID,
        auth_uri: process.env.FIREBASE_AUTH_URI,
        token_uri: process.env.FIREBASE_TOKEN_URI,
        auth_provider_x509_cert_url: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
        client_x509_cert_url: process.env.FIREBASE_CLIENT_X509_CERT_URL,
        universe_domain: process.env.FIREBASE_UNIVERSE_DOMAIN,
    };
    
    if (serviceAccount.project_id && serviceAccount.private_key) {
         if (!admin.apps.length) {
            admin.initializeApp({
                credential: admin.credential.cert(serviceAccount),
            });
            console.log("✅ Firebase Admin SDK inicializado con variables separadas.");
         }
    } else {
         console.error("FATAL: La variable de entorno FIREBASE_SERVICE_ACCOUNT_JSON o las variables separadas no están configuradas.");
         // process.exit(1); // No salimos, solo registramos el error para que la app pueda iniciar
    }
} else if (SERVICE_ACCOUNT_JSON) {
    try {
        const serviceAccountJson = JSON.parse(SERVICE_ACCOUNT_JSON);
        if (!admin.apps.length) {
            admin.initializeApp({
                credential: admin.credential.cert(serviceAccountJson)
            });
            console.log("✅ Firebase Admin SDK inicializado con JSON.");
        }
    } catch (e) {
        console.error("FATAL: Error al parsear FIREBASE_SERVICE_ACCOUNT_JSON. Verifique el formato JSON y el escape de caracteres.", e);
        // process.exit(1);
    }
}


// 🚨 VARIABLES DE FIREBASE ACCESIBLES GLOBALMENTE
const auth = admin.auth();
const db = admin.firestore();
const FieldValue = admin.firestore.FieldValue;


/* ----------------------------------------------------------------------------------
   CONSTANTES Y CONFIGURACIONES DE DEVELOPER CONSOLE
-------------------------------------------------------------------------------------*/

// Se asume que estas variables de entorno también están configuradas en Fly.io
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const G_OWNER = process.env.GITHUB_OWNER; // Ej: 'tu-usuario-github'
const G_REPO = process.env.GITHUB_REPO; // Ej: 'nombre-del-repositorio'
const VIRUSTOTAL_API_KEY = process.env.VIRUSTOTAL_API_KEY; 
const BASE_URL = process.env.BASE_URL || 'https://apps-masitaprex-v2.fly.dev'; 

// Colecciones de Firestore (Developer Console)
const USERS_COLLECTION = 'usuarios';
const APPS_COLLECTION = 'developer_apps';
const STATS_COLLECTION = 'app_stats';

// Agente HTTPS para axios
const httpsAgent = new https.Agent({ rejectUnauthorized: false });


/* ----------------------------------------------------------------------------------
   SERVIDOR EXPRESS
-------------------------------------------------------------------------------------*/

const app = express();
app.use(express.json({ limit: "10mb" }));

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
   1. HELPERS DE LA DEVELOPER CONSOLE
-------------------------------------------------------------------------------------*/

/**
 * Crea o actualiza un archivo en GitHub. (Developer Console Helper)
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
 * Elimina un archivo en GitHub. (Developer Console Helper)
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
 * Genera un ID corto único para las apps. (Developer Console Helper)
 */
function generateAppId() {
    return 'app_' + crypto.randomBytes(8).toString('hex');
}

/**
 * Convierte tamaño en bytes a MB y formatea la cadena. (Developer Console Helper)
 */
function formatBytesToMB(bytes) {
    if (bytes === 0) return '0 MB';
    const mb = bytes / (1024 * 1024);
    return mb.toFixed(1) + ' MB';
}

/**
 * Placeholder para la detección de anuncios. (Developer Console Helper)
 */
function analyzeAdsFromBinary(apkData) {
    const hasAds = apkData.length % 2 === 0; 
    return {
        ads_detected: hasAds,
        detected_sdks: hasAds ? ["admob", "unity-ads"] : []
    };
}

/**
 * Placeholder para el escaneo de VirusTotal. (Developer Console Helper)
 */
async function runVirusTotalScan(fileBuffer) {
    if (!VIRUSTOTAL_API_KEY) {
        return { status: "skipped", message: "VIRUSTOTAL_API_KEY no configurada." };
    }
    
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
        malicious: sizeInMB > 10 ? 1 : 0, 
        suspicious: 0,
        undetected: 68
    };

    return results;
}

/**
 * Función auxiliar para procesar los metadatos de las aplicaciones del catálogo público. (Developer Console Helper)
 */
async function enhanceAppMetadata(meta) {
    const latestVersion = meta.versions && meta.versions.length > 0
        ? meta.versions.slice(-1)[0]
        : null;

    let downloadsFromStats = 0;
    try {
        const statsDoc = await db.collection(STATS_COLLECTION).doc(meta.appId).get();
        if (statsDoc.exists) {
            downloadsFromStats = statsDoc.data().downloads || 0;
        }
    } catch (e) {
        console.warn(`No se pudieron obtener estadísticas para ${meta.appId}: ${e.message}`);
    }

    const installsText = downloadsFromStats > 0 
        ? downloadsFromStats.toLocaleString() + "+" 
        : meta.installs || "0+"; 

    const sizeInBytes = latestVersion?.apk_size || 0;

    return {
        appId: meta.appId,
        name: meta.name || meta.title,
        description: meta.summary || meta.description,
        icon: meta.iconUrl || meta.icon,
        category: meta.category || meta.genre || 'General',
        score: meta.score,
        ratings: meta.ratings,
        installs: installsText, 
        size_mb: formatBytesToMB(sizeInBytes), 
        version: latestVersion?.version_name || meta.version || 'N/A',
        updatedAt: meta.updatedAt || meta.updated
    };
}


/* ----------------------------------------------------------------------------------
   2. MIDDLEWARES (CONSOLA + API CONSULTAS)
-------------------------------------------------------------------------------------*/

/**
 * Middleware de Autenticación por API Key (Developer Console)
 * Verifica el token de Firebase y adjunta req.developerId (UID).
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
        
        // Adjuntamos el objeto de usuario (simplificado) para consistencia con authMiddleware
        req.user = { id: decodedToken.uid }; 

        next();
    } catch (e) {
        console.error("Error de autenticación por API Key:", e.message);
        return res.status(401).json({ ok: false, error: "API Key inválida o expirada. " + e.message });
    }
};


/**
 * Middleware de Verificación de Propiedad de App (Developer Console)
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
        
        req.appData = doc.data(); 
        next();

    } catch (e) {
        console.error("Error de verificación de propiedad:", e);
        return res.status(500).json({ ok: false, error: "Error interno al verificar la propiedad de la app." });
    }
};


/**
 * Middleware para validar el token de API del usuario y plan (API de Consultas)
 */
const authMiddleware = async (req, res, next) => {
  const token = req.headers["x-api-key"];
  if (!token) {
    return res.status(401).json({ ok: false, error: "Falta el token de API" });
  }

  try {
    const usersRef = db.collection(USERS_COLLECTION);
    const snapshot = await usersRef.where("apiKey", "==", token).get();
    if (snapshot.empty) {
      // 🛑 Intentar validar como ID Token de Firebase para la Developer Console
      try {
        const decodedToken = await auth.verifyIdToken(token);
        const userDoc = await db.collection(USERS_COLLECTION).doc(decodedToken.uid).get();
        if (userDoc.exists) {
            // El usuario existe en Firestore, pero su campo 'apiKey' es diferente al token.
            // Esto permite usar el ID Token de Firebase directamente si no se usa el campo 'apiKey'
            req.user = { id: decodedToken.uid, ...userDoc.data() };
            req.developerId = decodedToken.uid; 
            next();
            return;
        } else {
             return res.status(403).json({ ok: false, error: "Token inválido (Usuario no registrado en Firestore)." });
        }
      } catch (e) {
         return res.status(403).json({ ok: false, error: "Token inválido (No es un API Key o un ID Token válido)." });
      }
    }

    const userDoc = snapshot.docs[0];
    const userData = userDoc.data();
    const userId = userDoc.id;

    // Lógica de validación de plan (API de Consultas)
    if (userData.tipoPlan === "creditos" && (!userData.creditos || userData.creditos <= 0)) {
        return res.status(402).json({ ok: false, error: "No te quedan créditos, recarga tu plan para seguir consultando", });
    }

    if (userData.tipoPlan === "ilimitado") {
        const fechaActivacion = userData.fechaActivacion ? userData.fechaActivacion.toDate() : null;
        const duracion = userData.duracionDias || 0;
        if (fechaActivacion && duracion > 0) {
            const fechaFin = new Date(fechaActivacion);
            fechaFin.setDate(fechaFin.getDate() + duracion);
            if (new Date() > fechaFin) {
                 return res.status(403).json({ ok: false, error: "Sorpresa, tu plan ilimitado ha vencido, renueva tu plan para seguir consultando", });
            }
        } else {
             return res.status(403).json({ ok: false, error: "Tu plan ilimitado no es válido, por favor contacta soporte", });
        }
    }

    req.user = { id: userId, ...userData };
    req.developerId = userId; // También seteamos el developerId
    next();
  } catch (error) {
    console.error("Error en authMiddleware:", error);
    res.status(500).json({ ok: false, error: "Error interno al validar el token" });
  }
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
 * Middleware para gestionar créditos y actualizar la última consulta y el dominio de origen. (API de Consultas)
 */
const creditosMiddleware = (costo) => {
  return async (req, res, next) => {
    // Si no está el user, es un endpoint de la Developer Console que usa apiKeyAuth, no debitamos.
    if (!req.user || !req.user.id) {
        req.logData = { domain: getOriginDomain(req), cost: 0, endpoint: req.path };
        next();
        return;
    }

    const domain = getOriginDomain(req);
    const userRef = db.collection(USERS_COLLECTION).doc(req.user.id);
    const currentTime = new Date();

    if (req.user.tipoPlan === "creditos") {
      if (req.user.creditos < costo) {
        return res.status(402).json({
          ok: false,
          error: "Créditos insuficientes, recarga tu plan",
        });
      }
      await userRef.update({
        creditos: admin.firestore.FieldValue.increment(-costo),
        ultimaConsulta: currentTime, 
        ultimoDominio: domain,        
      });
      req.user.creditos -= costo;
    } else if (req.user.tipoPlan === "ilimitado") {
        await userRef.update({
            ultimaConsulta: currentTime,
            ultimoDominio: domain,
        });
    }

    req.logData = {
        domain: domain,
        cost: costo,
        endpoint: req.path,
    };
    
    next();
  };
};

/**
 * Middleware de Autenticación de Administrador (Panel de Admin)
 */
const adminAuthMiddleware = (req, res, next) => {
    if (!ADMIN_API_KEY) {
         return res.status(503).json({ ok: false, error: "Servicio de administración no disponible: Clave de entorno no cargada." });
    }
    
    const adminKey = req.headers["x-admin-key"];
    if (adminKey === ADMIN_API_KEY) {
        next();
    } else {
        res.status(401).json({ ok: false, error: "Clave de administrador Inválida. Acceso no autorizado." });
    }
};


/* ----------------------------------------------------------------------------------
   3. HELPERS DE API DE CONSULTAS
-------------------------------------------------------------------------------------*/

/**
 * Guarda el log en la API externa. (API de Consultas Helper)
 */
const guardarLogExterno = async (logData) => {
    const horaConsulta = new Date(logData.timestamp).toISOString();
    const url = `${LOG_GUARDADO_BASE_URL}/log_consulta?host=${encodeURIComponent(logData.domain)}&hora=${encodeURIComponent(horaConsulta)}&endpoint=${encodeURIComponent(logData.endpoint)}&userId=${encodeURIComponent(logData.userId)}&costo=${logData.cost}`;
    
    try {
        await axios.get(url);
    } catch (e) {
        console.error("Error al guardar log en API externa:", e.message);
    }
};


const replaceBranding = (data) => {
  if (typeof data === 'string') {
    return data.replace(/@LEDERDATA_OFC_BOT|@otra|\[FACTILIZA]/g, NEW_BRANDING);
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
const transformarRespuestaBusqueda = (response, user) => {
  let processedResponse = procesarRespuesta(response, user);

  if (processedResponse.message && typeof processedResponse.message === 'string') {
    processedResponse.message = processedResponse.message.replace(/\s*↞ Puedes visualizar la foto de una coincidencia antes de usar \/dni ↠\s*/, '').trim();
  }

  return processedResponse;
};


/**
 * Procesa la respuesta de la API externa para aplicar branding y limpiar campos.
 */
const procesarRespuesta = (response, user) => {
  let processedResponse = replaceBranding(response);

  delete processedResponse["developed-by"];
  delete processedResponse["credits"];

  const userPlan = {
    tipo: user.tipoPlan,
    creditosRestantes: user.tipoPlan === "creditos" ? user.creditos : null,
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

  if (processedResponse.ok === false && processedResponse.details) {
    if (processedResponse.details.message?.includes("Token con falta de pago")) {
      processedResponse.details.message = "Error en la consulta, intenta nuevamente";
    }
    if (processedResponse.details.detalle?.message?.includes("Token con falta de pago")) {
      processedResponse.details.detalle.message = "Error en la consulta, intenta nuevamente";
    }
    delete processedResponse.details.detalle?.plan;
  }

  return processedResponse;
};


/**
 * Función genérica para consumir API, procesar la respuesta y AHORA GUARDAR EL LOG EXTERNO.
 */
const consumirAPI = async (req, res, url, transformer = procesarRespuesta) => {
  try {
    const response = await axios.get(url);
    const processedResponse = transformer(response.data, req.user);

    if (response.status >= 200 && response.status < 300) {
        const logData = {
            userId: req.user.id,
            timestamp: new Date(),
            ...req.logData,
        };
        guardarLogExterno(logData);
    }
    
    res.json(processedResponse);
  } catch (error) {
    console.error("Error al consumir API:", error.message);
    const errorResponse = {
      ok: false,
      error: "Error en API externa",
      details: error.response ? error.response.data : error.message,
    };
    
    const processedErrorResponse = procesarRespuesta(errorResponse, req.user);
    res.status(error.response ? error.response.status : 500).json(processedErrorResponse);
  }
};

/* ----------------------------------------------------------------------------------
   4. ENDPOINTS: GESTIÓN DE APPS (DEVELOPER CONSOLE)
-------------------------------------------------------------------------------------*/

/**
 * 1️⃣ AUTENTICACIÓN Y VERIFICACIÓN (FIREBASE)
 * Estos endpoints usan la lógica de la Developer Console para la gestión de usuarios.
 */

app.post("/auth/register", async (req, res) => {
    const { email, password, displayName } = req.body;
    if (!email || !password) return res.status(400).json({ ok: false, error: "Email y password son requeridos." });

    try {
        const user = await auth.createUser({ email, password, displayName });
        await db.collection(USERS_COLLECTION).doc(user.uid).set({
            email: user.email,
            displayName: user.displayName,
            registeredAt: new Date().toISOString(),
            // Se mantiene la estructura de plan para compatibilidad con authMiddleware de API de Consultas
            tipoPlan: 'none', 
            creditos: 0,
            fechaCreacion: new Date(),
        });
        return res.json({ ok: true, message: "Usuario registrado con éxito.", uid: user.uid });
    } catch (e) {
        return res.status(400).json({ ok: false, error: e.message });
    }
});

app.post("/auth/login", async (req, res) => {
    // Esto sigue siendo un PLACEHOLDER. El ID Token final debe obtenerse en el CLIENTE.
    const { uid } = req.body; 
    if (!uid) return res.status(400).json({ ok: false, error: "Para este placeholder, debe proveer su UID." });

    try {
        const customToken = await auth.createCustomToken(uid);
        return res.json({ 
            ok: true, 
            message: "Token generado con éxito.", 
            uid,
            placeholder_custom_token: customToken, 
            placeholder_api_key_instruction: "Usar el ID Token generado por el cliente Firebase tras un login exitoso."
        });

    } catch (e) {
        return res.status(401).json({ ok: false, error: "Login fallido. " + e.message });
    }
});


/**
 * 2️⃣ APLICACIONES (CRUD PRINCIPAL)
 */

app.post("/apps/create", apiKeyAuth, async (req, res) => {
    const { name, description, category } = req.body;
    const { developerId } = req;
    
    if (!name || !description) return res.status(400).json({ ok: false, error: "Nombre y descripción son requeridos." });

    const appId = generateAppId();
    const currentTimestamp = new Date().toISOString();
    
    try {
        const appMetadata = {
            appId, developerId, name, description, category: category || 'General',
            status: 'draft', createdAt: currentTimestamp, updatedAt: currentTimestamp, versions: []
        };
        
        await db.collection(APPS_COLLECTION).doc(appId).set({
            appId, developerId, name, status: 'draft', createdAt: currentTimestamp, updatedAt: currentTimestamp
        });

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

app.patch("/apps/:appId/update", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { developerId, appId } = req;
    const updates = req.body;
    
    delete updates.appId; delete updates.developerId; delete updates.createdAt; delete updates.versions;
    
    try {
        const pathInRepo = `public/developer_apps/${developerId}/${appId}/meta.json`;
        
        const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: pathInRepo });
        const currentMeta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
        const sha = raw.data.sha;
        
        const newMeta = {
            ...currentMeta,
            ...updates,
            updatedAt: new Date().toISOString()
        };
        
        const contentBase64 = Buffer.from(JSON.stringify(newMeta, null, 2)).toString("base64");
        await octokit.repos.createOrUpdateFileContents({
            owner: G_OWNER, repo: G_REPO, path: pathInRepo, 
            message: `Actualizar app ${appId}: ${Object.keys(updates).join(', ')}`, 
            content: contentBase64, sha
        });

        if (updates.name) {
            await db.collection(APPS_COLLECTION).doc(appId).update({ name: updates.name, updatedAt: newMeta.updatedAt });
        }
        
        return res.json({ ok: true, message: "Aplicación actualizada con éxito.", app: newMeta });

    } catch (e) {
        console.error("Error al actualizar app:", e);
        return res.status(500).json({ ok: false, error: "Error interno al actualizar la aplicación." });
    }
});

app.delete("/apps/:appId", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { developerId, appId } = req;

    try {
        const pathInRepo = `public/developer_apps/${developerId}/${appId}/meta.json`;
        
        const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: pathInRepo });
        const currentMeta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
        const sha = raw.data.sha;
        
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
        
        await db.collection(APPS_COLLECTION).doc(appId).delete();

        return res.json({ ok: true, message: `Aplicación ${appId} marcada como eliminada/despublicada.`, status: newMeta.status });

    } catch (e) {
        console.error("Error al eliminar app:", e);
        return res.status(500).json({ ok: false, error: "Error interno al eliminar la aplicación." });
    }
});


/**
 * 3️⃣ SUBIR APK (CON ANÁLISIS AUTOMÁTICO) Y ENLACES
 */

app.post("/apps/:appId/upload-apk", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { developerId, appId } = req;
    const { apk_base64, version } = req.body; 
    
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
            status: "uploaded", apk_size: apkSize, ...adAnalysis, virus_scan: vtScan.scan_status,
            virustotal_report: vtScan, message: "APK subido y metadatos actualizados."
        });

    } catch (e) {
        console.error("Error al subir APK:", e);
        return res.status(500).json({ ok: false, error: "Error interno al subir el APK.", details: e.message });
    }
});

app.post("/apps/:appId/upload-url", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { developerId, appId } = req;
    const { apk_url, version } = req.body;

    if (!apk_url || !version) return res.status(400).json({ ok: false, error: "apk_url y version son requeridos." });

    try {
        const head = await axios.head(apk_url, { maxRedirects: 5, httpsAgent });
        const apkSize = parseInt(head.headers['content-length'], 10) || 0;
        
        let vtScan = { scan_status: "limited_or_skipped", message: "Escaneo por URL no disponible en esta simulación." };
        let adAnalysis = { ads_detected: null, detected_sdks: [] };
        
        if (apkSize > 0 && apkSize / (1024 * 1024) <= 80) { 
             adAnalysis = { ads_detected: true, detected_sdks: ["admob"] };
             if (apkSize / (1024 * 1024) <= 32) {
                vtScan = { scan_status: "completed", malicious: 0, suspicious: 0, undetected: 68 };
             }
        }
        
        const metaPath = `public/developer_apps/${developerId}/${appId}/meta.json`;
        const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: metaPath });
        const currentMeta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
        const sha = raw.data.sha;

        const versionData = {
            version_name: version, apk_size: apkSize, apk_url: apk_url, upload_type: 'external_url',
            uploadedAt: new Date().toISOString(), ads_detected: adAnalysis.ads_detected,
            ads_sdks: adAnalysis.detected_sdks, virustotal_report: vtScan
        };
        
        currentMeta.versions.push(versionData);

        const contentBase64 = Buffer.from(JSON.stringify(currentMeta, null, 2)).toString("base64");
        await octokit.repos.createOrUpdateFileContents({
            owner: G_OWNER, repo: G_REPO, path: metaPath, 
            message: `Añadir versión ${version} (URL externa) para ${appId}`, 
            content: contentBase64, sha
        });

        return res.json({
            status: "linked", apk_size: apkSize, ...adAnalysis, virus_scan: vtScan.scan_status,
            message: "Enlace de APK guardado y metadatos actualizados (análisis limitado)."
        });

    } catch (e) {
        console.error("Error al subir URL de APK:", e);
        return res.status(500).json({ ok: false, error: "Error al procesar la URL del APK.", details: e.message });
    }
});

app.post("/apps/:appId/check-ads", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const latestVersion = req.appData.versions?.slice(-1)[0];
    if (!latestVersion || !latestVersion.apk_size) {
         return res.status(400).json({ ok: false, error: "No hay una versión con un APK subido para analizar." });
    }
    const analysis = analyzeAdsFromBinary({ length: latestVersion.apk_size });
    return res.json({
        ok: true, ads_detected: analysis.ads_detected, detected_sdks: analysis.detected_sdks,
        message: "Análisis de anuncios completado con simulación."
    });
});

app.post("/apps/:appId/virus-scan", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const latestVersion = req.appData.versions?.slice(-1)[0];

    if (!latestVersion || !latestVersion.apk_size || !latestVersion.apk_path) {
         return res.status(400).json({ ok: false, error: "No hay una versión con un APK subido para escanear." });
    }
    
    if (latestVersion.apk_size / (1024 * 1024) > 32) {
         return res.json({ 
            scan_status: "skipped", message: "El archivo es demasiado grande ( > 32MB) para la API gratuita de VirusTotal.", 
            malicious: 0, suspicious: 0, undetected: 0 
        });
    }

    const vtScan = await runVirusTotalScan(Buffer.alloc(latestVersion.apk_size)); 

    return res.json({
        ok: true, scan_status: vtScan.scan_status, malicious: vtScan.malicious,
        suspicious: vtScan.suspicious, undetected: vtScan.undetected,
        message: "Escaneo de VirusTotal completado con simulación."
    });
});


/**
 * 4️⃣ GESTIÓN DE VERSIONES
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

app.get("/apps/:appId/versions", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const versions = req.appData.versions || [];
    return res.json({ ok: true, versions: versions.map(v => ({ name: v.version_name, uploadedAt: v.uploadedAt, size: v.apk_size })) });
});

app.get("/apps/:appId/latest", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const versions = req.appData.versions || [];
    if (versions.length === 0) {
        return res.status(404).json({ ok: false, error: "No se encontraron versiones para esta aplicación." });
    }
    const latest = versions.slice(-1)[0]; 
    return res.json({ ok: true, latest_version: latest });
});

/**
 * 5️⃣ ESTADÍSTICAS (REPORTES PÚBLICOS Y PRIVADOS)
 */

app.post("/stats/report-download", async (req, res) => {
    const { appId, country, device } = req.body;
    if (!appId) return res.status(400).json({ ok: false, error: "appId es requerido." });

    try {
        const statsRef = db.collection(STATS_COLLECTION).doc(appId);
        const updateData = {
            downloads: FieldValue.increment(1),
            today: FieldValue.increment(1), 
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

app.get("/apps/:appId/stats", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { appId } = req.params;

    try {
        const statsDoc = await db.collection(STATS_COLLECTION).doc(appId).get();
        if (!statsDoc.exists) {
            return res.json({ 
                ok: true, downloads: 0, installs: 0, uninstalls: 0, today: 0, countries: {}, versions: {} 
            });
        }
        
        const stats = statsDoc.data();
        
        return res.json({
            ok: true,
            downloads: stats.downloads || 0, installs: stats.installs || 0, uninstalls: stats.uninstalls || 0,
            today: stats.today || 0, countries: stats.countries || {}, versions: stats.versions || {},
            updatedAt: stats.updatedAt
        });
        
    } catch (e) {
        console.error("Error al obtener estadísticas:", e);
        return res.status(500).json({ ok: false, error: "Error interno al obtener las estadísticas." });
    }
});


/**
 * 6️⃣ RECURSOS MULTIMEDIA (IMÁGENES, VIDEOS)
 */

async function uploadMedia(developerId, appId, fileBase64, type, filename) {
    const pathInRepo = `public/developer_apps/${developerId}/${appId}/media/${filename}`;
    
    await createOrUpdateGithubFile(pathInRepo, fileBase64, `Subir ${type} para ${appId}`);

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

app.delete("/files/:fileId", apiKeyAuth, async (req, res) => {
    const { fileId } = req.params; 
    const { developerId } = req;
    
    const fullPath = `public/developer_apps/${developerId}/${fileId}`;
    if (!fullPath.includes(`/public/developer_apps/${developerId}/`)) {
        return res.status(403).json({ ok: false, error: "Acceso denegado. Solo puedes eliminar archivos dentro de tu carpeta de desarrollador." });
    }
    
    try {
        await deleteGithubFile(fullPath, `Eliminar archivo ${fullPath} solicitado por el desarrollador`);
        
        // NOTA: La lógica de actualizar el meta.json para remover la referencia se omite por brevedad.
        
        return res.json({ ok: true, message: `Archivo ${fullPath} eliminado con éxito.` });
    } catch (e) {
        console.error("Error al eliminar archivo:", e);
        return res.status(500).json({ ok: false, error: "Error interno al eliminar el archivo." });
    }
});


/**
 * 7️⃣ GESTIÓN DE ANUNCIOS
 */

app.get("/apps/:appId/ads-info", apiKeyAuth, checkAppOwnership, async (req, res) => {
    const { ads_config, ads_detected } = req.appData;
    
    return res.json({ 
        ok: true, 
        current_config: ads_config || { has_ads: false, ad_network: 'none' },
        detected_status: ads_detected
    });
});

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


/**
 * 8️⃣ NOTIFICACIONES DEL DESARROLLADOR
 */

app.get("/notifications", apiKeyAuth, async (req, res) => {
    const { developerId } = req;

    try {
        const notificationsSnapshot = await db.collection('notifications')
            .where('developerId', '==', developerId)
            .orderBy('createdAt', 'desc')
            .limit(20)
            .get();
            
        const notifications = notificationsSnapshot.docs.map(doc => ({
            id: doc.id,
            ...doc.data()
        }));

        if (notifications.length === 0) {
            notifications.push({
                id: 'sim_1', message: "¡Bienvenido! Revisa nuestra guía de Developer Console.", read: false,
                createdAt: new Date().toISOString()
            });
        }
        
        return res.json({ ok: true, notifications });
        
    } catch (e) {
        console.error("Error al obtener notificaciones:", e);
        return res.status(500).json({ ok: false, error: "Error interno al obtener notificaciones." });
    }
});

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
   5. ENDPOINTS DEL CATÁLOGO PÚBLICO (No protegidos)
-------------------------------------------------------------------------------------*/

app.get("/api/public/apps/popular", async (req, res) => {
    try {
        const tree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: "public/apps" });
        const appFolders = tree.data.filter(dir => dir.type === "dir");
        
        const popularApps = [];
        for (const folder of appFolders) {
             try {
                const metaRaw = await octokit.repos.getContent({ 
                    owner: G_OWNER, repo: G_REPO, path: `${folder.path}/meta.json` 
                });
                const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));
                
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
        const tree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: "public/apps" });
        const appFolders = tree.data.filter(dir => dir.type === "dir");
        
        const appsByCategory = {};
        const allApps = [];

        for (const folder of appFolders) {
            try {
                const metaRaw = await octokit.repos.getContent({ 
                    owner: G_OWNER, repo: G_REPO, path: `${folder.path}/meta.json` 
                });
                const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));
                
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
                    owner: G_OWNER, repo: G_REPO, path: `${folder.path}/meta.json` 
                });
                const meta = JSON.parse(Buffer.from(metaRaw.data.content, "base64").toString("utf8"));
                
                const appName = (meta.name || meta.title || '').toLowerCase();
                const appDescription = (meta.description || '').toLowerCase();

                if (appName.includes(lowerCaseQuery) || appDescription.includes(lowerCaseQuery)) {
                    const enhancedApp = await enhanceAppMetadata(meta);
                    searchResults.push(enhancedApp);
                }

            } catch (e) {
                 console.warn(`No se pudo cargar meta.json durante la búsqueda para ${folder.name}: ${e.message}`);
            }
        }

        return res.json({ 
            ok: true, query: query, results: searchResults, count: searchResults.length 
        });

    } catch (e) {
        if (e.status === 404) return res.json({ ok: true, results: [], message: "El catálogo público (public/apps) está vacío." });
        console.error("Error al buscar apps:", e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});

/* ----------------------------------------------------------------------------------
   6. ENDPOINTS: API DE CONSULTAS (Mantenidos)
-------------------------------------------------------------------------------------*/

// 🔹 API v1 (Nueva)
app.get("/api/dni", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/dni?dni=${req.query.dni}`);
});
app.get("/api/ruc", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/ruc?ruc=${req.query.ruc}`);
});
app.get("/api/ruc-anexo", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/ruc-anexo?ruc=${req.query.ruc}`);
});
app.get("/api/ruc-representante", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/ruc-representante?ruc=${req.query.ruc}`);
});
app.get("/api/cee", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/cee?cee=${req.query.cee}`);
});
app.get("/api/soat-placa", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/placa?placa=${req.query.placa}`);
});
app.get("/api/licencia", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/licencia?dni=${req.query.dni}`);
});
app.get("/api/ficha", authMiddleware, creditosMiddleware(30), async (req, res) => {
  await consumirAPI(req, res, `${NEW_IMAGEN_V2_BASE_URL}/generar-ficha?dni=${req.query.dni}`);
});
app.get("/api/reniec", authMiddleware, creditosMiddleware(10), async (req, res) => {
  const { dni } = req.query;
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/reniec?dni=${dni}`);
});
app.get("/api/denuncias-dni", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/denuncias-dni?dni=${req.query.dni}`);
});
app.get("/api/denuncias-placa", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/denuncias-placa?placa=${req.query.placa}`);
});
app.get("/api/sueldos", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/sueldos?dni=${req.query.dni}`);
});
app.get("/api/trabajos", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/trabajos?dni=${req.query.dni}`);
});
app.get("/api/sunat", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/sunat?data=${req.query.data}`);
});
app.get("/api/sunat-razon", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/sunat-razon?data=${req.query.data}`);
});
app.get("/api/consumos", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/consumos?dni=${req.query.dni}`);
});
app.get("/api/arbol", authMiddleware, creditosMiddleware(18), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/arbol?dni=${req.query.dni}`);
});
app.get("/api/familia1", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/familia1?dni=${req.query.dni}`);
});
app.get("/api/familia2", authMiddleware, creditosMiddleware(15), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/familia2?dni=${req.query.dni}`);
});
app.get("/api/familia3", authMiddleware, creditosMiddleware(18), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/familia3?dni=${req.query.dni}`);
});
app.get("/api/movimientos", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/movimientos?dni=${req.query.dni}`);
});
app.get("/api/matrimonios", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/matrimonios?dni=${req.query.dni}`);
});
app.get("/api/empresas", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/empresas?dni=${req.query.dni}`);
});
app.get("/api/direcciones", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/direcciones?dni=${req.query.dni}`);
});
app.get("/api/correos", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/correos?dni=${req.query.dni}`);
});
app.get("/api/telefonia-doc", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/telefonia-doc?documento=${req.query.documento}`);
});
app.get("/api/telefonia-num", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/telefonia-num?numero=${req.query.numero}`);
});
app.get("/api/vehiculos", authMiddleware, creditosMiddleware(15), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/vehiculos?placa=${req.query.placa}`);
});
app.get("/api/fiscalia-dni", authMiddleware, creditosMiddleware(15), async (req, res) => {
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/fiscalia-dni?dni=${req.query.dni}`);
});
app.get("/api/fiscalia-nombres", authMiddleware, creditosMiddleware(18), async (req, res) => {
  const { nombres, apepaterno, apematerno } = req.query;
  await consumirAPI(req, res, `${NEW_API_V1_BASE_URL}/fiscalia-nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`, transformarRespuestaBusqueda);
});
app.get("/api/info-total", authMiddleware, creditosMiddleware(50), async (req, res) => {
    await consumirAPI(req, res, `${NEW_PDF_V3_BASE_URL}/generar-ficha-pdf?dni=${req.query.dni}`);
});

// 🔹 Reemplazo de Factiliza
app.get("/api/dni-full", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dni?dni=${req.query.dni}`);
});
app.get("/api/c4", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/c4?dni=${req.query.dni}`);
});
app.get("/api/dnivaz", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dnivaz?dni=${req.query.dni}`);
});
app.get("/api/dnivam", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dnivam?dni=${req.query.dni}`);
});
app.get("/api/dnivel", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dnivel?dni=${req.query.dni}`);
});
app.get("/api/dniveln", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dniveln?dni=${req.query.dni}`);
});
app.get("/api/fa", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/fa?dni=${req.query.dni}`);
});
app.get("/api/fb", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/fb?dni=${req.query.dni}`);
});
app.get("/api/cnv", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cnv?dni=${req.query.dni}`);
});
app.get("/api/cdef", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cdef?dni=${req.query.dni}`);
});
app.get("/api/actancc", authMiddleware, creditosMiddleware(65), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/actancc?dni=${req.query.dni}`);
});
app.get("/api/actamcc", authMiddleware, creditosMiddleware(65), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/actamcc?dni=${req.query.dni}`);
});
app.get("/api/actadcc", authMiddleware, creditosMiddleware(65), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/actadcc?dni=${req.query.dni}`);
});
app.get("/api/tra", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/tra?dni=${req.query.dni}`);
});
app.get("/api/sue", authMiddleware, creditosMiddleware(8), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/sue?dni=${req.query.dni}`);
});
app.get("/api/cla", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cla?dni=${req.query.dni}`);
});
app.get("/api/sune", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/sune?dni=${req.query.dni}`);
});
app.get("/api/cun", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cun?dni=${req.query.dni}`);
});
app.get("/api/colp", authMiddleware, creditosMiddleware(6), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/colp?dni=${req.query.dni}`);
});
app.get("/api/mine", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/mine?dni=${req.query.dni}`);
});
app.get("/api/afp", authMiddleware, creditosMiddleware(6), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/afp?dni=${req.query.dni}`);
});
app.get("/api/antpen", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/antpen?dni=${req.query.dni}`);
});
app.get("/api/antpol", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/antpol?dni=${req.query.dni}`);
});
app.get("/api/antjud", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/antjud?dni=${req.query.dni}`);
});
app.get("/api/antpenv", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/antpenv?dni=${req.query.dni}`);
});
app.get("/api/dend", authMiddleware, creditosMiddleware(26), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dend?dni=${req.query.dni}`);
});
app.get("/api/fis", authMiddleware, creditosMiddleware(32), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/fis?dni=${req.query.dni}`);
});
app.get("/api/fisdet", authMiddleware, creditosMiddleware(36), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/fisdet?dni=${req.query.dni}`);
});
app.get("/api/det", authMiddleware, creditosMiddleware(26), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/det?dni=${req.query.dni}`);
});
app.get("/api/rqh", authMiddleware, creditosMiddleware(8), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/rqh?dni=${req.query.dni}`);
});
app.get("/api/meta", authMiddleware, creditosMiddleware(26), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/meta?dni=${req.query.dni}`);
});
app.get("/api/osiptel", authMiddleware, creditosMiddleware(10), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/osiptel?query=${req.query.query}`);
});
app.get("/api/claro", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/claro?query=${req.query.query}`);
});
app.get("/api/entel", authMiddleware, creditosMiddleware(5), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/entel?query=${req.query.query}`);
});
app.get("/api/pro", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/pro?query=${req.query.query}`);
});
app.get("/api/sen", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/sen?query=${req.query.query}`);
});
app.get("/api/sbs", authMiddleware, creditosMiddleware(12), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/sbs?query=${req.query.query}`);
});
app.get("/api/pasaporte", authMiddleware, creditosMiddleware(20), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/pasaporte?query=${req.query.query}`);
});
app.get("/api/seeker", authMiddleware, creditosMiddleware(28), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/seeker?query=${req.query.query}`);
});
app.get("/api/bdir", authMiddleware, creditosMiddleware(28), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/bdir?query=${req.query.query}`);
});
app.get("/api/dence", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dence?carnet_extranjeria=${req.query.carnet_extranjeria}`);
});
app.get("/api/denpas", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/denpas?pasaporte=${req.query.pasaporte}`);
});
app.get("/api/denci", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/denci?cedula_identidad=${req.query.cedula_identidad}`);
});
app.get("/api/denp", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/denp?placa=${req.query.placa}`);
});
app.get("/api/denar", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/denar?serie_armamento=${req.query.serie_armamento}`);
});
app.get("/api/dencl", authMiddleware, creditosMiddleware(25), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dencl?clave_denuncia=${req.query.clave_denuncia}`);
});
app.get("/api/cedula", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/cedula?cedula=${req.query.cedula}`);
});
app.get("/api/venezolanos_nombres", authMiddleware, creditosMiddleware(4), async (req, res) => {
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/venezolanos_nombres?query=${req.query.query}`, transformarRespuestaBusqueda);
});
app.get("/api/dni_nombres", authMiddleware, creditosMiddleware(5), async (req, res) => {
  const { nombres, apepaterno, apematerno } = req.query;
  await consumirAPI(req, res, `${NEW_FACTILIZA_BASE_URL}/dni_nombres?nombres=${nombres}&apepaterno=${apepaterno}&apematerno=${apematerno}`, transformarRespuestaBusqueda);
});

/* ----------------------------------------------------------------------------------
   7. ADMIN ENDPOINTS (Panel de Gestión de API)
-------------------------------------------------------------------------------------*/

app.get("/admin/users", adminAuthMiddleware, async (req, res) => {
    try {
        const usersRef = db.collection(USERS_COLLECTION);
        const snapshot = await usersRef.get();
        const users = snapshot.docs.map(doc => {
            const data = doc.data();
            return {
                userId: doc.id,
                email: data.email || 'N/A',
                tipoPlan: data.tipoPlan,
                creditos: data.creditos || 0,
                ultimaConsulta: data.ultimaConsulta ? data.ultimaConsulta.toDate().toISOString() : 'Nunca',
                ultimoDominio: data.ultimoDominio || 'Desconocido',
                fechaCreacion: data.fechaCreacion ? data.fechaCreacion.toDate().toISOString() : 'N/A',
            };
        });
        users.sort((a, b) => new Date(b.ultimaConsulta) - new Date(a.ultimaConsulta));

        res.json({ ok: true, users });
    } catch (error) {
        console.error("Error al obtener usuarios:", error);
        res.status(500).json({ ok: false, error: "Error interno al obtener usuarios" });
    }
});


// -------------------- RUTA RAÍZ Y ARRANQUE DEL SERVIDOR --------------------

app.get("/", (req, res) => {
  res.json({
    ok: true,
    mensaje: "🚀 API Consulta PE / Developer Console funcionando correctamente.",
    "consulta-pe": {
      poweredBy: "Consulta PE",
      info: "API oficial con endpoints actualizados y gestión de aplicaciones.",
    },
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
