import express from "express";
import dotenv from "dotenv";
import { Octokit } from "@octokit/rest";
import axios from "axios";
import https from "https"; 
import url from 'url';
import cors from "cors";
import gplay from "google-play-scraper"; // Mantener por si se usa en funciones futuras

// Cargar variables de entorno
dotenv.config();

// ==============================================================================
// 🛑 ATENCIÓN: Se eliminan todas las dependencias y la inicialización de Firebase Admin SDK (auth, db, FieldValue)
// ya que no son necesarias para el Catálogo Público o los Endpoints de Consulta (al eliminarse la autenticación).
// ==============================================================================


// -------------------- CONSTANTES DE LA API DE CONSULTAS (Tus URLs) --------------------
// Estas URLs se mantienen para los endpoints de consulta que se redirigen a otras APIs.
const NEW_API_V1_BASE_URL = process.env.NEW_API_V1_BASE_URL || "https://banckend-poxyv1-cosultape-masitaprex.fly.dev";
const NEW_IMAGEN_V2_BASE_URL = process.env.NEW_IMAGEN_V2_BASE_URL || "https://imagen-v2.fly.dev";
const NEW_PDF_V3_BASE_URL = process.env.NEW_PDF_V3_BASE_URL || "https://generar-pdf-v3.fly.dev";
const LOG_GUARDADO_BASE_URL = process.env.LOG_GUARDADO_BASE_URL || "https://base-datos-consulta-pe.fly.dev/guardar";
const NEW_BRANDING = "developer consulta pe"; // Solo un branding genérico

// --- CONFIGURACIÓN DE GITHUB (Solo para el catálogo público estático) ---
const GITHUB_TOKEN = process.env.GITHUB_TOKEN; // Puede no ser necesario si el repo es público
const G_OWNER = process.env.GITHUB_OWNER || 'tu-usuario-github'; // Reemplazar con tu usuario
const G_REPO = process.env.GITHUB_REPO || 'nombre-del-repositorio'; // Reemplazar con tu repo

// Inicializar Octokit. Si el repositorio es público, puede no necesitar el token.
const octokit = new Octokit({ auth: GITHUB_TOKEN });

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
   1. HELPERS SIMPLIFICADOS (Solo para el catálogo)
-------------------------------------------------------------------------------------*/

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
 * NOTA: La parte de búsqueda de estadísticas de Firestore se elimina.
 */
async function enhanceAppMetadata(meta) {
    // Asumiendo que el meta ya está en formato Google Play o similar
    const latestVersion = meta.version || 'N/A';
    
    // Usamos los datos de descargas directamente del JSON o un valor por defecto.
    const installsText = meta.installs || "0+"; 
    
    // Aquí asumimos que el tamaño debe calcularse o tomarse de un campo específico si no está en meta.apkPath
    const sizeInBytes = meta.apk_size || 0; // Si el JSON no tiene este campo, será 0

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


/* ----------------------------------------------------------------------------------
   2. HELPERS DE API DE CONSULTAS (SIMPLIFICADOS)
-------------------------------------------------------------------------------------*/

/**
 * Guarda el log en la API externa. (Se mantiene la funcionalidad, pero sin user.id)
 */
const guardarLogExterno = async (logData) => {
    const horaConsulta = new Date(logData.timestamp).toISOString();
    // Usamos 'public_access' como un ID de usuario genérico al eliminar la autenticación
    const url = `${LOG_GUARDADO_BASE_URL}/log_consulta?host=${encodeURIComponent(logData.domain)}&hora=${encodeURIComponent(horaConsulta)}&endpoint=${encodeURIComponent(logData.endpoint)}&userId=public_access&costo=${logData.cost}`;
    
    try {
        await axios.get(url);
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
 * 🛑 NOTA: Se ha eliminado toda la lógica de autenticación y créditos.
 */
const consumirAPI = async (req, res, url, costo, transformer = procesarRespuesta) => {
  const domain = getOriginDomain(req);
  const logData = {
    userId: "public_access", // Hardcodeado ya que no hay autenticación
    timestamp: new Date(),
    domain: domain,
    cost: costo, // El costo se sigue enviando al log externo
    endpoint: req.path,
  };
    
  try {
    const response = await axios.get(url);
    // Solo se usa el procesador de respuesta, sin enviar el objeto user
    const processedResponse = transformer(response.data); 

    if (response.status >= 200 && response.status < 300) {
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
    
    const processedErrorResponse = procesarRespuesta(errorResponse);
    res.status(error.response ? error.response.status : 500).json(processedErrorResponse);
  }
};


/* ----------------------------------------------------------------------------------
   3. ENDPOINTS DEL CATÁLOGO PÚBLICO (Mantenidos y No Protegidos)
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
        return res.redirect(307, '/api/public/apps/popular');
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
    const { appId } = req.params;

    try {
        const metaPath = `public/apps/${appId}/meta.json`;
        
        const raw = await octokit.repos.getContent({ 
            owner: G_OWNER, 
            repo: G_REPO, 
            path: metaPath 
        });
        
        const meta = JSON.parse(Buffer.from(raw.data.content, "base64").toString("utf8"));
        
        const enhancedApp = await enhanceAppMetadata(meta);
        
        if (meta.externalDownloadUrl) {
            enhancedApp.downloadUrl = meta.externalDownloadUrl;
        }

        return res.json({ ok: true, app: {...meta, ...enhancedApp} });

    } catch (e) {
        if (e.status === 404) {
            return res.status(404).json({ ok: false, error: `Aplicación con ID ${appId} no encontrada en el catálogo público.` });
        }
        console.error(`Error al obtener detalles de app ${appId}:`, e);
        return res.status(500).json({ ok: false, error: "Error interno al obtener los detalles de la aplicación." });
    }
});


/* ----------------------------------------------------------------------------------
   4. ENDPOINTS: API DE CONSULTAS (Ahora sin autenticación/créditos, solo logging)
-------------------------------------------------------------------------------------*/
// 🛑 NOTA: Se ha añadido el parámetro de costo para fines de log, pero no se debita.

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
    mensaje: "🚀 Catálogo Público / API Consulta PE funcionando correctamente.",
    "consulta-pe": {
      poweredBy: "Consulta PE",
      info: "Catálogo público de aplicaciones y endpoints de consulta sin autenticación.",
    },
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Servidor corriendo en http://localhost:${PORT}`);
});
