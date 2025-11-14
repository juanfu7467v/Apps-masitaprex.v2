// server.js
import express from "express";
import dotenv from "dotenv";
dotenv.config();
import { Octokit } from "@octokit/rest";
import axios from "axios";
import FormData from "form-data"; 
import fs from "fs"; 
import path from "path"; 
// import * as cheerio from 'cheerio'; // Ya no es necesario, Puppeteer usa un DOM
import puppeteer from 'puppeteer'; // <-- NUEVA LIBRERÍA

const app = express();
app.use(express.json({ limit: "10mb" }));

/* --------- Configs --------- */
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const G_OWNER = process.env.GITHUB_OWNER;
const G_REPO = process.env.GITHUB_REPO;
const MAX_GITHUB_FILE_SIZE_MB = 100;

// ----------------------------------------------------
// FUNCIÓN CENTRAL PARA INICIAR EL NAVEGADOR VIRTUAL
// ----------------------------------------------------
async function launchBrowser() {
    // Esto asegura que Puppeteer pueda ejecutarse en entornos como Fly.io/Alpine
    const browser = await puppeteer.launch({ 
        headless: true, // Ejecutar sin interfaz gráfica
        args: [
            '--no-sandbox', // NECESARIO para Docker/Alpine
            '--disable-setuid-sandbox', 
            '--disable-dev-shm-usage' // Importante para entornos con poca memoria (como Fly.io)
        ],
        executablePath: process.env.PUPPETEER_EXECUTABLE_PATH, // Usado por Alpine Dockerfile
        timeout: 60000 // Aumentar timeout a 60 segundos
    });
    return browser;
}


/* --------- Helpers GitHub (sin cambios) --------- */
async function createOrUpdateGithubFile(pathInRepo, contentBase64, message) {
  // Try get file to know if create or update
  try {
    const get = await octokit.repos.getContent({
      owner: G_OWNER,
      repo: G_REPO,
      path: pathInRepo,
    });
    // update
    const sha = get.data.sha;
    const res = await octokit.repos.createOrUpdateFileContents({
      owner: G_OWNER,
      repo: G_REPO,
      path: pathInRepo,
      message,
      content: contentBase64,
      sha,
    });
    return res.data;
  } catch (err) {
    // create
    const res = await octokit.repos.createOrUpdateFileContents({
      owner: G_OWNER,
      repo: G_REPO,
      path: pathInRepo,
      message,
      content: contentBase64,
    });
    return res.data;
  }
}

/* ----------------------------------------------------------------------
   FUNCIÓN REAL: Búsqueda y Extracción de Metadatos de APKMirror con Puppeteer
------------------------------------------------------------------------- */
async function searchAppAndScrapeInfo(query) {
    const browser = await launchBrowser();
    const page = await browser.newPage();
    const searchUrl = `https://www.apkmirror.com/?post_type=app_release&searchtype=fuzzy&s=${encodeURIComponent(query)}`;
    
    try {
        await page.goto(searchUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
        
        // 1. ESPERAR A QUE EL PRIMER RESULTADO APAREZCA antes de continuar
        const resultSelector = '.apkm-table-row';
        try {
            await page.waitForSelector(resultSelector, { timeout: 10000 }); // Espera hasta 10 segundos
        } catch (e) {
            console.log("No se encontró el selector de resultados de APKMirror. La estructura pudo haber cambiado.");
            return null;
        }

        // 1. Encontrar el primer resultado de la búsqueda
        const firstResultCard = await page.$(resultSelector); 
        if (!firstResultCard) {
            return null; // No se encontraron resultados (aunque waitForSelector ya lo indicó)
        }
        
        // 2. Extraer el enlace a la página de la aplicación
        const appPageLink = await firstResultCard.$eval('.appRow > div:nth-child(2) > a', a => a.getAttribute('href'));
        
        if (!appPageLink) {
             console.log("No se encontró appPageLink en el resultado de búsqueda.");
             return null;
        }
        const appPageUrl = `https://www.apkmirror.com${appPageLink}`;

        // 3. Navegar a la página de la aplicación para metadatos detallados
        await page.goto(appPageUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
        
        // Esperar a que el título principal de la aplicación esté cargado
        try {
            await page.waitForSelector('.app-name', { timeout: 5000 });
        } catch (e) {
            console.log("No se pudo cargar la página de detalles de la aplicación.");
            return null;
        }


        // 4. Extraer Metadatos usando page.evaluate
        const metaData = await page.evaluate((appPageLink) => {
            const getText = (selector) => document.querySelector(selector)?.textContent.trim() || '';
            const getAttr = (selector, attr) => document.querySelector(selector)?.getAttribute(attr) || '';

            const packageNameMatch = appPageLink.match(/\/app\/([^/]+)\/$/);
            const packageName = packageNameMatch ? packageNameMatch[1] : 'unknown.package.name';
            
            const displayName = getText('.app-name') || 'Nombre Desconocido';
            
            const latestReleaseLink = getAttr('#primary_details .app_versions .appRow:first-child .app-name-link', 'href');
            
            let version = '0.0';
            if (latestReleaseLink) {
                const parts = latestReleaseLink.split('/');
                for (const part of parts.reverse()) {
                    const versionMatch = part.match(/(\d+\.\d+\.\d+(\.\d+)*)/);
                    if (versionMatch) {
                        version = versionMatch[1];
                        break;
                    }
                }
            }
            
            const descriptionElement = document.querySelector('.details-section__description');
            let description = descriptionElement ? descriptionElement.textContent.trim().substring(0, 500) + '...' : 'No se encontró descripción.';
            
            const iconUrl = getAttr('.app-icon', 'src') || '';

            // Extraer URL de Descarga 
            const downloadPageLink = getAttr('#primary_details .app_versions .downloadButton', 'href');
            
            return {
                packageName,
                displayName,
                version,
                description,
                iconUrl,
                downloadPageLink
            };
        }, appPageLink); // Pasamos el enlace original para extraer el packageName

        if (!metaData.downloadPageLink) {
             console.log("No se encontró enlace a la página de descarga.");
             return null;
        }
        
        const downloadPageUrl = `https://www.apkmirror.com${metaData.downloadPageLink}`;
        
        // 5. Obtener el enlace final de descarga (usando Puppeteer)
        const finalDownloadLink = await scrapeFinalDownloadLink(browser, downloadPageUrl);
        
        if (!finalDownloadLink) {
             console.log("No se pudo obtener el enlace final de descarga de la APK.");
             return null;
        }

        return {
            packageName: metaData.packageName,
            displayName: metaData.displayName,
            version: metaData.version,
            description: metaData.description,
            iconUrl: metaData.iconUrl.startsWith('//') ? 'https:' + metaData.iconUrl : metaData.iconUrl,
            screenshots: [], 
            downloadUrl: finalDownloadLink, 
            source: "apkmirror"
        };
        
    } catch (e) {
        console.error("Error en el scraping de APKMirror con Puppeteer:", e.message);
        return null;
    } finally {
        // CERRAR EL NAVEGADOR ES CRÍTICO PARA NO AGOTAR RECURSOS
        await browser.close(); 
    }
}

// Función auxiliar para obtener el enlace de descarga final de APKMirror (con Puppeteer)
async function scrapeFinalDownloadLink(browser, downloadPageUrl) {
    const page = await browser.newPage();
    try {
        await page.goto(downloadPageUrl, { waitUntil: 'domcontentloaded', timeout: 30000 });
        
        // Esperar a que el botón de descarga aparezca
        const finalDownloadSelector = '.accent_bg > a[rel="nofollow"]';
        try {
             await page.waitForSelector(finalDownloadSelector, { timeout: 10000 });
        } catch (e) {
            console.log("No se pudo encontrar el botón final de descarga.");
             // Intenta el selector de fallback si el principal falla
             const fallbackLink = await page.evaluate(() => {
                 const fb = document.querySelector('a[rel="nofollow"][href*="/download.php"]');
                 return fb ? `https://www.apkmirror.com${fb.getAttribute('href')}` : null;
             });
             return fallbackLink;
        }
        
        // Buscar el botón final de descarga que contenga el atributo 'href'
        const finalLink = await page.evaluate((finalDownloadSelector) => {
            const finalDownloadButton = document.querySelector(finalDownloadSelector);
            
            if (finalDownloadButton) {
                const link = finalDownloadButton.getAttribute('href');
                if (link && link.startsWith('/download')) {
                    return `https://www.apkmirror.com${link}`;
                }
            }
            return null;
        }, finalDownloadSelector);

        return finalLink; 
    } catch (e) {
        console.error("Error al obtener el enlace final de descarga con Puppeteer:", e.message);
        return null;
    } finally {
        await page.close(); // Cerrar la página para liberar memoria
    }
}

/* ---------------------------------
   ENDPOINT 1: Buscar Aplicación
   Uso: GET /api/search_app?q=facebook
------------------------------------*/
app.get("/api/search_app", async (req, res) => {
    const { q } = req.query;
    if (!q) return res.status(400).json({ ok: false, error: "El parámetro 'q' (consulta de búsqueda) es requerido." });

    try {
        const appInfo = await searchAppAndScrapeInfo(q);
        
        if (!appInfo) {
            return res.json({ ok: true, results: [], message: "No se encontraron resultados para la búsqueda." });
        }

        // Devolvemos el resultado encontrado
        return res.json({ 
            ok: true, 
            results: [appInfo],
            message: "Resultados de búsqueda scrapeados de APKMirror."
        });

    } catch (e) {
        console.error(e);
        return res.status(500).json({ ok: false, error: e.message });
    }
});

/* ---------------------------------
   ENDPOINT 2: Iniciar Sincronización Automática
   Uso: POST /api/sync_app_by_search 
   Body: { query: "facebook" }
------------------------------------*/
app.post("/api/sync_app_by_search", async (req, res) => {
    const { query } = req.body;
    if (!query) return res.status(400).json({ ok: false, error: "El campo 'query' es requerido en el body." });
    
    // User Agent para la descarga con Axios (menos probable que sea bloqueado)
    const AXIOS_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

    try {
        // 1. Buscar y extraer metadatos
        const appInfo = await searchAppAndScrapeInfo(query);
        if (!appInfo || !appInfo.downloadUrl) {
            return res.json({ ok: false, error: "No se encontraron datos completos o URL de descarga para la aplicación." });
        }

        const { packageName, version, downloadUrl, displayName, description, iconUrl, screenshots } = appInfo;

        // 2. Descargar la APK usando Axios (más eficiente para archivos binarios)
        const apkResp = await axios.get(downloadUrl, { 
            responseType: "arraybuffer",
            headers: { 'User-Agent': AXIOS_USER_AGENT } 
        });
        const apkBuffer = Buffer.from(apkResp.data);

        // 3. Verificar límite de tamaño
        if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
            return res.json({ ok: false, error: `APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB) para GitHub API.` });
        }

        // 4. Guardar APK en GitHub
        const base64Apk = apkBuffer.toString("base64");
        const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
        await createOrUpdateGithubFile(apkPath, base64Apk, `Sincronizar APK: ${displayName} v${version}`);
        
        // 5. Crear Metadatos completos
        const meta = {
            source: appInfo.source,
            packageName,
            displayName,
            version,
            description,
            iconUrl,
            screenshots,
            size: apkBuffer.length,
            addedAt: new Date().toISOString(),
            apkPath
        };

        // 6. Guardar Metadatos en GitHub
        const metaPath = `public/apps/${packageName}/meta_${version}.json`;
        await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Sincronizar Meta: ${displayName} v${version}`);

        return res.json({ 
            ok: true, 
            meta, 
            message: `APK y Metadatos de ${displayName} v${version} sincronizados exitosamente.` 
        });

    } catch (e) {
        console.error("Error en sync_app_by_search:", e);
        return res.status(500).json({ ok: false, error: `Error durante la sincronización: ${e.message}` });
    }
});

/* ---------------------------------
   ENDPOINT 3: Sincronización Masiva de Apps Populares
   Uso: POST /api/sync_popular_apps 
------------------------------------*/
const POPULAR_APPS = [
    "facebook",
    "whatsapp",
    "instagram",
    "telegram",
    "spotify"
];

app.post("/api/sync_popular_apps", async (req, res) => {
    let results = [];
    let successCount = 0;
    
    // User Agent para la descarga con Axios
    const AXIOS_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';
    
    const syncSingleApp = async (query) => {
        try {
            const appInfo = await searchAppAndScrapeInfo(query);
            
            if (!appInfo || !appInfo.downloadUrl) {
                return { query, ok: false, message: "No se encontraron datos o URL de descarga." };
            }

            const { packageName, version, downloadUrl, displayName } = appInfo;

            const apkResp = await axios.get(downloadUrl, { 
                responseType: "arraybuffer",
                headers: { 'User-Agent': AXIOS_USER_AGENT }
            });
            const apkBuffer = Buffer.from(apkResp.data);

            if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
                return { query, ok: false, message: `APK demasiado grande (>=${MAX_GITHUB_FILE_SIZE_MB}MB).` };
            }

            // 4. Guardar APK y Metadatos en GitHub
            const base64Apk = apkBuffer.toString("base64");
            const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
            
            const meta = {
                source: appInfo.source,
                packageName,
                displayName,
                version,
                size: apkBuffer.length,
                addedAt: new Date().toISOString(),
                apkPath,
                description: appInfo.description,
                iconUrl: appInfo.iconUrl,
                screenshots: appInfo.screenshots
            };
            
            // Subir APK
            await createOrUpdateGithubFile(apkPath, base64Apk, `Sincronizar APK Masiva: ${displayName} v${version}`);
            
            // Subir Metadatos
            const metaPath = `public/apps/${packageName}/meta_${version}.json`;
            await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta, null, 2)).toString("base64"), `Sincronizar Meta Masiva: ${displayName} v${version}`);

            successCount++;
            return { query, ok: true, version, packageName, message: "Sincronizado correctamente." };

        } catch (e) {
            console.error(`Error al sincronizar ${query}:`, e.message);
            return { query, ok: false, message: `Error desconocido: ${e.message}` };
        }
    };

    for (const appQuery of POPULAR_APPS) {
        const result = await syncSingleApp(appQuery);
        results.push(result);
    }

    return res.json({ 
        ok: true, 
        totalProcessed: POPULAR_APPS.length,
        totalSuccess: successCount,
        results,
        message: "Proceso de sincronización masiva finalizado."
    });
});


/* ---------------------------------
   CRAWLERS ORIGINALES (Mantenidos)
------------------------------------*/

// 1) GitHub Releases fetcher
app.get("/api/sync_github_release", async (req, res) => {
  const { repo, packageName } = req.query; // format owner/repo
  if (!repo) return res.status(400).json({ ok:false, error: "repo param required (owner/repo)"});
  try {
    // list releases
    const [owner, repoName] = repo.split("/");
    const pName = packageName || repoName; // Usar repoName como packageName si no se especifica
    const releases = await octokit.repos.listReleases({ owner, repo: repoName, per_page: 5 });
    if (!releases.data.length) return res.json({ ok:false, error: "No releases found" });

    // find first release with asset .apk
    let assetUrl=null, assetName=null, version=null;
    for (const r of releases.data) {
      version = r.tag_name || r.name || "unknown";
      if (r.assets && r.assets.length) {
        for (const a of r.assets) {
          if (a.name.endsWith(".apk")) {
            assetUrl = a.browser_download_url;
            assetName = a.name;
            break;
          }
        }
      }
      if (assetUrl) break;
    }
    if (!assetUrl) return res.json({ ok:false, error: "No APK asset in recent releases" });

    // download apk
    const apkResp = await axios.get(assetUrl, { responseType: "arraybuffer" });
    const apkBuffer = Buffer.from(apkResp.data);

    // Check size limit
    if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
      // GitHub API limit ~100MB. Warn.
      return res.json({ ok:false, error: `APK too large for GitHub API (>=${MAX_GITHUB_FILE_SIZE_MB}MB). Use external storage (S3) or Git LFS.`});
    }

    // Save to GitHub (base64)
    const base64Apk = apkBuffer.toString("base64");
    const apkPath = `public/apps/${pName}/apk_${version}.apk`;
    await createOrUpdateGithubFile(apkPath, base64Apk, `Add APK ${pName} ${version}`);

    // metadata
    const meta = {
      source: "github_release",
      owner,
      repo: repoName,
      packageName: pName,
      version,
      assetName,
      size: apkBuffer.length,
      addedAt: new Date().toISOString(),
      apkPath
    };
    const metaPath = `public/apps/${pName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta,null,2)).toString("base64"), `Add meta ${pName} ${version}`);

    return res.json({ ok:true, meta, message: "APK sincronizado." });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok:false, error: e.message });
  }
});

// 2) F-Droid fetcher (requires package name)
app.get("/api/sync_fdroid", async (req, res) => {
  const { packageName } = req.query;
  if (!packageName) return res.status(400).json({ ok:false, error:"packageName required" });
  try {
    // Simpler approach: fetch package page to get the APK link
    const page = `https://f-droid.org/en/packages/${packageName}/`;
    const html = await axios.get(page).then(r=>r.data).catch(()=>null);
    if (!html) return res.json({ ok:false, error: "Package not found on F-Droid" });

    // parse link to .apk (best-effort)
    const m = html.match(/href="([^"]+\.apk)"/);
    if (!m) return res.json({ ok:false, error:"APK link not found in page" });
    let apkUrl = m[1];
    if (!apkUrl.startsWith("http")) apkUrl = "https://f-droid.org" + apkUrl;

    const apkResp = await axios.get(apkUrl, { responseType: "arraybuffer" });
    const apkBuffer = Buffer.from(apkResp.data);
    const versionMatch = html.match(/Version<\/th>\s*<td[^>]*>([^<]+)</);
    const version = versionMatch ? versionMatch[1].trim() : "unknown";

    // Check size limit
    if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
      return res.json({ ok:false, error: `APK too large for GitHub API (>=${MAX_GITHUB_FILE_SIZE_MB}MB). Use external storage.`});
    }
    
    // Save to GitHub
    const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
    await createOrUpdateGithubFile(apkPath, apkBuffer.toString("base64"), `Add F-Droid APK ${packageName} ${version}`);

    const meta = {
      source: "f-droid",
      packageName,
      version,
      size: apkBuffer.length,
      addedAt: new Date().toISOString(),
      apkPath
    };
    const metaPath = `public/apps/${packageName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta,null,2)).toString("base64"), `Add meta ${packageName} ${version}`);

    return res.json({ ok:true, meta, message: "APK sincronizado." });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok:false, error: e.message });
  }
});

// 3) Manual add by direct URL
app.post("/api/manual_add", async (req, res) => {
  // body: { url: "...", packageName: "..." , displayName: "..."}
  try {
    const { url, packageName, displayName } = req.body;
    if (!url || !packageName) return res.status(400).json({ ok:false, error:"url and packageName required" });
    
    const apkResp = await axios.get(url, { responseType: "arraybuffer" });
    const apkBuffer = Buffer.from(apkResp.data);
    
    // Check size limit
    if (apkBuffer.length >= MAX_GITHUB_FILE_SIZE_MB * 1024 * 1024) {
      return res.json({ ok:false, error: `APK too large for GitHub API (>=${MAX_GITHUB_FILE_SIZE_MB}MB). Use external storage.`});
    }
    
    const version = "manual-" + Date.now();
    const apkPath = `public/apps/${packageName}/apk_${version}.apk`;
    await createOrUpdateGithubFile(apkPath, apkBuffer.toString("base64"), `Add manual APK ${packageName} ${version}`);
    
    const meta = { 
        source:"manual", 
        url, 
        packageName, 
        displayName, 
        size: apkBuffer.length, 
        addedAt: new Date().toISOString(), 
        apkPath 
    };
    const metaPath = `public/apps/${packageName}/meta_${version}.json`;
    await createOrUpdateGithubFile(metaPath, Buffer.from(JSON.stringify(meta,null,2)).toString("base64"), `Add meta ${packageName} ${version}`);
    
    return res.json({ ok:true, meta, message: "APK agregado manualmente." });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok:false, error: e.message });
  }
});

// 4) List apps simple: reads repo tree for public/apps
app.get("/api/list_apps", async (req, res) => {
  try {
    const tree = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: "public/apps" });
    // tree is array of directories (one per package)
    const apps = [];
    for (const dir of tree.data) {
      if (dir.type === "dir") apps.push({ packageName: dir.name, path: dir.path });
    }
    return res.json({ ok:true, apps });
  } catch (e) {
    // Si 'public/apps' no existe, GitHub devuelve 404.
    if (e.status === 404) return res.json({ ok:true, apps: [], message: "No se encontró el directorio public/apps, el catálogo está vacío." });
    console.error(e);
    return res.status(500).json({ ok:false, error: e.message });
  }
});

// 5) Get metadata for a package (most recent meta_*.json)
app.get("/api/get_app_meta", async (req,res) => {
  const { packageName } = req.query;
  if (!packageName) return res.status(400).json({ ok:false, error:"packageName required" });
  try {
    const dir = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: `public/apps/${packageName}` });
    // find meta_*.json
    const metas = dir.data.filter(d=>d.name.startsWith("meta_") && d.name.endsWith(".json"));
    if (!metas.length) return res.json({ ok:false, error:"No metadata found" });
    // pick latest by name (not perfect but ok)
    metas.sort((a,b)=> b.name.localeCompare(a.name));
    const raw = await octokit.repos.getContent({ owner: G_OWNER, repo: G_REPO, path: metas[0].path });
    const content = Buffer.from(raw.data.content, "base64").toString("utf8");
    return res.json({ ok:true, meta: JSON.parse(content) });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok:false, error: e.message });
  }
});

/* --------- Simple health --------- */
app.get("/api/ping", (req,res)=> res.json({ ok:true, ts: new Date().toISOString() }) );

/* --------- Start server --------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log("App running on", PORT));
