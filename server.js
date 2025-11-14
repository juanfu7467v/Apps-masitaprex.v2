// server.js
import express from "express";
import dotenv from "dotenv";
dotenv.config();
import { Octokit } from "@octokit/rest";
import axios from "axios";
import FormData from "form-data"; 
import fs from "fs"; 
import path from "path"; 
import * as cheerio from 'cheerio'; // <--- NUEVA DEPENDENCIA

const app = express();
app.use(express.json({ limit: "10mb" }));

/* --------- Configs --------- */
const octokit = new Octokit({ auth: process.env.GITHUB_TOKEN });
const G_OWNER = process.env.GITHUB_OWNER;
const G_REPO = process.env.GITHUB_REPO;
const MAX_GITHUB_FILE_SIZE_MB = 100;
const USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'; // Para simular un navegador

/* --------- Helpers GitHub --------- */
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

/* ---------------------------------
   FUNCIÓN REAL: Búsqueda y Extracción de Metadatos de APKMirror
------------------------------------*/
async function searchAppAndScrapeInfo(query) {
    const searchUrl = `https://www.apkmirror.com/?post_type=app_release&searchtype=fuzzy&s=${encodeURIComponent(query)}`;
    
    try {
        const response = await axios.get(searchUrl, {
            headers: { 'User-Agent': USER_AGENT }
        });
        const $ = cheerio.load(response.data);
        
        // 1. Encontrar el primer resultado de la búsqueda
        const firstResultCard = $('.appRow').first();
        if (firstResultCard.length === 0) {
            return null; // No se encontraron resultados
        }
        
        // 2. Extraer el enlace a la página de la aplicación
        const appPageLink = firstResultCard.find('.appInfo .fontBlack').attr('href');
        if (!appPageLink) {
             return null;
        }
        const appPageUrl = `https://www.apkmirror.com${appPageLink}`;

        // 3. Obtener la página de la aplicación para metadatos detallados
        const appResponse = await axios.get(appPageUrl, {
            headers: { 'User-Agent': USER_AGENT }
        });
        const $$ = cheerio.load(appResponse.data);

        // 4. Extraer Metadatos
        const packageName = appPageLink.split('/').slice(-2, -1)[0]; // Ejemplo: /app/facebook/ -> facebook
        const displayName = $$('.app-name').text().trim() || 'Nombre Desconocido';
        
        // La versión más reciente está en la tabla de releases
        const latestRelease = $$('#primary_details > div.app_versions').first();
        const version = latestRelease.find('.appInfo > .fontBlack').text().trim().match(/Version:\s*([\d.]+)/)?.[1] || '0.0';
        
        // Extraer Descripción (A veces no disponible o requiere más scraping)
        // Por simplicidad, tomaremos la primera descripción o un placeholder.
        const description = $$('.details-section__description').text().trim() || 'No se encontró descripción.';

        // Extraer Ícono
        const iconUrl = $$('.app-icon').attr('src') || '';

        // Extraer URL de Descarga (Esta es la parte más compleja y requiere ir a la página de descarga)
        // APKMirror usa enlaces de redirección complejos. Usaremos el primer enlace de descarga:
        const downloadPageLink = $$('.downloadButton').first().attr('href');
        
        if (!downloadPageLink) {
             console.log("No se encontró enlace a la página de descarga.");
             return null;
        }
        
        const downloadPageUrl = `https://www.apkmirror.com${downloadPageLink}`;
        
        // ¡ADVERTENCIA! Scrapear el enlace final de descarga requiere otra petición HTTP
        // y puede romperse fácilmente si APKMirror cambia su HTML.
        // Aquí simplificaremos: solo devolvemos la URL de la página de descarga. 
        // El cliente (quien llama al API) podría necesitar ir a esa página para obtener la APK,
        // o, si la arquitectura lo permite, necesitamos un scraper más profundo.
        
        // Ya que el objetivo es la sincronización, intentaremos el scraping profundo para obtener la URL final de la APK.
        
        const finalDownloadLink = await scrapeFinalDownloadLink(downloadPageUrl);
        
        if (!finalDownloadLink) {
             console.log("No se pudo obtener el enlace final de descarga de la APK.");
             return null;
        }

        return {
            packageName,
            displayName,
            version,
            description,
            iconUrl: iconUrl.startsWith('//') ? 'https:' + iconUrl : iconUrl,
            screenshots: [], // APKMirror no lista capturas fácilmente, lo dejamos vacío
            downloadUrl: finalDownloadLink, 
            source: "apkmirror"
        };
        
    } catch (e) {
        console.error("Error en el scraping de APKMirror:", e);
        return null;
    }
}

// Función auxiliar para obtener el enlace de descarga final de APKMirror
async function scrapeFinalDownloadLink(downloadPageUrl) {
    try {
        const downloadResponse = await axios.get(downloadPageUrl, {
            headers: { 'User-Agent': USER_AGENT }
        });
        const $$$ = cheerio.load(downloadResponse.data);
        
        // Buscar el botón final de descarga que contenga el atributo 'data-url' o similar
        // APKMirror usa botones de descarga que redirigen al archivo final.
        // Buscamos la tabla con el botón de descarga real
        const finalDownloadButton = $$$('.accent_bg > a[rel="nofollow"]').first();
        
        if (finalDownloadButton.length > 0) {
            const finalLink = finalDownloadButton.attr('href');
            if (finalLink && finalLink.startsWith('/download')) {
                // Este es el enlace final que dispara la descarga.
                return `https://www.apkmirror.com${finalLink}`;
            }
        }
        
        return null; 
    } catch (e) {
        console.error("Error al obtener el enlace final de descarga:", e.message);
        return null;
    }
}


/* ---------------------------------
   ENDPOINT 1: Buscar Aplicación (REAL)
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
   ENDPOINT 2: Iniciar Sincronización Automática (REAL)
   Uso: POST /api/sync_app_by_search 
   Body: { query: "facebook" }
------------------------------------*/
app.post("/api/sync_app_by_search", async (req, res) => {
    const { query } = req.body;
    if (!query) return res.status(400).json({ ok: false, error: "El campo 'query' es requerido en el body." });

    try {
        // 1. Buscar y extraer metadatos
        const appInfo = await searchAppAndScrapeInfo(query);
        if (!appInfo || !appInfo.downloadUrl) {
            return res.json({ ok: false, error: "No se encontraron datos completos o URL de descarga para la aplicación." });
        }

        const { packageName, version, downloadUrl, displayName, description, iconUrl, screenshots } = appInfo;

        // 2. Descargar la APK
        // Se añade un User-Agent para la descarga, ya que algunas fuentes lo requieren.
        const apkResp = await axios.get(downloadUrl, { 
            responseType: "arraybuffer",
            headers: { 'User-Agent': USER_AGENT }
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
