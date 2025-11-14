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

// USER_AGENT no es necesario ya que Puppeteer usa uno real.
// const USER_AGENT = '...'; 


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
        
        // 1. Encontrar el primer resultado de la búsqueda
        const firstResultCard = await page.$('.apkm-table-row'); 
        if (!firstResultCard) {
            return null; // No se encontraron resultados
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

        // 4. Extraer Metadatos usando page.evaluate
        const metaData = await page.evaluate((appPageLink) => {
            const getInnerHtml = (selector) => document.querySelector(selector)?.innerHTML.trim() || '';
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
            
            const description = getText('.details-section__description').substring(0, 500) + '...' || 'No se encontró descripción.';
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
        
        // Buscar el botón final de descarga que contenga el atributo 'href'
        const finalLink = await page.evaluate(() => {
            // Buscamos el enlace del botón final de descarga
            const finalDownloadButton = document.querySelector('.accent_bg > a[rel="nofollow"]');
            
            if (finalDownloadButton) {
                const link = finalDownloadButton.getAttribute('href');
                if (link && link.startsWith('/download')) {
                    return `https://www.apkmirror.com${link}`;
                }
            }
            
            // Fallback (por si el selector cambia)
            const fallbackLink = document.querySelector('a[rel="nofollow"][href*="/download.php"]');
            if (fallbackLink) {
                return `https://www.apkmirror.com${fallbackLink.getAttribute('href')}`;
            }
            
            return null;
        });

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
// ... EL ENDPOINT 1 NO CAMBIA ...

/* ---------------------------------
   ENDPOINT 2: Iniciar Sincronización Automática
   Uso: POST /api/sync_app_by_search 
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
        // **IMPORTANTE**: La descarga de la APK debe seguir usando AXIOS/Buffer,
        // ya que es más eficiente que intentar que Puppeteer descargue el archivo binario.
        const apkResp = await axios.get(downloadUrl, { 
            responseType: "arraybuffer",
            // Es buena práctica usar un User-Agent real aquí también, aunque APKMirror rara vez bloquea las descargas directas.
            headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36' } 
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
// ... EL ENDPOINT 3 NO CAMBIA (usa la función searchAppAndScrapeInfo modificada) ...

/* ---------------------------------
   CRAWLERS ORIGINALES (Mantenidos)
------------------------------------*/

// 1) GitHub Releases fetcher (usa axios, NO CAMBIA)
// 2) F-Droid fetcher (usa axios, NO CAMBIA)
// 3) Manual add by direct URL (usa axios, NO CAMBIA)
// 4) List apps simple (usa Octokit, NO CAMBIA)
// 5) Get metadata for a package (usa Octokit, NO CAMBIA)

/* --------- Simple health --------- */
app.get("/api/ping", (req,res)=> res.json({ ok:true, ts: new Date().toISOString() }) );

/* --------- Start server --------- */
const PORT = process.env.PORT || 3000;
app.listen(PORT, ()=> console.log("App running on", PORT));
