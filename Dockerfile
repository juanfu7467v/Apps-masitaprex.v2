# Usa una imagen base oficial de Node.js (estable y ligera)
FROM node:20-alpine

# Instalar dependencias de Chromium para Puppeteer en Alpine
# Fuente: https://pptr.dev/troubleshooting#running-puppeteer-on-alpine
RUN apk add --no-cache \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont \
    ghostscript

# Establecer variable de entorno para que Puppeteer sepa dónde encontrar Chromium
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium-browser

# Crea y establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos de manifiesto y dependencias
COPY package*.json ./

# Instala las dependencias (solo de producción para reducir el tamaño de la imagen)
RUN npm install --omit=dev

# Copia el resto del código (incluyendo server.js)
COPY . .

# Expone el puerto que la aplicación escuchará
EXPOSE 3000

# Comando para iniciar la aplicación (usa el script "start" de package.json)
CMD ["npm", "start"]
