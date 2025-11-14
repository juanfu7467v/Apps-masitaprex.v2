# Usa una imagen base oficial de Node.js
FROM node:20-alpine

# Crea y establece el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copia los archivos de manifiesto y dependencias
COPY package*.json ./

# Instala las dependencias
RUN npm install --omit=dev

# Copia el resto del código
COPY . .

# Expone el puerto que la aplicación escuchará (3000)
EXPOSE 3000

# Comando para iniciar la aplicación (debe coincidir con "start" en package.json)
CMD ["npm", "start"]
