# syntax = docker/dockerfile:1

# Adjust NODE_VERSION as desired
ARG NODE_VERSION=20.12.2 # Usando la versión LTS más reciente como recomendación
FROM node:${NODE_VERSION}-slim AS base

LABEL fly_launch_runtime="Node.js"

# Node.js app lives here
WORKDIR /app

# Set production environment
ENV NODE_ENV="production"


# Throw-away build stage to reduce size of final image
FROM base AS build

# Install packages needed to build node modules
# El paquete python-is-python3 ya no es necesario en Node 20
RUN apt-get update -qq && \
    apt-get install --no-install-recommends -y build-essential pkg-config

# Install node modules
COPY package.json ./
# Para Node.js en producción, es mejor usar `npm ci` si tienes un package-lock.json (que se supone que sí)
# Pero `npm install` es suficiente para esta etapa de construcción
RUN npm install

# Copy application code
COPY . .


# Final stage for app image
FROM base

# Copy built application
COPY --from=build /app /app

# Start the server by default, this can be overwritten at runtime
EXPOSE 3000
CMD [ "npm", "run", "start" ]
