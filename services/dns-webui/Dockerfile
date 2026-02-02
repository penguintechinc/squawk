# Squawk DNS WebUI - React + Nginx
# Build context must be project root (for shared/react_libs access)
# Stage 1: Build
FROM node:18-bookworm-slim AS build

WORKDIR /app

# Copy shared react_libs first (dependency)
COPY shared/react_libs /shared/react_libs

# Install react_libs dependencies first
WORKDIR /shared/react_libs
RUN npm install

# Now install webui dependencies
WORKDIR /app
COPY services/dns-webui/package.json ./
RUN npm install --legacy-peer-deps

# Copy source code and build
COPY services/dns-webui/ .
RUN npm run build

# Stage 2: Serve with nginx
FROM nginx:1.27-bookworm

LABEL company="Penguin Tech Group LLC"
LABEL org.opencontainers.image.authors="info@penguintech.io"
LABEL description="Squawk DNS Web Console (React)"

# Copy built assets
COPY --from=build /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY services/dns-webui/nginx.conf /etc/nginx/conf.d/default.conf

# Remove default nginx config
RUN rm -f /etc/nginx/conf.d/default.conf.bak

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3000/nginx-health || exit 1

CMD ["nginx", "-g", "daemon off;"]
