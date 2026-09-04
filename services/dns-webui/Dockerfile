# Squawk DNS WebUI - React + Nginx
# Stage 1: Build
FROM node:24-bookworm-slim@sha256:b506e7321f176aae77317f99d67a24b272c1f09f1d10f1761f2773447d8da26c AS build

WORKDIR /app

# Install dependencies (react-libs pulled from GitHub via npm)
COPY services/dns-webui/package.json services/dns-webui/package-lock.json ./
RUN npm install --legacy-peer-deps

# Copy source code and build
COPY services/dns-webui/ .
RUN npm run build

# Stage 2: Serve with nginx
FROM nginx:stable-bookworm@sha256:552e7481ca93ffccd046aa658dbbed22caefbc09c66fa7cd247cbb90b8a5c609

LABEL company="Penguin Tech Group LLC"
LABEL org.opencontainers.image.authors="info@penguintech.io"
LABEL description="Squawk DNS Web Console (React)"

# Copy built assets
COPY --from=build /app/dist /usr/share/nginx/html

# Copy nginx configuration
COPY services/dns-webui/nginx.conf /etc/nginx/conf.d/default.conf

# Remove default nginx config
RUN rm -f /etc/nginx/conf.d/default.conf.bak

# Allow nginx worker to run as non-root; fix ownership of required dirs
RUN chown -R nginx:nginx /usr/share/nginx/html /var/cache/nginx /var/log/nginx /etc/nginx/conf.d && \
    touch /var/run/nginx.pid && chown nginx:nginx /var/run/nginx.pid

USER nginx

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --retries=3 \
    CMD bash -c 'echo -e "HEAD /nginx-health HTTP/1.0\r\nHost: localhost\r\n\r\n" > /dev/tcp/localhost/3000' || exit 1

CMD ["nginx", "-g", "daemon off;"]
