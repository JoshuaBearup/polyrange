# PolyRange — WSTG-BUSL-09 (4.10.9) Malicious File Upload. Node front + PHP backend.
FROM node:20-alpine
RUN (apk add --no-cache php83 && ln -sf /usr/bin/php83 /usr/local/bin/php) \
 || (apk add --no-cache php82 && ln -sf /usr/bin/php82 /usr/local/bin/php)
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-file-upload-rce-4.10.9/scenario.mjs ./classes/wstg-file-upload-rce-4.10.9/scenario.mjs
COPY classes/wstg-file-upload-rce-4.10.9/behaviour.mjs ./classes/wstg-file-upload-rce-4.10.9/behaviour.mjs
COPY classes/wstg-file-upload-rce-4.10.9/backends/ ./classes/wstg-file-upload-rce-4.10.9/backends/
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
