# PolyRange — WSTG-INPV-07 (4.7.7) XXE. Node + libxml2 (libxmljs2, native build).
FROM node:20-alpine
# Build deps for libxmljs2's native compile.
RUN apk add --no-cache python3 make g++
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-xxe-4.7.7/scenario.mjs ./classes/wstg-xxe-4.7.7/scenario.mjs
COPY classes/wstg-xxe-4.7.7/behaviour.mjs ./classes/wstg-xxe-4.7.7/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
