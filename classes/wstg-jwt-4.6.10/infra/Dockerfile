# PolyRange — WSTG-SESS-10 (4.6.10) JSON Web Tokens. Stateless Node;
# crypto via Node's built-in module so no extra deps beyond zod.
FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --no-audit --no-fund
COPY runtime/ ./runtime/
COPY classes/_shared/ ./classes/_shared/
COPY classes/wstg-jwt-4.6.10/scenario.mjs ./classes/wstg-jwt-4.6.10/scenario.mjs
COPY classes/wstg-jwt-4.6.10/behaviour.mjs ./classes/wstg-jwt-4.6.10/behaviour.mjs
COPY manifest.json ./manifest.json
ENV PORT=8080
ENV NODE_ENV=production
EXPOSE 8080
CMD ["node", "runtime/server.mjs"]
