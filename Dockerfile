# Postwart (früher Mail-Sortierer) – sortiert Postfächer mit lokaler KI, schützt vor gefährlichen Mails, Webmail
FROM node:22-slim
# Mindestversion Node.js (Sicherheitskorrekturen), wie bei Vedly
ARG NODE_MIN=22.23.5
RUN node -e "const a=process.versions.node.split('.').map(Number),b=process.argv[1].split('.').map(Number);for(let i=0;i<3;i++){if(a[i]>b[i])process.exit(0);if(a[i]<b[i]){console.error('Node '+process.versions.node+' ist älter als '+process.argv[1]);process.exit(1)}}" "$NODE_MIN"
ARG APP_VERSION=dev
WORKDIR /app
ENV NODE_ENV=production \
    PORT=8080 \
    DATA_DIR=/data \
    TZ=Europe/Berlin \
    APP_VERSION=$APP_VERSION
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --no-audit --no-fund && npm cache clean --force
COPY src ./src
COPY public ./public
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s CMD node -e "fetch('http://127.0.0.1:8080/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "--no-warnings", "src/index.js"]
