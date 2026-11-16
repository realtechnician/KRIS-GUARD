# syntax=docker/dockerfile:1

# ---- Stage 1: build ---------------------------------------------------------
# Installs everything (including build tools), compiles TypeScript to
# JavaScript, then removes what is only needed for building.
# The full (not "slim") Node image is used for building because it already
# contains a compiler. The SQLite library normally downloads a ready-made
# binary, but if none exists for this machine it compiles itself instead.
# None of this ends up in the final image.
FROM node:22.23.4-bookworm AS build
WORKDIR /app
COPY package.json package-lock.json ./
# "npm ci" installs exactly the versions in package-lock.json, nothing newer.
RUN npm ci
COPY tsconfig.json tsconfig.build.json ./
COPY src ./src
RUN npm run build && npm prune --omit=dev

# ---- Stage 2: run -----------------------------------------------------------
# A small image with only what is needed to run. No compiler, no test tools.
FROM node:22.23.4-bookworm-slim
ENV NODE_ENV=production \
    DATABASE_URL=sqlite:/data/kris-guard.db \
    POLICY_DIR=/app/config/policies \
    CHECKPOINT_DIR=/data/checkpoints \
    HOST=0.0.0.0 \
    PORT=8080
WORKDIR /app
COPY --from=build /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
# /data holds the database and checkpoints; policies are mounted from the host.
RUN mkdir -p /data /app/config/policies \
    && chown -R node:node /data /app/config \
    && printf '#!/bin/sh\nexec node /app/dist/cli.js "$@"\n' > /usr/local/bin/kris-guard \
    && chmod +x /usr/local/bin/kris-guard
# Never run as root: if a bug is ever exploited, the attacker gets a
# powerless user inside the container, not the machine.
USER node
EXPOSE 8080
VOLUME ["/data"]
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8080)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "dist/index.js"]
