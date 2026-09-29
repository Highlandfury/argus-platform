# Argus web (Next.js) — production image.
# Build arg ARGUS_API_BASE is baked into the /api rewrite (compose: http://server:8080).

FROM node:24.21.0-alpine AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci

FROM node:24.21.0-alpine AS build
WORKDIR /app
COPY --from=deps /app/node_modules ./node_modules
COPY . .
ARG ARGUS_API_BASE=http://127.0.0.1:8080
ENV ARGUS_API_BASE=$ARGUS_API_BASE
ENV NEXT_TELEMETRY_DISABLED=1
RUN npm run build

FROM node:24.21.0-alpine AS run
WORKDIR /app
ENV NODE_ENV=production NEXT_TELEMETRY_DISABLED=1 PORT=3000 HOSTNAME=0.0.0.0
ARG ARGUS_API_BASE=http://127.0.0.1:8080
ENV ARGUS_API_BASE=$ARGUS_API_BASE
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public
EXPOSE 3000
CMD ["node", "server.js"]
