FROM node:18-alpine AS builder

WORKDIR /app

COPY medusa-webapp/package.json medusa-webapp/package-lock.json* ./
RUN npm install

COPY medusa-webapp/ .

# Build-time environment variables
ARG NEXT_PUBLIC_MEDUSA_API_URL
ENV NEXT_PUBLIC_MEDUSA_API_URL=$NEXT_PUBLIC_MEDUSA_API_URL

RUN npm run build

FROM node:18-alpine AS runner

WORKDIR /app

ENV NODE_ENV production

COPY --from=builder /app/public ./public
COPY --from=builder /app/.next/standalone ./
COPY --from=builder /app/.next/static ./.next/static

EXPOSE 3000

ENV PORT 3000
ENV HOSTNAME "0.0.0.0"

CMD ["node", "server.js"]

