FROM node:22-alpine

# Security: run as non-root
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

RUN chown -R appuser:appgroup /app
USER appuser

CMD ["npm", "run", "dev", "--", "--host"]
