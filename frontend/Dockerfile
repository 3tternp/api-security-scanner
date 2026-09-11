FROM node:22-alpine

RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

WORKDIR /app
RUN chown appuser:appgroup /app

COPY --chown=appuser:appgroup package*.json ./
USER appuser
RUN npm ci

COPY --chown=appuser:appgroup . .

CMD ["npm", "run", "dev", "--", "--host"]
