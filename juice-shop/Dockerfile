# Stage 1: Build and install production dependencies
FROM node:20-buster AS builder

WORKDIR /juice-shop

# Copy all source files
COPY . .

# Install build tools for native module compilation
RUN apt-get update && \
    apt-get install -y --no-install-recommends build-essential python3 && \
    rm -rf /var/lib/apt/lists/*

# Install only production dependencies
RUN npm install --omit=dev --unsafe-perm && \
    npm dedupe --omit=dev && \
    npm cache clean --force

# Build native libxmljs module
RUN rm -rf node_modules/libxmljs/build && \
    cd node_modules/libxmljs && \
    npm run build

# Clean up unnecessary frontend assets
RUN rm -rf frontend/node_modules frontend/.angular frontend/src/assets && \
    rm -f data/chatbot/botDefaultTrainingData.json ftp/legal.md i18n/*.json

# Fix permissions for runtime
RUN mkdir -p logs && \
    chown -R 1001:1001 logs ftp/ frontend/dist/ logs/ data/ i18n/ && \
    chmod -R g=u logs ftp/ frontend/dist/ logs/ data/ i18n/

# Stage 2: Final runtime image (minimal & secure)
FROM gcr.io/distroless/nodejs20-debian12
# FROM node:20-alpine

LABEL maintainer="Bjoern Kimminich <bjoern.kimminich@owasp.org>" \
      org.opencontainers.image.title="OWASP Juice Shop" \
      org.opencontainers.image.description="Probably the most modern and sophisticated insecure web application" \
      org.opencontainers.image.authors="Bjoern Kimminich <bjoern.kimminich@owasp.org>" \
      org.opencontainers.image.vendor="Open Worldwide Application Security Project" \
      org.opencontainers.image.documentation="https://help.owasp-juice.shop" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="17.3.0" \
      org.opencontainers.image.url="https://owasp-juice.shop" \
      org.opencontainers.image.source="https://github.com/juice-shop/juice-shop"

WORKDIR /juice-shop

# Copy built application and dependencies from builder
COPY --from=builder --chown=1001:1001 /juice-shop .

# Use non-root user for security
USER 1001

# Expose application port
EXPOSE 3000

# Use read-only root filesystem (enforced at runtime)
CMD ["/juice-shop/build/app.js"]