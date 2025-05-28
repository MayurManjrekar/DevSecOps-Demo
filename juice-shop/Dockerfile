# Single stage: Build everything here
FROM node:20-buster AS installer

# Set working directory and copy source
WORKDIR /juice-shop
COPY . .

# Install global tools and app dependencies
RUN npm i -g typescript ts-node && \
    npm install --omit=dev --unsafe-perm && \
    npm dedupe --omit=dev && \
    npm install -g @cyclonedx/cyclonedx-npm@latest && \
    npm run sbom

# Clean up unneeded frontend dev artifacts
RUN rm -rf frontend/node_modules frontend/.angular frontend/src/assets && \
    rm -f data/chatbot/botDefaultTrainingData.json ftp/legal.md i18n/*.json

# Build libxmljs to prevent runtime issues
RUN apt-get update && apt-get install -y build-essential python3 && \
    rm -rf node_modules/libxmljs/build && \
    cd node_modules/libxmljs && npm run build

# Fix permissions for distroless runtime
RUN mkdir -p logs \
    .well-known/csaf \
    frontend/dist/frontend/assets/public/videos && \
    chown -R 65532 logs && \
    chgrp -R 0 ftp/ frontend/dist/ logs/ data/ i18n/ .well-known frontend/dist/frontend/assets/public/videos && \
    chmod -R g=u ftp/ frontend/dist/ logs/ data/ i18n/ .well-known frontend/dist/frontend/assets/public/videos && \
    chmod -R 777 data ftp logs .well-known frontend/dist/frontend/assets/public/videos


FROM gcr.io/distroless/nodejs20-debian12

ARG BUILD_DATE
ARG VCS_REF

LABEL maintainer="Bjoern Kimminich <bjoern.kimminich@owasp.org>" \
    org.opencontainers.image.title="OWASP Juice Shop" \
    org.opencontainers.image.description="Probably the most modern and sophisticated insecure web application" \
    org.opencontainers.image.authors="Bjoern Kimminich <bjoern.kimminich@owasp.org>" \
    org.opencontainers.image.vendor="Open Worldwide Application Security Project" \
    org.opencontainers.image.documentation="https://help.owasp-juice.shop" \
    org.opencontainers.image.licenses="MIT" \
    org.opencontainers.image.version="17.3.0" \
    org.opencontainers.image.url="https://owasp-juice.shop" \
    org.opencontainers.image.source="https://github.com/juice-shop/juice-shop" \
    org.opencontainers.image.revision=$VCS_REF \
    org.opencontainers.image.created=$BUILD_DATE

WORKDIR /juice-shop

# Copy full app build and dependencies
COPY --from=installer --chown=65532:0 /juice-shop .

USER 65532

EXPOSE 3000
CMD ["/juice-shop/build/app.js"]
