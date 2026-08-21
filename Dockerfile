FROM node:22.18.0-bookworm-slim@sha256:0d130e2ee18e88e1561375276daced6bff032539200173f2daf48c2e33f38ff5 AS frontend-builder

WORKDIR /src

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/* \
    && git init \
    && git remote add origin https://github.com/remnawave/frontend.git \
    && git fetch --depth=1 origin 9d671520067f73b2beb96c282f2ce2ff7b7a9a00 \
    && git checkout --detach FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "9d671520067f73b2beb96c282f2ce2ff7b7a9a00"

COPY frontend/remnawave-2.8.1.patch /tmp/remnawave-2.8.1.patch

RUN git apply --check /tmp/remnawave-2.8.1.patch \
    && git apply /tmp/remnawave-2.8.1.patch \
    && npm ci \
    && npm run start:build

FROM remnawave/backend@sha256:361f9bb0b183d4fcefea2f1f7163db490e2aa1ec3b4bdde016a9ab9229ce956b

ARG VCS_REF=unknown

LABEL org.opencontainers.image.source="https://github.com/THWEDOKA/hamvpn-remnawave-theme"
LABEL org.opencontainers.image.description="HAMVPN visual theme for Remnawave"
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"
LABEL org.opencontainers.image.revision="$VCS_REF"

COPY --from=frontend-builder /src/dist/ /opt/app/frontend/
COPY public/hamvpn-mascot.png /opt/app/frontend/hamvpn/hamvpn-mascot.png
COPY theme/hamvpn-theme.css /opt/app/frontend/hamvpn/hamvpn-theme.css
COPY scripts/install-theme.sh /usr/local/bin/install-hamvpn-theme

RUN chmod 0755 /usr/local/bin/install-hamvpn-theme \
    && /usr/local/bin/install-hamvpn-theme \
    && rm /usr/local/bin/install-hamvpn-theme
