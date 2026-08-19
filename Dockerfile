FROM remnawave/backend@sha256:361f9bb0b183d4fcefea2f1f7163db490e2aa1ec3b4bdde016a9ab9229ce956b

LABEL org.opencontainers.image.source="https://github.com/THWEDOKA/hamvpn-remnawave-theme"
LABEL org.opencontainers.image.description="HAMVPN visual theme for Remnawave"
LABEL org.opencontainers.image.licenses="AGPL-3.0-only"

COPY public/hamvpn-mascot.png /opt/app/frontend/hamvpn/hamvpn-mascot.png
COPY theme/hamvpn-theme.css /opt/app/frontend/hamvpn/hamvpn-theme.css
COPY scripts/install-theme.sh /usr/local/bin/install-hamvpn-theme

RUN chmod 0755 /usr/local/bin/install-hamvpn-theme \
    && /usr/local/bin/install-hamvpn-theme \
    && rm /usr/local/bin/install-hamvpn-theme
