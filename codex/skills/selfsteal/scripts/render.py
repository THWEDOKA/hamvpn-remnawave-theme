"""Render public self-steal templates as JSON; never connect, deploy or write files."""

import argparse
import hashlib
import html
import ipaddress
import json
from pathlib import Path
import re
import unicodedata


ASSETS = Path(__file__).resolve().parents[1] / "assets"


def normalize_hostname(value):
    if (not isinstance(value, str) or value != value.strip() or not value
            or any(unicodedata.category(c).startswith("C") for c in value)):
        raise ValueError("hostname must be a fully qualified domain without whitespace")
    try:
        hostname = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ValueError("hostname cannot be encoded as IDNA") from None
    labels = hostname.split(".")
    if (len(hostname) > 253 or len(labels) < 2 or labels[-1].isdigit()
            or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                   for label in labels)):
        raise ValueError("hostname must be a domain, not an IP, URL, wildcard or path")
    return hostname


def validate_port(value, name):
    if type(value) is not int or not 1 <= value <= 65535 or value == 80:
        raise ValueError(f"{name} must be an integer in 1..65535 other than HTTP port 80")
    return value


def render(hostname, ipv4, site_title="Ремонт чайников", tls_port=8443, vpn_port=443):
    hostname = normalize_hostname(hostname)
    if not isinstance(ipv4, str):
        raise ValueError("ipv4 must be a dotted IPv4 address")
    try:
        ipv4 = str(ipaddress.IPv4Address(ipv4))
    except ipaddress.AddressValueError:
        raise ValueError("ipv4 must be a dotted IPv4 address") from None
    tls_port = validate_port(tls_port, "tls_port")
    vpn_port = validate_port(vpn_port, "vpn_port")
    if tls_port == vpn_port:
        raise ValueError("TLS target and public VPN ports must differ")
    if (not isinstance(site_title, str) or not 1 <= len(site_title.strip()) <= 100
            or any(unicodedata.category(c).startswith("C") for c in site_title)):
        raise ValueError("site_title must contain 1..100 visible characters, no controls")
    site_title = site_title.strip()
    origin = f"https://{hostname}" + (f":{vpn_port}" if vpn_port != 443 else "")
    root = f"/var/www/{hostname}"
    challenge = """    location ^~ /.well-known/acme-challenge/ {
        root /var/www/acme;
        default_type text/plain;
        try_files $uri =404;
    }
"""
    http = f"""server {{
    listen 80;
    server_name {hostname};
    root {root};
    index index.html;
    server_tokens off;
    charset utf-8;
{challenge}    location / {{ try_files $uri $uri/ =404; }}
    location ~ /\\. {{ deny all; }}
}}
"""
    cache = "SS" + hashlib.sha256(hostname.encode("ascii")).hexdigest()[:12]
    tls = f"""server {{
    listen 80;
    server_name {hostname};
    server_tokens off;
{challenge}    location / {{ return 301 {origin}$request_uri; }}
}}

# Public VPN port belongs to REALITY. Verify reachability from Xray's namespace.
server {{
    listen 127.0.0.1:{tls_port} ssl http2;
    server_name {hostname};
    root {root};
    index index.html;
    server_tokens off;
    charset utf-8;
    ssl_certificate /etc/letsencrypt/live/{hostname}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/{hostname}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:{cache}:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    add_header Content-Security-Policy "default-src 'none'; style-src 'self'; img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" always;
    location / {{ try_files $uri $uri/ =404; }}
    location ~ /\\. {{ deny all; }}
}}
"""
    dns = {"type": "A", "name": hostname, "content": ipv4, "ttl": 300, "proxied": False}
    return {
        "mode": "templates-only",
        "hostname": hostname,
        "ipv4": ipv4,
        "site_url": origin + "/",
        "local_tls_target": f"127.0.0.1:{tls_port}",
        "files": {
            "dns-record.json": json.dumps(dns, ensure_ascii=False, indent=2) + "\n",
            "nginx-http.conf": http,
            "nginx-tls.conf": tls,
            "site/index.html": (ASSETS / "index.html").read_text(encoding="utf-8").replace(
                "{{SITE_TITLE}}", html.escape(site_title, quote=True)),
            "site/style.css": (ASSETS / "style.css").read_text(encoding="utf-8"),
            "renew-nginx.sh": "#!/bin/sh\nset -eu\n/usr/sbin/nginx -t\n/usr/bin/systemctl reload nginx\n",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--hostname", required=True)
    parser.add_argument("--ipv4", required=True)
    parser.add_argument("--site-title", default="Ремонт чайников")
    parser.add_argument("--tls-port", type=int, default=8443)
    parser.add_argument("--vpn-port", type=int, default=443)
    args = parser.parse_args()
    try:
        result = render(**vars(args))
    except ValueError as exc:
        parser.error(str(exc))
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
