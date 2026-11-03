# Ghostwall: ghost-dns in shadow mode + the dashboard (+ Telegram alerts once set up). See compose.yaml.
# Pinned by digest: the same base image on every build. Dependabot proposes bumps
# (.github/dependabot.yml; it reads a literal FROM, not one built from an ARG).
# Rate-limited by Docker Hub? Use Google's mirror of it for every pull: add
# "registry-mirrors": ["https://mirror.gcr.io"] to /etc/docker/daemon.json.
FROM python:3.15.0-slim-bookworm@sha256:0e019bbdfb5d9874cb2389f1c2884b64aa2ac97c99960b5bc521cef978c0617d

WORKDIR /opt/ghostwall
COPY requirements.lock .
RUN pip install --no-cache-dir --disable-pip-version-check --require-hashes -r requirements.lock

COPY pyproject.toml .
COPY ghostwall/models ghostwall/models
COPY agents/ghost_dns agents/ghost_dns
COPY agents/web_ui agents/web_ui
COPY agents/fw_bot agents/fw_bot
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && rm -rf agents/*/tests \
 && printf '#!/bin/sh\nexec python /opt/ghostwall/agents/ghost_dns/ghostwall_cli.py "$@"\n' > /usr/local/bin/ghostwall \
 && chmod 755 /usr/local/bin/ghostwall

# ORT_DISABLE_TELEMETRY: onnxruntime sends usage telemetry to Microsoft unless told not to.
# GHOSTWALL_DATA/ETC: where `python agents/ghost_dns/ghostwall_cli.py` finds things here.
ENV PYTHONUNBUFFERED=1 ORT_DISABLE_TELEMETRY=1 GHOSTWALL_DATA=/data GHOSTWALL_ETC=/data GHOSTWALL_DOCKER=1
VOLUME /data
EXPOSE 8088
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5380/status', timeout=4)"
ENTRYPOINT ["/entrypoint.sh"]
