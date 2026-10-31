# Ghostwall: ghost-dns in shadow mode + the dashboard. See compose.yaml.
FROM python:3.12-slim

WORKDIR /opt/ghostwall
COPY requirements.txt .
RUN pip install --no-cache-dir --disable-pip-version-check -r requirements.txt

COPY ghostwall/models ghostwall/models
COPY agents/ghost_dns agents/ghost_dns
COPY agents/web_ui agents/web_ui
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && rm -rf agents/*/tests

ENV PYTHONUNBUFFERED=1
VOLUME /data
EXPOSE 8088
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5380/status', timeout=4)"
ENTRYPOINT ["/entrypoint.sh"]
