# Ghostwall: ghost-dns in shadow mode + the dashboard. See compose.yaml.
# Pinned by digest: the same base image on every build (bump it deliberately). Rate-limited
# by Docker Hub? The same digest from a mirror works too:
#   docker build --build-arg BASE=mirror.gcr.io/library/python@sha256:e697c818... .
ARG BASE=python:3.12.16-slim-bookworm@sha256:e697c81897302a4c4333bade000d98038fbb21eb064f8ee1fd42d02ebcd9d337
FROM ${BASE}

WORKDIR /opt/ghostwall
COPY requirements.lock .
RUN pip install --no-cache-dir --disable-pip-version-check --require-hashes -r requirements.lock

COPY ghostwall/models ghostwall/models
COPY agents/ghost_dns agents/ghost_dns
COPY agents/web_ui agents/web_ui
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && rm -rf agents/*/tests

# ORT_DISABLE_TELEMETRY: onnxruntime sends usage telemetry to Microsoft unless told not to.
ENV PYTHONUNBUFFERED=1 ORT_DISABLE_TELEMETRY=1
VOLUME /data
EXPOSE 8088
HEALTHCHECK --interval=60s --timeout=5s --start-period=30s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5380/status', timeout=4)"
ENTRYPOINT ["/entrypoint.sh"]
