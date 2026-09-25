FROM python:3.12-slim

# FORWARDED_ALLOW_IPS: trust X-Forwarded-For from Traefik so rate limits see the real
# visitor IP. Safe because the container port is only reachable via the Traefik network.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    FLET_FORCE_WEB_SERVER=true \
    FLET_SERVER_IP=0.0.0.0 \
    FLET_SERVER_PORT=8000 \
    FORWARDED_ALLOW_IPS="*" \
    DATA_DIR=/data

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY app/ .

RUN useradd --create-home --uid 1000 flet \
    && mkdir -p /data && chown -R flet:flet /app /data
USER flet

VOLUME ["/data"]
EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/', timeout=4)" || exit 1

CMD ["python", "main.py"]
