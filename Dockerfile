FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV SECURE_SHARE_HOST=0.0.0.0
ENV SECURE_SHARE_PORT=8000
ENV SECURE_SHARE_DATA_DIR=/data
ENV SECURE_SHARE_MAX_REQUEST_MB=100

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential ca-certificates libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY secure_share_server.py ./

RUN useradd --create-home --shell /usr/sbin/nologin appuser \
    && mkdir -p /data \
    && chown appuser:appuser /data

USER appuser

EXPOSE 8000
VOLUME ["/data"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/health' % os.getenv('SECURE_SHARE_PORT', '8000'), timeout=3).read()"

CMD ["python", "secure_share_server.py"]
