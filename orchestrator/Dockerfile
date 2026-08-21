FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --disable-pip-version-check -r /app/requirements.txt \
    && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin infrastructure

COPY app /app/app
COPY static /app/static

USER 10001:10001
EXPOSE 8090

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8090", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]

