FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /srv

RUN adduser --disabled-password --gecos "" appuser

COPY pyproject.toml README.md ./
COPY src ./src
COPY config ./config
COPY db ./db
COPY scripts ./scripts
RUN pip install --no-cache-dir .

USER appuser

# Overridden by docker-compose for the beat / migrate services.
CMD ["celery", "-A", "src.celery_app:celery_app", "worker", "--loglevel=info"]
