# ------------------------------------------------------------------------------
# Image de l'API backend
#
# Build :  docker build -t secrets-lab/api-backend:1.0.0 apps/backend
# Puis   :  kind load docker-image secrets-lab/api-backend:1.0.0 --name secrets-lab
#
# Choix : image non-root par construction (UID 10001), pas de shell utile en
# production, aucune dépendance de build conservée dans l'image finale.
# ------------------------------------------------------------------------------
FROM python:3.12-alpine AS base

RUN addgroup -g 10001 -S app \
 && adduser -u 10001 -S -G app -h /app app

WORKDIR /app

# psycopg[binary] : roues précompilées, pas de compilateur dans l'image
RUN pip install --no-cache-dir "psycopg[binary]==3.2.3"

COPY --chown=10001:10001 app.py /app/app.py

USER 10001:10001
EXPOSE 8080

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    SECRETS_DIR=/etc/app-secrets \
    APP_PORT=8080

# Pas de HEALTHCHECK ici : ce sont les probes Kubernetes qui font foi
# (readinessProbe / livenessProbe dans le Deployment).
ENTRYPOINT ["python", "/app/app.py"]
