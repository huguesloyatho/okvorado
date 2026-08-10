FROM python:3.13-slim

# Okvorado doit rejoindre le réseau docker du stack akvorado : ClickHouse (8123)
# et l'outlet (8080) ne sont volontairement PAS exposés sur l'hôte
# (mesuré : "8123/tcp": null). Voir docker-compose.yml.

WORKDIR /app

# Dépendances d'abord : couche mise en cache tant que pyproject.toml ne change pas.
COPY pyproject.toml README.md ./
COPY app ./app
# Repli embarqué du catalogue applicatif (registre IANA officiel, ~11 600
# lignes) — DONNÉE DE SOURCE versionnée dans le dépôt (app/services/app_catalog.py
# la lit à `/app/data/...`), à ne pas confondre avec le VOLUME runtime monté
# sur `/data` (base SQLite, config générée) par docker-compose.yml. Sans ce
# COPY, l'image ne contient QUE le code : le premier démarrage d'un poste
# sans accès Internet sortant (proxy d'entreprise, cas SFR) se retrouverait
# avec un catalogue vide malgré le repli censé le couvrir — défaut mesuré au
# premier déploiement (2026-08-08).
COPY data/iana_service_names_fallback.csv ./data/iana_service_names_fallback.csv
# Catalogue GRAND PUBLIC (BitTorrent, Spotify, Teams/Zoom, appel WiFi/VoWiFi,
# jeux, cloud, VPN, IoT...) — même raisonnement que ci-dessus : sans ce COPY,
# `seed_grand_public_defaults()` échouerait silencieusement au démarrage
# (fichier absent -> retour 0, dégradation gracieuse mais catalogue non
# amorcé) sur un poste sans accès Internet sortant.
COPY data/grand_public_fallback.csv ./data/grand_public_fallback.csv
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir .

# Utilisateur non privilégié — l'app n'a besoin d'aucun droit root.
RUN useradd --create-home --uid 10001 okvorado \
 && mkdir -p /data \
 && chown -R okvorado:okvorado /app /data
USER okvorado

ENV OKVORADO_SQLITE_PATH=/data/okvorado.db \
    PYTHONUNBUFFERED=1

EXPOSE 8099

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8099/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8099"]
