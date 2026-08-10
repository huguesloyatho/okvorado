FROM python:3.13-slim

# Agent de restart Akvorado — service séparé d'Okvorado, SEUL à monter
# /var/run/docker.sock (voir README.md pour le pourquoi). Base alignée sur le
# Dockerfile racine d'Okvorado pour rester cohérent sur l'infra.

WORKDIR /app

# Dépendances d'abord : couche mise en cache tant que requirements.txt ne change pas.
COPY requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

COPY agent.py ./

# Utilisateur dédié non-root, membre du groupe `docker` de l'hôte via
# `group_add` au niveau compose (voir README.md pour l'argumentaire complet).
# L'UID/GID applicatif (10001) est fixe et sans rapport avec le GID du
# groupe `docker` de l'hôte (généralement 999 ou 998), injecté à l'exécution.
RUN useradd --create-home --uid 10001 restart-agent
USER restart-agent

ENV PYTHONUNBUFFERED=1

EXPOSE 8098

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8098/health', timeout=4).status==200 else 1)"

CMD ["uvicorn", "agent:app", "--host", "0.0.0.0", "--port", "8098"]
