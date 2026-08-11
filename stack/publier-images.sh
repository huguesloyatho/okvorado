#!/usr/bin/env bash
# Publie sur Docker Hub les deux images dont un serveur d'entreprise a besoin :
#
#   1. okvorado           — l'application (elle n'existe sur AUCUN registre public)
#   2. akvorado-amd64     — Akvorado `main` RE-ÉTIQUETÉE en amd64 STANDARD
#
# POURQUOI L'IMAGE 2 EXISTE (défaut mesuré le 2026-08-11 sur un serveur réel) :
#   `docker compose up -d` échouait sur
#       no matching manifest for linux/amd64 in the manifest list entries
#   alors que le CPU exposait bien AVX2. Cause : `quay.io/akvorado/akvorado:main`
#   n'est publiée QUE en variante `linux/amd64/v3`. Docker refuse au niveau du
#   MANIFESTE, avant même de regarder le binaire — le contrôle AVX2 documenté
#   dans le README ne suffit donc pas à prédire l'échec : v3 exige AVX+AVX2+BMI1+
#   BMI2+F16C+FMA+LZCNT+MOVBE, et il suffit qu'une seule manque.
#
#   Le tag `latest` n'est PAS une solution : mesuré, il porte v2.4.1, qui REJETTE
#   la configuration de ce stack (invalid key geoip / kafkainput / networks).
#
#   La parade : tirer l'image v3 en forçant `--platform`, la republier sous un
#   manifeste amd64 standard. Le binaire est le même — seule l'étiquette change,
#   et c'est elle seule qui bloquait.
#
# USAGE :
#   docker login                      # une fois, la session expire
#   ./publier-images.sh               # defaut : compte hugues64100
#   ./publier-images.sh <compte> <tag>  # pour surcharger
#
# Prérequis : `docker login` déjà fait, et buildx disponible.

set -euo pipefail

COMPTE="${1:-hugues64100}"
TAG="${2:-latest}"
RACINE="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

AKVORADO_SOURCE="quay.io/akvorado/akvorado:main"
IMG_OKVORADO="docker.io/${COMPTE}/okvorado:${TAG}"
IMG_AKVORADO="docker.io/${COMPTE}/akvorado-amd64:${TAG}"

echo "=== 1/3 — Okvorado : build linux/amd64 et publication ==="
echo "    cible : ${IMG_OKVORADO}"
# --platform explicite : la station de build peut être en arm64 (Apple Silicon),
# auquel cas une image construite sans cette option serait INUTILISABLE sur le
# serveur x86 — et l'erreur n'apparaîtrait qu'au démarrage, pas au push.
docker buildx build \
  --platform linux/amd64 \
  --file "${RACINE}/Dockerfile" \
  --tag "${IMG_OKVORADO}" \
  --push \
  "${RACINE}"

echo
echo "=== 2/3 — Akvorado : re-étiquetage en amd64 standard ==="
echo "    source : ${AKVORADO_SOURCE} (variante v3)"
echo "    cible  : ${IMG_AKVORADO} (manifeste amd64 standard)"
# `--platform linux/amd64/v3` est OBLIGATOIRE ici : sans lui, le pull échoue
# exactement comme sur le serveur du client. On demande explicitement la seule
# variante publiée, puis on la republie sans contrainte de variante.
docker pull --platform linux/amd64/v3 "${AKVORADO_SOURCE}"
docker tag "${AKVORADO_SOURCE}" "${IMG_AKVORADO}"
docker push "${IMG_AKVORADO}"

echo
echo "=== 3/3 — Vérification des manifestes publiés ==="
for img in "${IMG_OKVORADO}" "${IMG_AKVORADO}"; do
  printf '    %-45s ' "${img}"
  docker manifest inspect "${img}" 2>/dev/null | python3 -c "
import sys, json
d = json.load(sys.stdin)
plats = []
for m in d.get('manifests', [d]):
    p = m.get('platform', {})
    if p.get('architecture'):
        plats.append(p['architecture'] + ('/' + p['variant'] if p.get('variant') else ''))
    else:
        plats.append(d.get('architecture', '?'))
print(', '.join(plats) or '?')
" || echo "ÉCHEC"
done

echo
echo "Terminé. Sur le serveur d'entreprise, renseigner dans stack/.env :"
echo "    OKVORADO_IMAGE=${IMG_OKVORADO}"
echo "    AKVORADO_IMAGE=${IMG_AKVORADO}"
echo "puis : docker compose up -d"
