#!/bin/sh
# Génère config/outlet.yaml ET les fichiers de provisioning d'alerte Grafana
# depuis leurs `.template` respectifs, en résolvant leurs `${VAR}`. Exécuté
# par le service `config-generator` du compose, AVANT que l'orchestrateur
# Akvorado ET Grafana ne démarrent (les deux en dépendent).
#
# POURQUOI CE SCRIPT (mesuré 2026-08-07, machine vierge) : Akvorado ne résout
# JAMAIS lui-même les `${VAR}` dans ses YAML (seul Docker Compose le fait, et
# seulement dans docker-compose.yml — jamais dans un fichier lu par le
# binaire Akvorado). La communauté SNMP est un secret d'authentification :
# elle ne doit JAMAIS apparaître en clair dans un YAML versionné. Ce script
# vit dans un fichier séparé (plutôt qu'inline dans `command:` du compose)
# précisément pour ne JAMAIS exposer un caractère `$` littéral à
# l'interpolation de Docker Compose lui-même — piège vécu en session : un `$`
# non doublé (`$$`) dans une commande YAML compose se fait remplacer par
# Docker Compose AVANT même d'atteindre ce script, avec la valeur (souvent
# vide) de la variable d'environnement de l'HÔTE qui lance `docker compose`,
# pas celle du conteneur. Ici, `${SNMP_COMMUNITY}` n'existe que dans ce
# fichier shell exécuté DANS le conteneur — jamais vu par le moteur compose.
#
# MÊME PIÈGE MESURÉ CÔTÉ GRAFANA (2026-08-08) : `defaults.ini` du conteneur
# `grafana/grafana:latest` ne porte aucun réglage `expand_env`, et
# `docker exec ... printenv` ne montre que les GF_* explicitement passées —
# Grafana ne résout AUCUNE `${VAR}` dans ses fichiers de provisioning. Les
# seuils d'alerte (demande : paramétrables par variable d'environnement)
# passent donc par le même mécanisme `.template` + génération ici, jamais
# par une hypothétique substitution native de Grafana.
#
# `sed` chaîné (pas `envsubst`) : cohérent avec la substitution unique
# ci-dessous, sans ajouter le paquet `gettext` à l'image Alpine seulement
# pour une poignée de variables connues à l'avance.
set -eu

sed "s#\${SNMP_COMMUNITY}#$SNMP_COMMUNITY#g" \
  /etc/akvorado/outlet.yaml.template > /etc/akvorado/outlet.yaml

# --- Credentials SNMPv3 (coexistence avec v2c, migration progressive) ------
# Akvorado ne résout aucune logique conditionnelle en YAML (cf. commentaires
# du gabarit) : c'est ICI, en shell, que la décision "ajouter une entrée v3
# ou pas" se prend. SNMP_V3_USERNAME vide = pas de migration v3 en cours,
# fail-safe = comportement identique à aujourd'hui (seul "::/0" en v2c).
#
# `credentials` est une MAP CIDR -> config (doc Akvorado officielle) : cette
# entrée v3 s'AJOUTE à côté de "::/0" v2c, elle ne le remplace jamais — c'est
# le mécanisme qui permet à v2c et v3 de coexister pendant la migration.
#
# `authentication-passphrase`/`privacy-passphrase` ne sont émises QUE si le
# protocole correspondant est renseigné (doc Akvorado : "if the previous
# value was set") — nécessaire pour couvrir noAuthNoPriv/authNoPriv sans
# écrire de clé de passphrase vide dans le YAML final.
if [ -n "${SNMP_V3_USERNAME:-}" ]; then
  # SNMP_V3_SUBNET est OBLIGATOIRE dès que SNMP_V3_USERNAME est renseigné —
  # PAS de repli sur "::/0" ici (contrairement au `::/0` légitime du v2c
  # ci-dessus) : "::/0" est DÉJÀ la clé de l'entrée v2c. Un repli silencieux
  # sur "::/0" produirait une DEUXIÈME entrée "::/0" dans la map YAML
  # `credentials` — clé dupliquée, le parseur YAML ne garde que la DERNIÈRE
  # (la v3), qui écraserait silencieusement le défaut v2c pour tout le parc
  # non encore migré. Zéro silencieux : on arrête la génération plutôt que
  # de produire ce résultat.
  if [ -z "${SNMP_V3_SUBNET:-}" ]; then
    echo "ERREUR: SNMP_V3_USERNAME est renseigne mais SNMP_V3_SUBNET est vide." >&2
    echo "  Sans sous-reseau explicite, l'entree v3 prendrait la cle \"::/0\"," >&2
    echo "  en collision avec l'entree v2c \"::/0\" deja presente (cle dupliquee" >&2
    echo "  dans la map YAML credentials => la v3 ecraserait silencieusement" >&2
    echo "  le defaut v2c pour tout le parc non migre). Renseigner" >&2
    echo "  SNMP_V3_SUBNET (ex: 10.99.0.0/24) dans .env." >&2
    exit 1
  fi
  bloc_v3="        ${SNMP_V3_SUBNET}:\\n          user-name: ${SNMP_V3_USERNAME}"
  if [ -n "${SNMP_V3_AUTH_PROTOCOL:-}" ]; then
    bloc_v3="${bloc_v3}\\n          authentication-protocol: ${SNMP_V3_AUTH_PROTOCOL}"
    if [ -n "${SNMP_V3_AUTH_PASSPHRASE:-}" ]; then
      bloc_v3="${bloc_v3}\\n          authentication-passphrase: \"${SNMP_V3_AUTH_PASSPHRASE}\""
    fi
  fi
  if [ -n "${SNMP_V3_PRIV_PROTOCOL:-}" ]; then
    bloc_v3="${bloc_v3}\\n          privacy-protocol: ${SNMP_V3_PRIV_PROTOCOL}"
    if [ -n "${SNMP_V3_PRIV_PASSPHRASE:-}" ]; then
      bloc_v3="${bloc_v3}\\n          privacy-passphrase: \"${SNMP_V3_PRIV_PASSPHRASE}\""
    fi
  fi
  sed -i "s#^.*__SNMP_V3_CREDENTIALS_PLACEHOLDER__.*\$#${bloc_v3}#" /etc/akvorado/outlet.yaml
else
  # Pas de migration v3 en cours : la ligne marqueur est retirée, `credentials`
  # ne contient que "::/0" en v2c — non-regression explicite du cas par
  # defaut (350 routeurs pas encore migres).
  sed -i "/__SNMP_V3_CREDENTIALS_PLACEHOLDER__/d" /etc/akvorado/outlet.yaml
fi

echo "outlet.yaml genere depuis outlet.yaml.template"

# --- Provisioning d'alerte Grafana ------------------------------------------
# Chaque *.yaml.template de ce dossier est résolu vers le même nom sans
# ".template", dans le dossier de sortie monté par Grafana (lecture seule).
# Les 4 variables sont TOUJOURS substituées, même si un fichier n'en utilise
# qu'une partie (sed sur une variable absente du fichier est un no-op).
for tpl in /etc/grafana-alerting-templates/*.yaml.template; do
  [ -e "$tpl" ] || continue
  out="/etc/grafana-alerting/$(basename "$tpl" .template)"
  sed \
    -e "s#\${ALERTE_EXPORTATEUR_MUET_MINUTES}#$ALERTE_EXPORTATEUR_MUET_MINUTES#g" \
    -e "s#\${ALERTE_SATURATION_INTERFACE_SEUIL_PCT}#$ALERTE_SATURATION_INTERFACE_SEUIL_PCT#g" \
    -e "s#\${ALERTE_CHUTE_TRAFIC_SEUIL_PCT}#$ALERTE_CHUTE_TRAFIC_SEUIL_PCT#g" \
    -e "s#\${ALERTE_NOTIFICATION_WEBHOOK_URL}#$ALERTE_NOTIFICATION_WEBHOOK_URL#g" \
    -e "s#\${ALERTE_DB_HEALTH_PARTS_ACTIVES_SEUIL}#$ALERTE_DB_HEALTH_PARTS_ACTIVES_SEUIL#g" \
    "$tpl" > "$out"
  echo "$(basename "$out") genere depuis $(basename "$tpl")"
done
