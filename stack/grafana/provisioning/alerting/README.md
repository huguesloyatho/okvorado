# Provisioning des alertes Grafana

Ce dossier est monté par `stack/docker-compose.yml`
(`./grafana/provisioning:/etc/grafana/provisioning:ro`) sur
`/etc/grafana/provisioning/alerting` — Grafana le scanne au démarrage et
provisionne règles d'alerte, contact points et politiques de notification
automatiquement, sans le moindre clic.

## Pourquoi un `.template` + un générateur, pas un YAML statique

Grafana ne résout **aucune** substitution `${VAR}` dans ses fichiers de
provisioning — vérifié sur ce projet (2026-08-08) : `defaults.ini` ne porte
aucun réglage `expand_env`, et `docker exec stack-grafana-1 printenv` ne
montre que les `GF_*` que Docker Compose lui a explicitement passées.
Seul Docker Compose résout des `${VAR}` — et seulement dans
`docker-compose.yml` lui-même, jamais dans un fichier monté en lecture
seule. C'est exactement le même piège déjà documenté pour Akvorado
(`stack/config/outlet.yaml.template`, voir son en-tête).

Les seuils d'alerte doivent pourtant être **paramétrables par variable
d'environnement** (demande explicite). Solution retenue, cohérente avec
l'existant : ce dossier contient des `*.yaml.template` **versionnés**, et le
service `config-generator` du compose (déjà responsable de la génération
`outlet.yaml`) les résout via `envsubst` au démarrage, AVANT que Grafana ne
lise son dossier de provisioning. Les `.yaml` résolus sont **gitignorés**
(jamais versionnés avec un seuil figé) — seuls les `.template` le sont.

## Fichiers

- `alerte-exportateur-muet.yaml.template` — un routeur qui émettait et
  n'émet plus (signal n°1 sur un parc de 350 : un site tombé).
- `alerte-saturation-interface.yaml.template` — utilisation d'interface
  au-delà d'un seuil (InIfSpeed/OutIfSpeed).
- `alerte-chute-trafic.yaml.template` — effondrement du volume par rapport
  à la période précédente (signe d'un lien coupé).
- `contact-points.yaml.template` — canal de notification (webhook,
  paramétrable) où les alertes déclenchées sont envoyées.
- `notification-policies.yaml.template` — route toutes les alertes de ce
  provider vers le contact point ci-dessus.

## Variables d'environnement (voir `.env.example`)

| Variable | Défaut | Rôle |
|---|---|---|
| `ALERTE_EXPORTATEUR_MUET_MINUTES` | `15` | silence au-delà duquel un exportateur est dit muet |
| `ALERTE_SATURATION_INTERFACE_SEUIL_PCT` | `80` | seuil d'utilisation d'interface (%) |
| `ALERTE_CHUTE_TRAFIC_SEUIL_PCT` | `50` | chute de volume (%) vs la demi-heure précédente qui déclenche l'alerte |
| `ALERTE_NOTIFICATION_WEBHOOK_URL` | `http://localhost:9999/aucune-cible-configuree` | cible du contact point — inoffensive par défaut (URL locale non routée), à remplacer par la vraie cible (webhook Slack/Teams/ntfy/mail relay...) au déploiement réel |
