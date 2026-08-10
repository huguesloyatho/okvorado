# okvorado-restart-agent

Service HTTP minuscule, séparé d'Okvorado, dont l'unique raison d'être est de
porter l'accès au socket Docker qu'Okvorado n'a pas le droit d'avoir.

## Pourquoi cet agent existe

`/var/run/docker.sock` donne à qui le monte un accès équivalent à **root sur
l'hôte** (créer/détruire n'importe quel container, monter n'importe quel
volume du filesystem hôte, etc.). Okvorado est une application web exposée à
des utilisateurs via Authelia : lui donner ce socket transformerait n'importe
quelle faille applicative (XSS, SSRF, dépendance vulnérable, bug d'auth) en
compromission complète de l'hôte `routeur-agence-01`. C'est une règle non
négociable du projet (voir `../CONTRACT.md` et `app/config.py`).

Ce risque ne disparaît pas — il est **isolé**. Cet agent tourne dans son
propre container, sans jamais parler à un utilisateur final ni à Authelia. Il
n'expose qu'une capacité étroite : redémarrer un sous-ensemble figé de
containers Akvorado, derrière un token. La surface d'attaque du socket docker
se limite désormais à ce seul service, minuscule et auditable, plutôt qu'à
toute la surface HTTP d'Okvorado (routes, templates, dépendances tierces).

## Ce qu'il sait faire — et ce qu'il ne sait PAS faire

**Capacités** (voir `agent.py`, allowlist `ALLOWED_SERVICES`) :
- `POST /restart` — redémarre un ou plusieurs services parmi :
  `akvorado-outlet`, `akvorado-inlet`, `akvorado-orchestrator`,
  `akvorado-console`. Ordre déterministe (`orchestrator` en premier, il porte
  les migrations de schéma/config), attente du retour à `healthy` (timeout
  120 s par défaut), rapport détaillé par service. Accepte un champ optionnel
  `purge_metadata_cache` (défaut `false`) qui purge le cache de metadata
  Akvorado avant le redémarrage — voir section « Purge du cache de metadata »
  plus bas.
- `GET /status` — état courant (présence, statut, santé) des containers de
  l'allowlist.
- `GET /health` — liveness de l'agent lui-même, sans authentification.

**Ce qu'il refuse structurellement** :
- Tout nom de service hors de l'allowlist en dur → `403`, **avant** tout
  appel docker (aucune tentative, même en cas d'injection).
- **`clickhouse` est volontairement EXCLU de l'allowlist.** On ne redémarre
  jamais la base de données via cet agent : un restart ClickHouse mal
  maîtrisé (pendant une requête, une insertion Kafka en vol) risque une
  corruption ou une perte de données bien plus grave qu'un service applicatif
  qui redémarre. Un redémarrage ClickHouse reste possible, mais **manuel**,
  hors de cet agent.
- Aucune commande arbitraire, aucun `exec`, aucune création/suppression de
  container, aucune interpolation shell : le SDK Python `docker.from_env()`
  cible les containers uniquement par leurs labels compose
  (`com.docker.compose.project` / `com.docker.compose.service`) — jamais de
  `subprocess(shell=True)` ni de nom concaténé dans une commande.
- **Aucune suppression de fichier arbitraire.** Le seul fichier que l'agent
  peut supprimer est le cache de metadata, dont le chemin vient uniquement de
  la configuration serveur (jamais du corps de la requête HTTP) et doit
  satisfaire deux gardes (nom `metadata.cache`, répertoire
  `/data/akvorado/run`) avant tout `unlink()`. Voir « Purge du cache de
  metadata » plus bas.

## Déploiement

Prérequis : être sur `routeur-agence-01` (192.0.2.6), le réseau externe
`akvorado_default` doit déjà exister (créé par le stack Akvorado).

```bash
cd /root/okvorado/restart-agent   # ou l'équivalent du chemin de déploiement

# 1. Générer un token solide
openssl rand -hex 32

# 2. Créer le .env réel à partir de l'exemple
cp .env.example .env
# Éditer .env :
#   RESTART_AGENT_TOKEN=<le token généré ci-dessus>
#   DOCKER_SOCKET_GID=<sortie de: getent group docker | cut -d: -f3>

# 3. Démarrer
docker compose up -d --build

# 4. Vérifier que le container est up et healthy
docker compose ps
```

Le même `RESTART_AGENT_TOKEN` doit être renseigné côté Okvorado
(`OKVORADO_RESTART_AGENT_TOKEN` dans son `.env` / son compose), sans quoi
`app/clients/restart.py` refuse d'émettre la requête (`RuntimeError` fail-fast
côté client) et l'agent renverrait `401` de toute façon.

## Comment vérifier que ça marche

Le `/health` n'est pas authentifié et n'est joignable que depuis le réseau
`akvorado_default` (aucun port publié — voir plus bas) :

```bash
# Depuis un autre container du réseau akvorado_default (ex: okvorado lui-même)
docker exec okvorado curl -sf http://okvorado-restart-agent:8098/health
# Attendu : {"status":"ok","service":"okvorado-restart-agent"}
```

`/status` est authentifié — vérifie à la fois le token et l'accès réel au
socket docker (l'agent liste les containers de l'allowlist) :

```bash
docker exec okvorado curl -s \
  -H "Authorization: Bearer <RESTART_AGENT_TOKEN>" \
  http://okvorado-restart-agent:8098/status
# Attendu : {"status":"ok","items":[...4 entrées...],"total":4}
```

Un `401` sur `/status` avec un bon token signale un problème de token
(désynchronisé entre `.env` de l'agent et d'Okvorado). Une entrée `"status":
"absent"` dans la réponse signale que le container correspondant n'existe pas
sous ce nom de service compose sur cet hôte — à comparer avec `docker compose
-f /root/akvorado/docker-compose.yml ps`.

## Purge du cache de metadata (optionnelle, non activée par défaut)

Akvorado maintient un cache disque de metadata sur `routeur-agence-01`
(`/data/akvorado/run/metadata.cache` par défaut) qui mémorise la
correspondance `ifIndex → nom d'interface + boundary`. Ce cache est
**persistant entre redémarrages** : un simple `restart` de l'outlet ne le
vide pas.

**Pourquoi c'est un piège** : après une correction d'ifIndex dans
`outlet.yaml` (ex : l'ifIndex de `tailscale0` change à chaque redémarrage du
démon Tailscale) suivie d'un restart classique de l'outlet, les flux
continuent d'être classés `InIfName=unknown` / `InIfBoundary=undefined`. La
correction du YAML est **sans effet visible** tant que ce cache n'est pas
purgé — l'outlet réutilise l'ancienne correspondance qu'il a en mémoire
disque au lieu de relire `outlet.yaml` à froid. Vécu en production : ifIndex
corrigé, outlet redémarré et `healthy`, mais 335 flux/60s toujours
`unknown/undefined` — le cache datait d'avant la correction.

**Ce que fait la purge** : `POST /restart` accepte un champ optionnel
`purge_metadata_cache` (défaut `false`). Quand il vaut `true`, la séquence
pour chaque service concerné devient **stop → suppression du fichier de
cache → start** (au lieu d'un simple `restart()`) — voir `agent.py:
restart_service`. L'ordre est délibéré : purger un cache pendant que
l'outlet tourne ne sert à rien, il le réécrit ; il faut que le service soit
arrêté avant la suppression, et la suppression doit avoir lieu avant le
redémarrage effectif pour que l'outlet reparte à froid.

**Pourquoi ce n'est PAS activé par défaut** : la purge n'est nécessaire que
lors d'un changement de topologie réseau (correction d'ifIndex, ajout/retrait
d'interface). Un restart classique (bump de version, récupération d'un crash,
changement de config sans impact sur les interfaces) n'a besoin d'aucune
purge, et purger à chaque restart ferait perdre inutilement tout le cache
accumulé (latence de reconstruction à froid). C'est donc un geste conscient
de l'opérateur, jamais une conséquence implicite d'un simple restart.

**Log normal au démarrage sans cache** : `cannot load cache, ignoring` dans
les logs de l'outlet juste après une purge (ou au tout premier démarrage,
avant que le fichier n'existe) est **attendu**, pas une erreur — l'outlet
reconstruit le cache en mémoire au fil des flux reçus.

**Garde de sécurité sur le chemin** : le chemin du fichier purgé vient
**uniquement** de la configuration serveur (`METADATA_CACHE_PATH`, défaut
`/data/akvorado/run/metadata.cache`) — jamais du corps de la requête HTTP.
`resolve_metadata_cache_path` (agent.py) refuse tout chemin qui ne se termine
pas par `metadata.cache` ou qui ne se trouve pas sous `/data/akvorado/run`
une fois résolu, avant tout `unlink()`. Un fichier absent n'est pas une
erreur (premier démarrage). Un échec de suppression (droits) est signalé
dans le rapport (`cache_purged: false` + message) mais **ne bloque jamais le
restart** : mieux vaut un restart sans purge qu'un service resté arrêté.

Le montage du répertoire `/data/akvorado/run` (voir `docker-compose.yml`) est
en écriture pour permettre cette suppression, mais reste borné à ce seul
répertoire — l'agent ne monte ni `/data/akvorado` en entier, ni aucun autre
chemin de l'hôte, et la garde de code applicative empêche toute suppression
en dehors de ce répertoire même en cas de mauvaise configuration.

**Permissions à vérifier avant premier usage réel** : supprimer un fichier
(`unlink`) dépend du droit d'**écriture sur le répertoire parent**, pas des
permissions du fichier lui-même. Le fichier `metadata.cache` appartient
généralement à `root:root` sur l'hôte, mais ce n'est pas ce qui compte — ce
qui compte est le mode de `/data/akvorado/run` lui-même. L'agent tourne en
uid 10001 (Dockerfile, aucun rapport avec le GID docker injecté par
`group_add`, qui ne sert qu'au socket) :
- si `/data/akvorado/run` est en `755` root:root (cas courant), **uid 10001
  ne pourra PAS supprimer le fichier** (ni owner ni dans le groupe) — la
  purge échouera à `unlink()`, sera reportée dans `cache_purge_message` sans
  bloquer le restart (comportement attendu, dégradé mais sûr) ;
- pour que la purge fonctionne réellement, il faut, côté hôte
  `routeur-agence-01`, soit `chmod g+w /data/akvorado/run` avec un groupe
  incluant le GID 10001, soit un ACL POSIX dédié (`setfacl -m u:10001:rwx
  /data/akvorado/run`) — à faire par l'opérateur du déploiement, pas par ce
  code.

## Modèle de sécurité

- **Authentification** : token statique unique (`RESTART_AGENT_TOKEN`),
  header `Authorization: Bearer <token>`, comparaison en **temps constant**
  (`hmac.compare_digest`) pour éviter les attaques par timing. Absence du
  token en variable d'env au démarrage → l'agent **refuse de démarrer**
  (fail-fast, jamais de mode sans authentification).
- **Rate-limit** : un seul restart accepté toutes les 30 secondes (défaut) ;
  un appel trop rapproché reçoit `429`. Limite l'impact d'un token compromis
  utilisé en boucle et absorbe les double-clics accidentels côté UI.
- **Aucun port publié sur l'hôte.** Le compose ne déclare volontairement
  aucune section `ports:`. Publier ce service (même sur un port non standard
  comme `8098`) le rendrait joignable par **tout le mesh Tailscale**
  (`100.64.0.0/10`), pas seulement par Okvorado — un simple token statique
  glané ou deviné suffirait alors depuis n'importe quelle machine du tailnet
  pour déclencher un restart de la stack Akvorado. En restant uniquement sur
  le réseau docker `akvorado_default`, seuls les containers qui y sont
  explicitement rattachés peuvent même tenter de le joindre.
- **Allowlist en dur, non paramétrable à l'exécution.** Aucune variable
  d'environnement, aucun endpoint n'étend la liste des services
  redémarrables : c'est une constante Python (`ALLOWED_SERVICES` dans
  `agent.py`), donc un changement de périmètre exige un changement de code
  revu, pas une simple reconfiguration.
- **Journalisation** : chaque tentative (refusée ou acceptée) est loggée avec
  contexte (`log.error()` sur les échecs — token invalide, service hors
  allowlist, rate-limit, échec de restart, non-retour à `healthy`).

**Limites assumées** (à ne pas perdre de vue) :
- N'importe quel container placé sur le réseau `akvorado_default` **et** en
  possession du token peut déclencher un restart — le réseau docker n'est pas
  une frontière d'authentification en soi, seulement une réduction de surface
  (pas de port publié). Le token reste la seule barrière réelle : le protéger
  comme un secret de prod (jamais commité, jamais loggé, jamais dans une URL).
- Le rate-limit est en mémoire process : un restart de l'agent lui-même
  réinitialise le compteur. Acceptable ici (l'allowlist et le token restent
  les gardes principales), mais à savoir en cas d'audit.
- Le socket docker monté donne techniquement à l'agent la capacité de faire
  bien plus que ce que `agent.py` implémente aujourd'hui (le code applique la
  restriction, pas le montage). Toute évolution de `agent.py` doit donc rester
  sous la même revue de sécurité que le code originel.

## Choix utilisateur / permissions sur le socket docker

Le Dockerfile fait tourner le process sous un utilisateur dédié non-root
(`restart-agent`, uid 10001) — **pas root**, malgré le montage du socket.

Le socket `/var/run/docker.sock` appartient côté hôte au groupe `docker`
(généralement GID 999 ou 998, jamais garanti identique d'une machine à
l'autre). Pour que l'utilisateur applicatif non-root puisse ouvrir ce socket
sans élever le process à root, le compose utilise `group_add` avec le GID
réel du groupe `docker` de l'hôte, injecté via la variable d'environnement
`DOCKER_SOCKET_GID` (voir `.env.example`) plutôt que figé en dur dans l'image
— le GID n'est pas portable entre hôtes et le figer casserait le déploiement
sur toute machine où il diffère.

Alternative écartée : faire tourner tout le container en root. Root dans le
container + socket docker monté équivaut de toute façon à root sur l'hôte
(on peut lancer un container privilégié qui monte `/`), donc le gain de
`group_add` sur le **risque du socket lui-même** est nul — la restriction
Docker ne protège pas contre ce vecteur, avec ou sans root applicatif. Le
choix `group_add` + uid dédié reste néanmoins préférable en défense en
profondeur : il élimine toute élévation *additionnelle* qui proviendrait d'un
bug non lié au socket (écriture hors de `/app`, exploitation d'une dépendance
qui suppose des droits root, primitive d'écriture fichier détournée) — ce que
`useradd --uid 10001` + `USER restart-agent` garantit indépendamment de la
question du socket.

## Ce qui n'a pas pu être vérifié depuis ce poste

- `docker compose config` a été exécuté et validé en local (syntaxe et
  résolution de variables OK — voir rapport de livraison), mais **aucun
  déploiement réel** n'a été fait depuis ce poste : ni build de l'image, ni
  `docker compose up`, ni test HTTP contre un agent réellement démarré sur
  `routeur-agence-01`. La valeur réelle de `DOCKER_SOCKET_GID` sur cet hôte
  n'a pas été vérifiée (à obtenir via `getent group docker | cut -d: -f3`
  avant le premier déploiement).
