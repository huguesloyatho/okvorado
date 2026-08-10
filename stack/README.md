# Okvorado — stack clé en main

Collecteur NetFlow/IPFIX/sFlow open-source, avec auto-découverte des routeurs
et complétion SNMP — sans devoir déclarer un seul exportateur à la main.

Cible : remplacer une solution NetFlow propriétaire sur un parc de plusieurs
centaines de routeurs. Comportement attendu, identique à un wizard NetFlow
classique : on pointe les routeurs vers ce collecteur, ils apparaissent
seuls dans la console ; on active SNMP pour qu'il complète les noms
d'interface, la vitesse, la description — rien d'autre à faire.

## Ce qu'on installe

| Composant | Rôle |
|---|---|
| `akvorado-inlet` | reçoit les flux NetFlow v9 / IPFIX / sFlow des routeurs (UDP) |
| `kafka` | tampon entre la réception et l'écriture disque |
| `akvorado-outlet` | décode les flux, résout les interfaces (SNMP), écrit ClickHouse |
| `clickhouse` | entrepôt des flux (un seul nœud suffit, voir dimensionnement dans le YAML) |
| `akvorado-orchestrator` | distribue la configuration aux autres composants |
| `akvorado-console` | interface web native Akvorado (exploration, filtres) |
| `redis` (valkey) | cache de la console |
| `grafana` | tableaux de bord graphiques (courbes, donuts, répartitions) |
| `okvorado` | configuration à l'écran + diagnostics de convergence de trafic |

Aucune dépendance à une infrastructure préexistante : pas de VPN mesh, pas
de reverse proxy, pas de registre d'image privé, pas de système d'identité
externe. Toutes les images sont publiques (quay.io, docker.io). Ce stack
démarre sur une machine Linux nue avec Docker et Docker Compose installés.

## Prérequis

- Docker + Docker Compose v2
- Une machine avec au moins 4 Go de RAM disponible et quelques dizaines de
  Go d'espace disque (le volume réel dépend du nombre de routeurs et du
  taux d'échantillonnage — voir la section Dimensionnement plus bas)
- Les ports UDP 2055 (NetFlow/IPFIX), 4739 (IPFIX) et 6343 (sFlow) accessibles
  depuis les routeurs à superviser
- Le port SNMP (161/UDP, sortant depuis cette machine) accessible vers les
  mêmes routeurs, pour la complétion automatique des interfaces

> ⚠️ **CPU x86-64 : vérifier le support AVX2 AVANT le premier `up -d`.**
> L'image `quay.io/akvorado/akvorado:main` (utilisée par défaut par les
> services `akvorado-orchestrator`/`akvorado-console`/`akvorado-inlet`/
> `akvorado-outlet`) n'est publiée qu'en `linux/amd64` variant **v3**, qui
> exige un CPU annonçant **AVX2** (Intel Haswell 2013+ / AMD Excavator
> 2015+). MESURÉ sur deux machines réelles (2026-08-08) :
>   - CPU physique i7-11700KF (AVX2 présent) → `docker pull` OK.
>   - VM QEMU avec un modèle de CPU générique (« Virtual CPU version 2.5+ »,
>     AVX2 absent bien que le CPU hôte le supporte) → `docker pull` ÉCHOUE
>     avec `no matching manifest for linux/amd64 in the manifest list entries`.
>
> Le second cas est **fréquent en entreprise** : une VM dont l'hyperviseur
> expose un CPU générique par défaut masque les instructions modernes de
> l'hôte physique, même si celui-ci les possède réellement. Sur une machine
> cible inconnue, vérifier AVANT de cloner :
>
> ```bash
> grep -o avx2 /proc/cpuinfo | head -1   # "avx2" affiché = OK, sinon vide = KO
> ```
>
> Si absent (cas typique d'une VM) : configurer l'hyperviseur pour exposer le
> CPU réel — **Proxmox/QEMU** : `cpu: host` dans la config de la VM ; **VMware** :
> mode de compatibilité EVC au moins **Haswell** — puis relancer. Aucune
> modification de `docker-compose.yml` n'est nécessaire une fois le CPU
> correctement exposé. Un tag stable (`2.4.1`) n'a pas cette contrainte mais
> **rejette la configuration de ce stack** (schéma YAML différent, testé) —
> ce n'est pas une alternative valable ici.

## Démarrer

**Le seul paramètre à connaître avant de démarrer : le port NetFlow.** Par
défaut ce stack écoute sur le port UDP **2055** (`NETFLOW_PORT`), plus 4739
pour l'IPFIX (`IPFIX_PORT`) et 6343 pour le sFlow (`SFLOW_PORT`). Il n'y a
qu'une seule raison d'y toucher : un conflit de port sur cette machine (un
autre collecteur y écoute déjà), ou un parc de routeurs configuré pour
émettre sur un port non standard. Dans ce cas, créer un `.env` (copie de
`.env.example`) et ajuster la variable concernée avant le premier démarrage.
Dans tous les autres cas, aucun fichier `.env` n'est nécessaire.

```bash
git clone <ce dépôt>
cd okvorado/stack
docker compose up -d
```

C'est tout. `.env.example` documente un défaut FONCTIONNEL pour chaque
variable (voir le fichier) — le stack démarre sans `.env` du tout. Créer un
`.env` sert uniquement à PERSONNALISER un réglage (port en conflit, mot de
passe Grafana, identifiants Okvorado, communauté SNMP du parc réel), jamais
à débloquer un démarrage qui serait autrement bloqué.

> **Avant toute exposition réseau au-delà du poste d'administration** :
> changer `GRAFANA_ADMIN_PASSWORD` (défaut `admin`, le défaut Grafana
> lui-même) ET `OKVORADO_AUTH_PASSWORD` (défaut `changeme`) — voir la
> section « Mise en production » plus bas pour la liste complète.

### Vérifier que ça marche

```bash
docker compose ps
# Tous les services doivent afficher "healthy" ou "running" après ~1 minute.
```

Puis, dès qu'un premier routeur pointe vers cette machine (voir « Pointer un
routeur » plus bas) :

- Ouvrir Grafana : http://<cette-machine>:3000 (port ajustable via
  `GRAFANA_PORT`) — le dashboard d'accueil affiche le trafic dès que les
  premiers flux arrivent.
- `docker compose logs -f akvorado-inlet` : une ligne par flux reçu confirme
  que les paquets UDP arrivent bien sur le port configuré.

## Accès aux interfaces

Deux interfaces distinctes, chacune avec son rôle :

- **Grafana** — http://<cette-machine>:3000 (port ajustable via
  `GRAFANA_PORT`) : les tableaux de bord (courbes, donuts, répartitions,
  saturation d'interface). S'ouvre directement sur le dashboard d'accueil
  (`GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH`), authentifié par le compte
  admin Grafana (`GRAFANA_ADMIN_PASSWORD`).
- **Okvorado** — http://127.0.0.1:8000 par défaut (port ajustable via
  `OKVORADO_PORT`) : la configuration à l'écran et les diagnostics de
  convergence que Grafana ne sait pas produire. Protégé par sa PROPRE
  authentification (page de connexion, session, TOTP activable — identifiants
  initiaux `OKVORADO_AUTH_USER` / `OKVORADO_AUTH_PASSWORD` dans `.env`).

Le port Okvorado est lié à **127.0.0.1** par défaut
(`OKVORADO_BIND_ADDRESS`) : joignable uniquement depuis cette machine, ou un
reverse proxy qui y tourne — pas depuis le reste du réseau, même si
l'authentification applicative est déjà en place. Voir « Mise en
production » plus bas pour le cas d'un reverse proxy sur une autre machine.

Ni la console Akvorado ni l'outlet ne publient de port sur l'hôte (ils
tournent toujours, joignables seulement sur le réseau docker interne du
stack — l'outlet n'expose que des métriques Prometheus internes, pas une
interface humaine).

**La console Akvorado reste accessible — À TRAVERS Okvorado, en proxy**
(`app/routers/proxy_akvorado.py`, ajouté le 2026-08-09) : ouvrir
`http://127.0.0.1:8000/akvorado-console` relaie transparemment vers
`akvorado-console:8080` sur le réseau docker interne, DERRIÈRE
l'authentification d'Okvorado — la console hérite d'une protection qu'elle
n'a jamais eue nativement. Décision retenue après l'échec du proxy Grafana
ci-dessous : Okvorado est du code maison, libre d'adapter sa CSP pour ce seul
chemin (`app/main.py::add_security_headers`), contrairement à Grafana qui
impose une CSP `sandbox` non contournable.

**La console est INTÉGRÉE dans Okvorado (2026-08-10)** : l'onglet
« Akvorado » du menu mène à l'écran `/akvorado`
(`app/routers/console_embed.py`), qui affiche la console SOUS la barre de
navigation d'Okvorado, dans un `<iframe>` même origine pointant sur le proxy.
L'exploitant ne quitte plus l'application — auparavant ce lien portait
`target="_blank"` et ouvrait un onglet séparé.

Trois points de cette intégration, chacun décidé par une mesure :

- **Iframe plutôt que rendu direct du HTML proxifié.** La console est une SPA
  Vue dont les chemins se résolvent contre une balise `<base href>` que le
  proxy réécrit. L'injecter dans un gabarit Jinja mettrait deux `<base>` et
  deux racines de document concurrentes dans une même page ; l'iframe lui
  laisse son propre document, donc son routeur et ses appels d'API intacts.
- **Deux en-têtes bloquaient l'encadrement**, tous deux corrigés pour la
  seule origine d'Okvorado : `X-Frame-Options` venant de l'amont n'était pas
  filtré et est désormais retiré des réponses du proxy (la politique de
  cadrage effective reste `frame-ancestors`, seul mécanisme capable
  d'exprimer une allowlist) ; et `frame-ancestors` s'est vu ajouter `'self'`
  — sans lui, Okvorado ne pouvait pas encadrer sa propre réponse de proxy et
  le cadre restait blanc alors que le proxy répondait 200. Jamais de `*` :
  les origines configurées via `OKVORADO_FRAME_ANCESTORS` sont conservées
  telles quelles, `'self'` est ajouté, pas substitué.
- **Zéro silencieux.** Un iframe dont la source ne répond pas rend un cadre
  blanc, indiscernable d'une page qui charge. L'écran SONDE donc la console
  avant de rendre le cadre : si elle ne répond pas (ou répond ≥ 500), aucun
  iframe n'est rendu — l'écran affiche « Console Akvorado indisponible »
  avec LA CAUSE (erreur de connexion, ou code HTTP reçu).

**Exposition réseau de la console — vérifié le 2026-08-10.** Le service
`akvorado-console` de `stack/docker-compose.yml` ne déclare AUCUNE section
`ports:` : il n'est donc joignable que sur le réseau docker interne du stack.
Les deux seuls chemins vers la console sont l'écran `/akvorado` et le proxy
`/akvorado-console`, tous deux servis par Okvorado et montés DERRIÈRE le
middleware `require_authentication` (`app/main.py`) — ils ne figurent dans
aucune allowlist publique (`_AUTH_PUBLIC_PATHS` / `_AUTH_PUBLIC_PREFIXES`),
donc une session valide est exigée. Aucun accès distant n'existe hors de ce
chemin authentifié. Garde-fous :
`tests/test_console_embed.py::TestProtectionParSession` et
`tests/test_proxy_akvorado.py::TestProtectionParSession`.

**Ancien mécanisme abandonné (2026-08-09)** : une tentative précédente
servait Okvorado À TRAVERS Grafana, via un plugin d'app à backend Go
(resource handler `/api/plugins/.../resources/...`), pour éviter de publier
un second port avant qu'Okvorado ait sa propre authentification. Mesuré au
navigateur jusqu'au bout : Grafana pose en DUR un en-tête
`Content-Security-Policy: sandbox` sur TOUTES les réponses de proxy, y
compris celles du resource handler d'un plugin — le CSS ne s'appliquait
jamais (page en Times New Roman), JavaScript inopérant. Même un plugin
posant explicitement une CSP permissive se fait écraser par Grafana. Aucun
contournement trouvé ; le module Go et le plugin ont été supprimés du dépôt.
Okvorado porte désormais sa propre authentification, ce qui rend ce
détour inutile.

## Mise en production

Trois gestes avant d'exposer ce stack au-delà du poste d'administration :

1. **Changer le mot de passe Okvorado par défaut** — `OKVORADO_AUTH_PASSWORD`
   dans `.env` (défaut `changeme`, à ne jamais garder). `OKVORADO_AUTH_USER`
   peut aussi être personnalisé.
2. **Activer le TOTP** — depuis l'écran de compte d'Okvorado, une fois
   connecté avec l'admin initiale. Optionnel mais recommandé dès que le
   port est joignable par plus d'une personne.
3. **Placer un reverse proxy devant, pour le TLS** — ce stack ne fait pas de
   TLS lui-même (ni pour Grafana, ni pour Okvorado). Le port Okvorado étant
   lié à `127.0.0.1` par défaut, ceci suppose que le reverse proxy tourne
   **sur cette même machine** (nginx, Caddy, Traefik local...). Si le
   reverse proxy tourne sur une AUTRE machine (fréquent en entreprise),
   régler `OKVORADO_BIND_ADDRESS=0.0.0.0` dans `.env` pour publier le port
   sur toutes les interfaces — l'authentification applicative d'Okvorado
   reste alors la seule protection du port, à ne faire qu'en connaissance
   de cause. Même logique côté Grafana (reverse proxy vers `GRAFANA_PORT`).

## Pointer un routeur

Sur CHAQUE routeur (ou depuis votre outil de configuration centralisée —
c'est le seul geste répétitif à 350 routeurs, tout le reste est automatique) :

1. Configurer l'export NetFlow/IPFIX ou sFlow vers l'IP de cette machine,
   port UDP 2055 (NetFlow v9/IPFIX), 4739 (IPFIX) ou 6343 (sFlow) selon ce
   que le matériel sait faire.
2. Rien d'autre côté collecteur : dès la réception du premier flux, le
   routeur apparaît automatiquement dans Okvorado. La console Akvorado le
   voit aussi en interne, mais aucune URL ne mène vers elle depuis un
   navigateur (décision utilisateur, voir « Une seule URL » plus bas).
3. Si le parc a une communauté SNMP en lecture seule commune, réglable via
   `SNMP_COMMUNITY` (défaut `public`, le plus répandu sur le matériel
   réseau — à personnaliser dans `.env` si le parc utilise une autre
   communauté) — Akvorado interroge alors automatiquement chaque routeur
   découvert pour compléter noms d'interface, vitesse et description.
   Aucune action supplémentaire.
4. Cas particulier (communauté différente sur un sous-ensemble du parc, ou
   équipement sans SNMP) : se règle depuis l'écran Okvorado, section
   « Découverte des interfaces (SNMP) » — jamais en éditant un YAML à la
   main.

## Quoi vérifier après le premier flux

- Okvorado : le routeur apparaît dans la liste des exportateurs, avec ses
  interfaces nommées (si SNMP a répondu) ou un nom générique
  `exportateur-non-resolu` (SNMP n'a pas encore répondu — vérifier la
  communauté et l'accessibilité UDP 161 depuis cette machine).
- Grafana : les tableaux de bord affichent du trafic sur les nouvelles
  interfaces découvertes.
- Okvorado, écran « Rétention » : la croissance disque quotidienne réelle,
  pour ajuster la rétention si besoin.

## Dimensionnement

Le volume dépend du nombre de routeurs et du taux d'échantillonnage
(`SamplingRate`, réglé sur chaque routeur, PAS ici). Extrapolation mesurée
sur un pilote homelab (10,3 octets/flux compressé côté ClickHouse) :

| Profil | Disque/jour | Par an |
|---|---|---|
| Agences calmes | ~0,4 Go | ~0,1 To |
| Profil intermédiaire | ~4,0 Go | ~1,5 To |
| Sites chargés | ~12,0 Go | ~4,4 To |

Un seul nœud ClickHouse suffit dans tous ces cas : le volume n'est pas le
sujet. Garder la rétention des flux BRUTS courte (15 jours par défaut,
`RETENTION_FLOWS_DAYS` dans `.env`) et les agrégats longs (1 an par défaut)
— ajustable à tout moment depuis l'écran « Rétention » d'Okvorado.

⚠️ Si les routeurs échantillonnent (norme opérateur, ex: 1:1000), le trafic
réel est mille fois supérieur à ce qu'un simple `sum(Bytes)` afficherait :
la colonne `SamplingRate` porte le facteur à réappliquer, et les vues de ce
stack l'appliquent déjà. Toute requête ClickHouse écrite à la main doit
faire de même (`sum(Bytes * SamplingRate)`), jamais `sum(Bytes)` seul.

## Capacité d'écriture ClickHouse — tient-on à 350 routeurs ?

### Erreur précédente de cette section, et pourquoi elle a été commise

Une version antérieure de cette section annonçait « ralentissement vers
~100 routeurs, refus vers ~300, la cadence d'écriture est le facteur
limitant ». **C'était faux**, et la cause est une confusion de granularité
dans la mesure, pas dans le mécanisme :

Le total de parts actives de la table `flows` avait été extrapolé (109 →
×31,8 → ~3468), puis comparé aux seuils `parts_to_delay_insert` (1000) et
`parts_to_throw_insert` (3000). **Or ces deux seuils ClickHouse s'appliquent
au nombre de parts actives d'UNE SEULE PARTITION, jamais au total de la
table** — source qui tranche, code source ClickHouse
(`src/Storages/MergeTree/MergeTreeSettings.cpp`), verbatim : *« If the
number of active parts in a **SINGLE PARTITION** exceeds the
`parts_to_delay_insert` value, an INSERT is artificially slowed down. »*

La table `flows` est partitionnée par heure
(`toStartOfInterval(TimeReceived, 25920s)`, tranches de 7,2 h) : le total
de parts se répartit sur des dizaines de partitions actives simultanément,
chacune très en dessous du seuil. Comparer le total à un seuil par
partition produit une fausse alerte croissante avec le nombre de
partitions — **exactement le type d'erreur que la règle « zéro silencieux »
de ce projet vise à empêcher côté code** (`app/services/db_health.py` a été
corrigé en conséquence pour comparer le maximum par partition, jamais le
total ; voir écran **Santé DB**, `/db-health`).

### Mesure réelle (`.6`, 2026-08-08)

| Indicateur | Valeur mesurée |
|---|---|
| Exportateurs actifs | 63 |
| Lignes dans `flows` | 86,2 millions |
| Partitions actives sur `flows` | 27 |
| **Maximum de parts actives dans UNE partition** | **7** |
| Total de parts actives, toutes partitions confondues (info, jamais comparé au seuil) | ~90 |
| Seuil de ralentissement forcé (`parts_to_delay_insert`), **par partition** | 1000 |
| Seuil de refus d'écriture (`parts_to_throw_insert`), **par partition** | 3000 |
| Parts créées / fusionnées (consommées) sur la dernière heure | 565 créées / 680 fusionnées — la fusion suit |
| Erreurs `TOO_MANY_PARTS` cumulées | 0 |
| Mémoire ClickHouse résidente | 1,05 Gio / 2 Gio (52 %) |
| Disque | 51 Go utilisés / 118 Go (46 %), 61 Go disponibles |
| CPU (8 cœurs), charge 1 min | 0,78 (< 10 % d'un cœur) |

Ces deux seuils (1000 / 3000) sont des réglages ClickHouse **ajustables**, pas
des constantes de ce projet — l'écran Santé DB les relit en direct depuis
`system.merge_tree_settings` à chaque vérification, jamais codés en dur, et
les compare désormais au **maximum par partition**, jamais au total.

### Calcul de capacité à 350 routeurs

Le parc actuel (63 exportateurs) donne un facteur d'échelle de **×5,56**
vers la cible SFR (350 routeurs) — pas ×31,8 : le pilote a grandi depuis la
première mesure, ce chiffre doit être recalculé à chaque révision de cette
section, jamais réutilisé tel quel.

Sous l'hypothèse prudente retenue ici (les parts actives par partition
croissent proportionnellement au nombre d'exportateurs, faute de preuve que
la fusion accélère automatiquement) : à 350 routeurs, extrapolation
linéaire de 7 parts/partition × 5,56 ≈ **39 parts dans la partition la
plus chargée** — **marge de facteur ×25 sous le seuil de ralentissement
(1000)**, largement sous le seuil de refus (3000). Le partitionnement
horaire d'Akvorado absorbe déjà le problème : répartir l'écriture sur ~27
partitions actives divise le risque par ~27 par rapport à un flux qui
irait tout dans une seule partition.

**Conclusion : la cadence d'écriture (via les parts) n'est PAS le facteur
limitant à 350 routeurs.** Le ralentissement forcé n'arriverait pas avant
plusieurs milliers d'exportateurs, à partitionnement horaire inchangé.

### Le vrai facteur limitant, mesuré plutôt que supposé

Aucun des indicateurs mesurés (parts, disque, CPU) n'est proche d'une
limite à 350 routeurs — marge ×25 minimum sur chacun. Le seul paramètre
dont la marge n'est PAS confortable par simple extrapolation est la
**mémoire ClickHouse** : 52 % d'un plafond de 2 Gio déjà à 63 exportateurs,
et ce plafond n'a **pas de raison mesurée d'être linéaire** avec le nombre
d'exportateurs (la mémoire résidente sert notamment au cache de fusion et
aux buffers de requête, pas à un espace proportionnel au flux entrant) —
extrapoler un pourcentage par un facteur d'échelle serait retomber dans la
même erreur méthodologique que celle corrigée ci-dessus (mesurer le mauvais
grain). **La mémoire est donc l'indicateur à surveiller en priorité en
montée en charge** (écran Santé DB, section Mémoire), pas un chiffre à
figer par calcul : relever son évolution réelle à mesure que le parc
grandit, et augmenter `mem_limit` du service `clickhouse` dans
`docker-compose.yml` si elle approche 90 % durablement — ce plafond de 2
Gio est une limite de conteneur Docker choisie pour ce pilote, pas une
limite ClickHouse.

⚠️ Aucune mesure à 350 routeurs réels n'est disponible (parc pas encore à
cette taille) : les chiffres de parts/partition à 350 routeurs restent une
extrapolation, pas une mesure. L'écran Santé DB permet de suivre les
indicateurs RÉELS (parts par partition, mémoire, fusions en retard) au fur
et à mesure de la montée en charge, pour confirmer ou infirmer cette
extrapolation avant d'atteindre un seuil critique.

### Réglages qui augmentent la marge, si une dérive est un jour mesurée

Par ordre d'impact décroissant / effort croissant — aucun n'est nécessaire
aujourd'hui vu les marges mesurées, à garder en réserve :

1. **`mem_limit` du service `clickhouse`** — premier levier si la mémoire
   (le seul indicateur sans marge extrapolable ci-dessus) approche son
   plafond en montée en charge réelle.
2. **Taille de lot côté Akvorado** — des lots plus gros réduisent le nombre
   de parts créées pour le même volume de données, si jamais le
   partitionnement horaire ne suffisait plus à absorber la charge.
3. **`async_insert` réellement utilisé pour `default.flows`** — vérifié le
   2026-08-08 : `async_insert=1` est actif côté serveur, mais
   `system.asynchronous_insert_log` montre le regroupement asynchrone
   appliqué à une table tampon interne (`flows_<hash>_raw`), pas
   directement à `default.flows` — Akvorado écrit `flows` en direct, le
   regroupement asynchrone ne réduit donc pas le nombre de parts sur la
   table qui compte. Sans effet mesuré aujourd'hui vu la marge disponible,
   à ré-évaluer si les parts par partition dérivent.
4. **`OPTIMIZE TABLE`** (geste manuel, écran Santé DB) — force un rattrapage
   ponctuel de la fusion si un pic transitoire fait grimper les parts
   actives d'une partition ; ne résout pas une dérive structurelle, seulement
   un pic.

Aucun de ces réglages ne nécessite un second nœud ClickHouse : un nœud
unique tient largement à 350 routeurs sur tous les indicateurs mesurés.

## Sauvegarde

Les données qui comptent vivent dans des **dossiers du projet** (bind mounts,
pas des volumes Docker nommés — exigence « stockage et persistance dans des
dossiers à la racine du projet », voir `docker-compose.yml`) :

| Dossier | Contenu |
|---|---|
| `stack/data/clickhouse` | les flux (table `flows`, agrégats) |
| `stack/data/grafana` | tableaux de bord, plugins installés |
| `stack/data/okvorado` | base SQLite Okvorado, état interne Akvorado (`console.sqlite`, caches) |
| `stack/data/kafka` | tampon Kafka (transitoire — pas critique à sauvegarder) |
| `stack/data/geoip` | bases GeoIP optionnelles, si déposées manuellement |
| `stack/data/grafana-alerting` | règles d'alerte générées (régénérées au démarrage, pas critique) |

Un `tar czf sauvegarde.tar.gz stack/data/clickhouse stack/data/grafana
stack/data/okvorado` (stack arrêté ou ClickHouse en cohérence via un snapshot
applicatif) suffit à restaurer le stack sur une autre machine — visible,
inspectable et sauvegardable sans connaître Docker, contrairement à un volume
nommé dont l'emplacement réel est géré par Docker (`/var/lib/docker/volumes/...`).

## Ajouter Grafana à un Akvorado DÉJÀ en place (cas d'usage entreprise)

Cas différent du démarrage clé en main ci-dessus : un Akvorado existe déjà en
prod (déployé indépendamment de ce dépôt, sans `okvorado` ni le service
`config-generator`) et on veut SEULEMENT y ajouter la restitution Grafana,
**sans toucher aux services existants** — c'est le scénario le plus probable
en entreprise (Akvorado tourne depuis des mois, personne ne veut y toucher).

### Ce qu'on ajoute, et rien d'autre

1. **Le service `grafana`** dans le `docker-compose.yml` existant (pas un
   fichier à côté — un seul stack, un seul `docker compose up -d`) :
   - `image: grafana/grafana:latest`
   - `GF_INSTALL_PLUGINS: grafana-clickhouse-datasource` — **obligatoire**.
     Plugin communautaire absent de l'image officielle : sans cette ligne,
     Grafana démarre et répond en HTTP, mais TOUS les panneaux affichent une
     erreur (le symptôme n'apparaît qu'à l'écran, jamais dans les logs de
     démarrage).
   - `GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH` pour la page d'accueil.
     `GF_USERS_HOME_DASHBOARD_UID` et `GF_USERS_DEFAULT_HOME_DASHBOARD_PATH`
     **n'existent pas** et sont ignorées EN SILENCE (mesuré, aucun warning au
     démarrage) — la vraie clé attend un CHEMIN DE FICHIER, pas un UID, et
     vit dans la section `[dashboards]` de `grafana.ini`, pas `[users]`.
   - mot de passe admin par variable (`${GRAFANA_ADMIN_PASSWORD:-admin}`),
     jamais en clair dans le compose versionné.
   - `mem_limit` raisonnable (512 Mio suffit largement), healthcheck sur
     `/api/health`.
   - la persistance. Ce paquet utilise un **bind-mount** (`./data/grafana`),
     pas un volume nommé : les données restent visibles dans l'arborescence
     du projet, sauvegardables par une simple copie de `stack/data/`. Deux
     conséquences à ne pas manquer :
     - Docker crée le dossier cible en `root:root` alors que Grafana tourne
       en **uid 472** — sans `user: root` sur le service (ce que fait ce
       compose), le conteneur redémarre en boucle sur un « permission
       denied ». Même piège rencontré sur `kafka` (uid 1000) et `okvorado`
       (uid 10001, traité par le service d'init `okvorado-data-init`).
     - Si vous préférez un volume nommé Docker (`grafana-data`) dans un
       stack existant qui en utilise déjà, le problème de permissions ne se
       pose pas — Docker initialise le volume avec les droits de l'image.
       Il faut alors une section `volumes:` au niveau racine, à côté de
       `services:` et jamais en dessous (indentation de premier niveau).
2. **Dashboards + provisioning** copiés depuis ce dépôt
   (`stack/grafana/dashboards/`, `stack/grafana/provisioning/`) dans un
   sous-répertoire du projet existant (ex. `grafana/`), montés en lecture
   seule (`:ro`) :
   - `provisioning/datasources/clickhouse.yml` — la datasource pointe le nom
     du service Docker ClickHouse **existant** (jamais une IP), et porte
     l'UID explicite `ClickHouse` (les règles d'alerte le référencent — sans
     cet UID fixe, Grafana en génère un aléatoire et les alertes échouent
     leur évaluation sur un stack neuf).
   - `provisioning/dashboards/dashboards.yml` — pointe le dossier des JSON,
     zéro clic.
   - `provisioning/alerting/*.yaml.template` — voir choix de résolution
     ci-dessous.
3. **Rien d'autre.** Aucun service existant du compose n'est modifié, aucune
   dépendance (`depends_on`) n'est ajoutée entre `grafana` et les services
   Akvorado — Grafana lit ClickHouse en HTTP au runtime, pas besoin d'ordre
   de démarrage garanti.

### Résoudre les gabarits d'alerte SANS ajouter de service généateur

Les fichiers `provisioning/alerting/*.yaml.template` contiennent des
`${VAR}` (seuils configurables) que Grafana **ne résout jamais lui-même**
(vérifié : aucun `expand_env` dans `grafana.ini`, `printenv` dans le
conteneur ne montre que les `GF_*` explicitement passées). Le dépôt source
les résout via un service `config-generator` dédié — **inutile pour un ajout
ponctuel** sur une infra déjà en place : un service de plus, un volume
intermédiaire de plus, pour un besoin qui ne se présente qu'une fois.

Choix retenu ici, documenté par ce README : **résoudre les `.yaml.template`
une seule fois, à la main**, en substituant les valeurs par défaut
documentées (`ALERTE_EXPORTATEUR_MUET_MINUTES=15`,
`ALERTE_SATURATION_INTERFACE_SEUIL_PCT=80`,
`ALERTE_CHUTE_TRAFIC_SEUIL_PCT=50`, webhook inoffensif par défaut), puis
déposer les `.yaml` résolus (sans le suffixe `.template`) directement dans
`grafana/provisioning/alerting/` monté par le compose. Si les seuils doivent
un jour devenir réglables par variable d'environnement sans repasser par une
résolution manuelle, réintroduire le service `config-generator` du dépôt
source (`stack/config-generator/generate-config.sh`) — mais ce n'est pas le
cas par défaut, et ajouter la corvée avant le besoin réel est le mauvais
compromis.

### Vérifier sans rien casser

- `docker compose config` AVANT tout `up -d` : confirmer que les définitions
  des services existants (image, env, ports, volumes) sont identiques à
  avant l'édition — seule la section `grafana` doit apparaître en plus.
- `docker compose up -d grafana` (jamais `up -d` seul) : ne crée/démarre QUE
  le nouveau service. Si Docker Compose annonce la recréation d'un autre
  conteneur, s'arrêter et comprendre pourquoi avant de continuer — jamais
  forcer.
- `docker inspect <container> --format '{{.State.StartedAt}}'` sur chaque
  service existant, avant et après : les valeurs doivent être **strictement
  identiques** — c'est la preuve qu'aucun n'a redémarré.
- ClickHouse reste en lecture seule pour Grafana : la datasource ne fait que
  des `SELECT` (aucun utilisateur d'écriture référencé dans le
  provisioning) ; les dashboards livrés ne contiennent aucune requête de
  mutation.

## Pourquoi ces choix (pour qui reprend ce stack plus tard)

- **Aucun exportateur n'est déclaré nominativement** dans
  `config/outlet.yaml` : c'est délibéré, c'est ce qui rend ce stack tenable
  à 350 routeurs plutôt qu'à une dizaine. Voir les commentaires du fichier.
- **L'ordre des fournisseurs `static` puis `snmp`** dans
  `config/outlet.yaml` est contre-intuitif mais nécessaire — inverser cet
  ordre désactive silencieusement l'auto-découverte SNMP. Ne pas le changer
  sans avoir lu le commentaire dans le fichier.
- **La communauté SNMP est une référence d'environnement** (`${SNMP_COMMUNITY}`)
  dans `config/outlet.yaml.template`, jamais une valeur en clair : le secret
  ne vit que dans le `.env` local, jamais dans un fichier versionné. Akvorado
  ne résout aucun `${VAR}` lui-même (vérifié dans sa doc officielle) : le
  service `config-generator` du compose résout cette référence AVANT le
  démarrage de l'orchestrateur et écrit `config/outlet.yaml` (gitignoré) —
  c'est ce dernier fichier, jamais le `.template`, qu'Akvorado lit réellement.
- **Deux interfaces PUBLIÉES, pas quatre** : la console Akvorado et l'outlet
  (métriques Prometheus internes — pas une interface humaine) ne publient
  aucun port sur l'hôte ; ils continuent de tourner, joignables seulement
  sur le réseau docker interne. Grafana (`:3000`) et Okvorado (`:8000`,
  `127.0.0.1` par défaut) sont les deux seules interfaces publiées, chacune
  avec sa propre authentification — voir la section « Accès aux
  interfaces » plus haut. La console Akvorado reste néanmoins ACCESSIBLE :
  via `/akvorado-console` sous Okvorado (reverse proxy, voir plus haut), pas
  par un port dédié.
- **`OKVORADO_URL_PREFIX`** (`.env`, défaut vide) : le préfixe que
  l'application utilise pour générer ses liens et ses assets sous un
  sous-chemin plutôt qu'à la racine `/` — utile pour un déploiement derrière
  un reverse proxy d'entreprise qui fait cohabiter plusieurs applications
  sous un même nom d'hôte. Vide par défaut : le port étant republié
  directement, Okvorado est servi normalement à la racine.
- **Plus de plugin Grafana maison** (2026-08-09) : la tentative précédente
  servait Okvorado À TRAVERS Grafana via un plugin d'app à backend Go,
  contournée par un `<iframe>` protégé par une allowlist CSP
  (`frame-ancestors`). Abandonnée : Grafana pose en DUR un sandbox CSP sur
  toutes ses réponses de proxy, y compris celles d'un resource handler de
  plugin — mesuré au navigateur jusqu'au bout, aucun contournement trouvé.
  Le module Go, le plugin déclaré et son provisioning ont été supprimés du
  dépôt. Okvorado porte désormais sa propre authentification et n'a plus
  besoin d'être caché derrière Grafana.
