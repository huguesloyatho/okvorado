# Okvorado — contrats partagés entre lots (SOURCE DE VÉRITÉ)

Ce fichier est le contrat d'interface entre les 4 lots. **Aucun lot ne le modifie.**
Chaque lot implémente ce qui lui est assigné et consomme les signatures des autres.

## Faits d'infra mesurés (2026-08-04/05) — NE PAS RE-SONDER

| Fait | Valeur |
|---|---|
| Hôte Akvorado | `routeur-agence-01` = `192.0.2.6` |
| Version Akvorado | `v2.4.1-44-g42e151bb` |
| Répertoire prod | `/root/akvorado` (config en `:ro` dans les containers) |
| Console web | `http://192.0.2.6:8082` |
| ClickHouse | container `akvorado-clickhouse-1`, natif `9000`, HTTP `8123` (NON exposés sur l'hôte) |
| **Métriques outlet** | `http://<ip-outlet>:8080/api/v0/outlet/metrics` — **PAS `/metrics`** (404) |
| IP docker outlet | `203.0.113.8` (réseau `br-akvorado`, peut changer → résoudre par nom `akvorado-outlet`) |
| Healthcheck outlet | `http://<ip>:8080/api/v0/healthcheck` |
| Repo Gitea | `lortath/netflow-stack`, sous-dossier `akvorado-shakas-6/`, Gitea sur `.6:3100` |

### Tables ClickHouse
| Table | Engine | TTL |
|---|---|---|
| `default.flows` | MergeTree | `TimeReceived + 1296000s` (15 j) |
| `default.flows_1m0s` | SummingMergeTree | idem |
| `default.flows_5m0s` | SummingMergeTree | idem |
| `default.flows_1h0m0s` | SummingMergeTree | idem |
| `default.flows_*_consumer` | MaterializedView | — |
| `default.exporters` | — | — |

Sorting key de `flows` : `toStartOfFiveMinutes(TimeReceived), ExporterAddress, InIfName, OutIfName`.

### Colonnes utiles de `default.flows`
`TimeReceived` (DateTime), `ExporterAddress` (IPv6), `ExporterName` (LowCardinality String),
`SrcAddr`/`DstAddr` (IPv6), `SrcPort`/`DstPort` (UInt16), `Proto` (UInt32 : 1=ICMP, 6=TCP, 17=UDP),
`Bytes`/`Packets` (UInt64), `InIfName`/`OutIfName`, `InIfBoundary`/`OutIfBoundary`
(Enum8 : `undefined`=0, `external`=1, `internal`=2), `SrcAS`/`DstAS` (UInt32),
`SrcCountry`/`DstCountry` (FixedString(2)), `EType` (2048=IPv4, 34525=IPv6), `SamplingRate`.

⚠️ **`IPTos` N'EXISTE PAS** dans le schéma actuel (colonne optionnelle non activée).
Tout code QoS doit détecter son absence et dégrader proprement, JAMAIS supposer sa présence.

⚠️ **Les adresses sont en IPv6-mapped** : `192.0.2.18` s'écrit `::ffff:192.0.2.18`.
Toujours comparer via `toIPv6('::ffff:X.X.X.X')`.

### Métriques Prometheus de l'outlet (format réel mesuré)
```
akvorado_outlet_core_flows_errors_total{error="input and output interfaces missing",exporter="192.0.2.18"} 2.161545e+06
akvorado_outlet_core_forwarded_flows_total{exporter="192.0.2.24"} 1.0557793e+07
akvorado_outlet_kafkaoutput_dropped_messages_total 0
akvorado_outlet_metadata_provider_errors_total 0
```
⚠️ Les valeurs sont en **notation scientifique** (`2.161545e+06`) → parser en `float` puis `int`.
⚠️ Le label est `exporter` et contient une **IP en clair** (pas IPv6-mapped, pas un nom).

## Structure du projet (périmètres DISJOINTS)

```
okvorado/
├── app/
│   ├── main.py              [LOT 0 - moi] FastAPI app, montage des routers, lifespan
│   ├── config.py            [LOT 0 - moi] Settings (env), aucune valeur en dur
│   ├── deps.py              [LOT 0 - moi] dépendances partagées (clients)
│   ├── clients/
│   │   ├── clickhouse.py    [LOT 1] client ClickHouse (lecture seule)
│   │   ├── prometheus.py    [LOT 4] parser des métriques outlet
│   │   └── akvorado_yaml.py [LOT 1] lecture de outlet.yaml (ruamel, READ-ONLY en v1)
│   ├── routers/
│   │   ├── exporters.py     [LOT 1]
│   │   ├── retention.py     [LOT 2]
│   │   ├── views.py         [LOT 3]
│   │   └── ingestion.py     [LOT 4]
│   ├── services/
│   │   ├── exporters.py     [LOT 1] croisement déclaré × observé
│   │   ├── retention.py     [LOT 2] TTL + projection disque
│   │   ├── portmap.py       [LOT 3] table port→application (SQLite)
│   │   └── ingestion.py     [LOT 4] agrégation des compteurs de rejet
│   ├── db.py                [LOT 0 - moi] SQLite (schéma + migrations)
│   ├── templates/
│   │   ├── base.html        [LOT 0 - moi] layout + nav + HTMX
│   │   ├── exporters.html   [LOT 1]
│   │   ├── retention.html   [LOT 2]
│   │   ├── views.html       [LOT 3]
│   │   └── ingestion.html   [LOT 4]
│   └── static/style.css     [LOT 0 - moi]
├── tests/
│   ├── conftest.py          [LOT 0 - moi] fixtures partagées
│   ├── test_exporters.py    [LOT 1]
│   ├── test_retention.py    [LOT 2]
│   ├── test_views.py        [LOT 3]
│   └── test_ingestion.py    [LOT 4]
├── pyproject.toml           [LOT 0 - moi]
└── CONTRACT.md              (ce fichier)
```

**Règle absolue** : un lot n'écrit QUE dans les fichiers marqués de son numéro.
Un besoin dans un fichier [LOT 0] → le signaler dans le rapport final, ne pas l'éditer.

## Contrats de données (dataclasses/Pydantic — signatures figées)

```python
# app/models.py  [LOT 0 - moi] — tous les lots importent d'ici, personne ne le modifie

from enum import Enum
from datetime import datetime
from pydantic import BaseModel

class Boundary(str, Enum):
    INTERNAL = "internal"
    EXTERNAL = "external"
    UNDEFINED = "undefined"

class ExporterHealth(str, Enum):
    HEALTHY = "healthy"           # déclaré + émet + interfaces connues
    SILENT = "silent"             # déclaré mais aucun flux sur la fenêtre
    UNDECLARED = "undeclared"     # émet mais pas déclaré nommément (filet CIDR)
    UNKNOWN_INTERFACE = "unknown_interface"  # émet sur un ifIndex non déclaré
    REJECTED = "rejected"         # émet mais 100% rejeté à l'ingestion (cas .18)

class InterfaceSpec(BaseModel):
    if_index: int
    name: str
    description: str = ""
    speed: int = 1000
    boundary: Boundary = Boundary.UNDEFINED

class DeclaredExporter(BaseModel):
    cidr: str                     # ex "192.0.2.23/32" ou "100.64.0.0/10"
    name: str
    if_indexes: dict[int, InterfaceSpec] = {}
    default: InterfaceSpec | None = None
    is_catchall: bool = False     # True si le CIDR est un filet (prefix court)

class ObservedExporter(BaseModel):
    address: str                  # IP en clair, ex "192.0.2.23"
    name: str                     # ExporterName vu dans les flux
    flows: int
    bytes: int
    last_seen: datetime | None
    interfaces: list[str] = []    # InIfName distincts observés

class ExporterStatus(BaseModel):
    address: str
    name: str
    health: ExporterHealth
    declared: DeclaredExporter | None
    observed: ObservedExporter | None
    forwarded_total: int = 0      # depuis Prometheus
    rejected_total: int = 0       # depuis Prometheus
    rejection_reasons: dict[str, int] = {}
    explanation: str = ""         # phrase en clair pour un collègue
```

## Fenêtre de mesure — RÈGLE MÉTIER NON NÉGOCIABLE

**Minimum 1 HEURE pour tout statut de santé.** Motif mesuré : un nœud à flux longs
(`maxlife=60`) peut n'émettre qu'un datagramme toutes les 75 s — il disparaît des fenêtres
de 5 min et paraît en panne alors qu'il fonctionne.

`WINDOW_CHOICES = ["1h", "6h", "24h", "7d"]`, défaut `"1h"`.
**Aucune fenêtre < 1h ne doit être proposée dans l'UI.** Un helper
`window_to_interval(w) -> str` vit dans `app/config.py` [LOT 0].

## Conventions (CLAUDE.md — obligatoires)

- Routes : `verbe_nom` (`get_exporters`, `list_retention`)
- Services : `action_objet` (`load_exporters`, `check_status`)
- Variables : `snake_case`, noms explicites (jamais `x`, `tmp`, `data`)
- Réponse API succès : `{"status": "ok", ...data}` ; liste : `{"items": [...], "total": N}`
- Erreur : `{"error": "message explicite"}` + code HTTP approprié
- **Toujours `log.error()` avec contexte AVANT de retourner une erreur.** Jamais d'exception avalée.

## Sécurité — profil de menace de CETTE app

| Surface | Garde obligatoire |
|---|---|
| Entrées utilisateur (query params : fenêtre, filtres, ports) | Validation Pydantic stricte, allowlist pour les enums. **Aucune interpolation dans le SQL.** |
| **Requêtes ClickHouse** | **Requêtes paramétrées exclusivement** (`{param:Type}` du driver). Noms de tables/colonnes = littéraux en dur, JAMAIS dérivés d'input. C'est la garde n°1 de ce projet. |
| Appels sortants (ClickHouse, Prometheus outlet) | Hosts **depuis la config uniquement**, jamais depuis l'input utilisateur. Timeout explicite sur chaque appel. |
| Secrets | Aucun secret en dur. Tout via variables d'env. Jamais loggé. |
| Rendu HTML (Jinja2) | Autoescape **activé** (défaut Jinja2 — ne pas le désactiver). Aucun `|safe` sur de la donnée venant de ClickHouse ou du YAML. |
| Écriture YAML (v2, hors périmètre v1) | Optimistic locking par hash + git commit + rollback. **PAS en v1.** |

## Régime de typage strict (Python)

- `mypy --strict` doit passer. **0 `# type: ignore`** sans code d'erreur + raison inline.
- `ruff check` (règles `E,F,I,B,UP,ANN`) + `ruff format --check`.
- Commande de gate : `mypy --strict app tests && ruff check . && ruff format --check .`

## Tests — matrice par couche

| Couche | Type de test | Oracle |
|---|---|---|
| Logique de croisement / calculs (services) | Unitaire, **fixtures en dur** (pas d'infra) | Valeur métier attendue |
| Parsing (metrics Prometheus, YAML) | Unitaire sur échantillon réel figé | Structure attendue |
| Routers FastAPI | Intégration via `TestClient`, clients **mockés** | HTTP + payload conformes |
| Requêtes ClickHouse | Unitaire sur la **construction** de la requête (paramètres bien passés, pas d'interpolation) | SQL attendu + params |
| Templates | Rendu Jinja2 sans exception, données présentes | Contenu attendu dans le HTML |

**Interdiction absolue : aucun test ne doit écrire dans ClickHouse ni dans la prod.**
Les tests tournent hors infra (mocks/fixtures). Un test qui exige `.6` est un test cassé.
