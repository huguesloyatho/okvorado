"""Catalogue applicatif port -> application, à l'échelle IANA + métier.

CONTEXTE (mesuré, cf. tâche « remplacement ManageEngine NetFlow Analyzer sur
350 routeurs SFR ») : `app.services.portmap` porte ~73 entrées (67 IANA + 6
maison). ManageEngine, sur le même parc, embarque 2416 applications — lui
aussi construit sa reconnaissance applicative sur une correspondance
port -> nom (`Layer7 = 0` mesuré côté client : aucune inspection de contenu).
Sur 38 592 ports distincts observés dans les flux réels, le TOP 12 par volume
n'était reconnu qu'à 4/12 par les 73 entrées existantes.

Ce module ÉTEND `app.services.portmap` (dont il réutilise le CRUD, les
validations et la table `port_mappings`) sur trois axes :

1. **Chargement du catalogue IANA officiel** (~11 600 entrées exploitables,
   contre les ~67 entrées "courantes" pré-câblées de `portmap.py`) — voir
   `reload_from_iana()`.
2. **Repli embarqué hors-ligne** : le CSV IANA officiel (~700 Ko) est
   téléchargé UNE FOIS par cet outil (pas à l'exécution) et versionné dans le
   dépôt (`data/iana_service_names_fallback.csv`). Un poste client SFR,
   probablement sans accès Internet sortant (proxy d'entreprise), démarre donc
   quand même avec un catalogue utile — jamais un catalogue vide au premier
   boot. Voir `_load_embedded_fallback()`.
3. **Catalogue MÉTIER pré-chargé** : ce que ni IANA ni ManageEngine ne
   connaissent (SCCM, Tailscale, WSUS...) — voir `seed_metier_defaults()`.

RÈGLE DE PRIORITÉ DES SOURCES (non négociable, cf. tâche) : `source` vaut
`'iana'`, `'custom'` (saisie ad hoc via l'écran/API existants de
`portmap.py`) ou `'metier'` (catalogue applicatif pré-chargé par ce module,
éditable comme `'custom'`). Un rechargement IANA (`reload_from_iana`) ou un
reseed métier (`seed_metier_defaults`) ne réécrit JAMAIS une entrée
`'custom'` OU `'metier'` déjà en base sur le même (port, proto) : c'est le
travail de l'exploitant, jamais écrasé par un rafraîchissement automatique.
Idempotence : relancer un rechargement ne duplique rien (upsert sur la clé
primaire `(port, proto)`).

ZÉRO SILENCIEUX (CLAUDE.md règle n°2, même traitement que
`app.services.snmp_inventory`) : un rechargement IANA dont le réseau échoue
NE DOIT JAMAIS laisser croire à un catalogue vide ou à jour — il produit un
état DISTINCT et visible (`app_catalog_reload_status`, table dédiée), jamais
une absence de changement confondue avec un succès sans rien à faire.

RÉSOLUTION APPLICATIVE D'UN FLUX — LOI MESURÉE (cf. tâche) : sur les flux
réels, les ports ÉPHÉMÈRES (>=32768) portent PLUS de trafic (266,73 GiB) que
les ports de SERVICE (179,41 GiB) — le trafic dominant est du retour de
connexion. La règle qui capte le port de service quel que soit le sens est
`min(SrcPort, DstPort)`, SAUF si les deux ports sont éphémères (aucun des
deux n'est un port de service identifiable — on retombe sur le port
destination, compatible avec `portmap.resolve_application` existant).
Voir `resolve_flow_application()`.

⚠️ Ce module ne modifie AUCUN appelant existant de
`portmap.resolve_application` (`app/routers/views.py`,
`app/routers/diagnostics.py`) : il leur reste disponible tel quel pour la
résolution port+proto simple. `resolve_flow_application` est une fonction
NOUVELLE, additive, pour le cas flux (source ET destination connus).
"""

from __future__ import annotations

import csv
import io
import logging
import os
import sqlite3
from dataclasses import dataclass
from pathlib import Path

import httpx

from app.models import PortMapping
from app.services import portmap

log = logging.getLogger(__name__)

# CONFIG_HARDCODE_OK: le défaut est l'URL PUBLIQUE, STABLE et STANDARD du
# registre officiel IANA (autorité mondiale unique, pas une infra de
# déploiement) — la même pour tout le monde, jamais spécifique à un poste ou
# un client. Surchargeable via OKVORADO_IANA_CSV_URL (ex. miroir interne
# d'entreprise, cas SFR probable si un proxy réécrit les URL sortantes) :
# documenté dans .env.example, jamais figé en dur au sens de la règle.
IANA_CSV_URL = os.environ.get(
    "OKVORADO_IANA_CSV_URL",
    "https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.csv",
)
"""Registre officiel IANA — colonnes `Service Name,Port Number,Transport
Protocol,Description,...`. Format documenté, stable depuis des années."""

_EMBEDDED_FALLBACK_PATH = Path(__file__).resolve().parent.parent.parent / (
    "data/iana_service_names_fallback.csv"
)
"""Repli embarqué : extraction du CSV IANA ci-dessus (~11 600 lignes
exploitables), format simplifié `port;proto;application`, versionné dans le
dépôt. Régénéré manuellement (outil ponctuel, pas de tâche planifiée) — voir
le rapport de livraison pour la procédure. Sert UNIQUEMENT le premier
démarrage / un rechargement dont le réseau échoue : Applipedia a été écarté
(accès automatisé bloqué, reCAPTCHA, catalogue Couche 7 propriétaire — sans
rapport avec une correspondance port -> application), IANA est la seule
source ouverte, stable et réellement exploitable en repli hors-ligne."""

_GRAND_PUBLIC_FALLBACK_PATH = Path(__file__).resolve().parent.parent.parent / (
    "data/grand_public_fallback.csv"
)
"""Catalogue GRAND PUBLIC — ce que ni IANA ni le catalogue métier ne
couvrent : P2P/torrent, streaming, visio, messagerie, jeux, VoWiFi, cloud
grand public, VPN grand public, IoT/domotique. Voir CATÉGORIES DE FAMILLES
dans le retour de livraison pour la liste complète.

MESURÉ (cf. tâche « remplacement ManageEngine ») : le registre IANA nomme
ces ports de façon TROMPEUSE (`4070/tcp` -> "tripe" au lieu de Spotify,
`6969/tcp` -> "acmsoda" au lieu du tracker BitTorrent) ou pas du tout
(`6881/tcp`, `51413/tcp`, `57621/udp` absents d'IANA). Un nom IANA brut
trompeur est PIRE qu'une absence : il donne une fausse confiance à
l'exploitant. D'où la source dédiée `'grand_public'`, prioritaire sur
`'iana'` (même règle que `'metier'` — voir `seed_grand_public_defaults()`).

Format simplifié `port;proto;application`, versionné dans le dépôt (ce
poste SFR n'aura pas Internet). La catégorie (P2P, Streaming, Visio,
Messagerie, Jeu, VoWiFi/VoIP, Cloud, VPN, IoT) est encodée en préfixe
`[Catégorie] Nom` DANS le champ `application` — pas de colonne dédiée : la
table `port_mappings` n'a pas de colonne `category` (ajouter une colonne
est hors périmètre de ce module, qui ne possède pas le schéma `app/db.py`),
et le préfixe reste greppable/recherchable tel quel via
`list_catalog_page(search=...)` et exploitable par un dashboard qui
voudrait grouper sur le préfixe.

LIMITE HONNÊTE, documentée explicitement (cf. tâche) : beaucoup
d'applications grand public modernes (WhatsApp, Netflix, YouTube, Twitch,
Deezer, Apple Music, Google Meet, Messenger, OneDrive/Google Drive/iCloud,
Windows Update, Apple/Adobe update) passent exclusivement en HTTPS/443 ou
QUIC/443 mutualisé avec des milliers d'autres services — AUCUN port ne les
distingue. Ce module ne prétend PAS les résoudre par port : seule une
inspection de couche 7 (hors périmètre ici, cf. Applipedia écarté plus haut)
ou une corrélation par plage d'IP/AS (`SrcAS`/`DstAS`, présents dans les
flux Akvorado/ClickHouse) pourrait les identifier. Piste évaluée mais NON
implémentée dans ce lot (voir rapport de livraison) : viable sur les
données réelles (ASN Google 15169, Amazon 16509, Microsoft 8075, Fastly
54113 mesurés en volume significatif sur `.6`), mais nécessite une table
ASN -> service distincte du présent catalogue port -> application (portée,
volatilité et fausse-confiance différentes : un ASN cloud héberge des
dizaines de services, pas un seul) — hors périmètre de cette tâche."""

_EPHEMERAL_PORT_THRESHOLD = 32768
"""Seuil mesuré (cf. tâche) séparant port de service et port éphémère.
Cohérent avec la plage IANA dynamique/privée (49152-65535) tout en couvrant
la plage large observée dans les flux réels (>=32768)."""

_HTTP_TIMEOUT_SECONDS = 15.0
_MAX_APPLICATION_LENGTH = portmap.MAX_APPLICATION_LENGTH


# ---------------------------------------------------------------------------
# Résolution d'un FLUX (source + destination) — règle min(SrcPort, DstPort)
# ---------------------------------------------------------------------------


def resolve_flow_application(
    conn: sqlite3.Connection,
    *,
    src_port: int,
    dst_port: int,
    proto: str,
) -> str:
    """Détermine l'application d'un flux à partir des DEUX ports.

    RÈGLE MESURÉE : le port de SERVICE est le plus petit des deux ports, sauf
    si les deux sont éphémères (>=32768) — dans ce cas aucun des deux ports
    n'identifie un service connu, on retombe sur le port destination (même
    convention que `portmap.resolve_application`, qui reçoit alors le port
    destination directement).

    Trois cas couverts (voir tests) :
    - port service -> port éphémère (retour de connexion, cas DOMINANT
      mesuré : 266,73 GiB sur ports éphémères contre 179,41 GiB sur ports de
      service) : `min()` retombe correctement sur le port service, quel que
      soit le sens du flux.
    - port éphémère -> port service (sens `attendu` naïvement) : `min()`
      retombe aussi sur le port service.
    - deux ports éphémères (rare, flux pair-à-pair type Tailscale
      41641/udp -> port éphémère du client) : aucun `min()` n'aiderait, on
      résout sur le port destination, qui reste le choix le plus stable.

    N'écrase PAS `portmap.resolve_application` (toujours utilisée telle
    quelle par `views.py`/`diagnostics.py` avec un seul port) : cette
    fonction est un point d'entrée ADDITIONNEL pour le cas flux complet.
    """
    if src_port >= _EPHEMERAL_PORT_THRESHOLD and dst_port >= _EPHEMERAL_PORT_THRESHOLD:
        service_port = dst_port
    else:
        service_port = min(src_port, dst_port)
    return portmap.resolve_application(conn, service_port, proto)


def is_ephemeral_port(port: int) -> bool:
    """Port dans la plage éphémère mesurée (>=32768)."""
    return port >= _EPHEMERAL_PORT_THRESHOLD


# ---------------------------------------------------------------------------
# Statut de rechargement — ZÉRO SILENCIEUX (table dédiée, une seule ligne)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReloadStatus:
    """État du dernier rechargement IANA — jamais un catalogue silencieux.

    `status` vaut `'never_run'` (aucun rechargement tenté depuis l'init de la
    base), `'ok'` (téléchargement réseau réussi), `'offline_fallback'`
    (réseau indisponible, repli embarqué utilisé — état DISTINCT d'un échec
    total) ou `'error'` (ni le réseau ni le repli n'ont pu être exploités :
    catalogue potentiellement vide, à signaler bruyamment).
    """

    status: str
    detail: str
    entries_iana: int
    happened_at: str | None


def get_reload_status(conn: sqlite3.Connection) -> ReloadStatus:
    row = conn.execute(
        "SELECT status, detail, entries_iana, happened_at FROM app_catalog_reload_status "
        "WHERE id = 1"
    ).fetchone()
    if row is None:
        return ReloadStatus(status="never_run", detail="", entries_iana=0, happened_at=None)
    return ReloadStatus(status=row[0], detail=row[1], entries_iana=row[2], happened_at=row[3])


def _record_reload_status(
    conn: sqlite3.Connection, *, status: str, detail: str, entries_iana: int
) -> None:
    conn.execute(
        """
        INSERT INTO app_catalog_reload_status (id, status, detail, entries_iana, happened_at)
        VALUES (1, ?, ?, ?, datetime('now'))
        ON CONFLICT(id) DO UPDATE SET
            status = excluded.status,
            detail = excluded.detail,
            entries_iana = excluded.entries_iana,
            happened_at = excluded.happened_at
        """,
        (status, detail, entries_iana),
    )
    conn.commit()


# ---------------------------------------------------------------------------
# Parsing — commun au flux réseau (CSV IANA officiel) et au repli embarqué
# (CSV simplifié `port;proto;application`)
# ---------------------------------------------------------------------------


def _parse_iana_official_csv(content: str) -> list[tuple[int, str, str]]:
    """Parse le CSV OFFICIEL IANA (colonnes `Service Name,Port Number,
    Transport Protocol,...`) en triplets `(port, proto, application)`.

    Ne garde que les lignes EXPLOITABLES pour une correspondance port ->
    application simple :
    - `Port Number` est un entier unique valide (les plages `"a-b"` et les
      lignes sans port sont ignorées ici — hors périmètre du catalogue
      simple ; une plage éventuelle reste saisissable à la main via l'écran,
      colonne `port_end`).
    - `Transport Protocol` est `tcp` ou `udp` (SCTP/DCCP ignorés : Akvorado
      ne les distingue pas dans les flux NetFlow captés ici).
    - `Service Name` non vide.

    Premier couple (port, proto) rencontré gagne en cas de doublon dans le
    CSV source (IANA en contient : plusieurs services historiques partageant
    un port réassigné).
    """
    reader = csv.DictReader(io.StringIO(content))
    seen: set[tuple[int, str]] = set()
    result: list[tuple[int, str, str]] = []
    for row in reader:
        name = (row.get("Service Name") or "").strip()
        port_raw = (row.get("Port Number") or "").strip()
        proto_raw = (row.get("Transport Protocol") or "").strip().lower()
        if not name or not port_raw or proto_raw not in portmap.VALID_PROTOS:
            continue
        try:
            port = int(port_raw)
        except ValueError:
            continue  # plage "a-b" ou valeur non numérique : hors périmètre simple
        if not (portmap.MIN_PORT <= port <= portmap.MAX_PORT):
            continue
        key = (port, proto_raw)
        if key in seen:
            continue
        seen.add(key)
        application = name[:_MAX_APPLICATION_LENGTH]
        result.append((port, proto_raw, application))
    return result


def _parse_embedded_fallback_csv(content: str) -> list[tuple[int, str, str]]:
    """Parse le repli embarqué (format simplifié `port;proto;application`,
    en-tête `port;proto;application`)."""
    result: list[tuple[int, str, str]] = []
    lines = content.splitlines()
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line == "port;proto;application":
            continue
        parts = line.split(";")
        if len(parts) != 3:
            continue
        port_raw, proto_raw, application = parts
        try:
            port = int(port_raw)
        except ValueError:
            continue
        proto_raw = proto_raw.strip().lower()
        if proto_raw not in portmap.VALID_PROTOS:
            continue
        if not (portmap.MIN_PORT <= port <= portmap.MAX_PORT):
            continue
        result.append((port, proto_raw, application.strip()[:_MAX_APPLICATION_LENGTH]))
    return result


def _load_embedded_fallback() -> list[tuple[int, str, str]] | None:
    """Lit le repli embarqué versionné dans le dépôt. `None` si absent/illisible.

    Ne lève JAMAIS : un dépôt sans ce fichier (déploiement anormal) ne doit
    pas empêcher le démarrage de l'application, seulement dégrader le
    catalogue au strict socle `portmap._IANA_DEFAULTS` déjà en place.
    """
    try:
        content = _EMBEDDED_FALLBACK_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        log.error("app_catalog: repli embarque illisible (%s): %s", _EMBEDDED_FALLBACK_PATH, exc)
        return None
    parsed = _parse_embedded_fallback_csv(content)
    if not parsed:
        log.error(
            "app_catalog: repli embarque present mais vide/illisible: %s", _EMBEDDED_FALLBACK_PATH
        )
        return None
    return parsed


# ---------------------------------------------------------------------------
# Application en base — upsert qui NE TOUCHE JAMAIS une entrée custom/metier
# ---------------------------------------------------------------------------


_PROTECTED_FROM_IANA_RELOAD = ("custom", "metier", "grand_public")
"""Sources JAMAIS écrasées par un rechargement IANA (`_apply_entries`, source
`'iana'` uniquement). `'grand_public'` rejoint `'custom'`/`'metier'` : c'est
un catalogue construit, au même titre que le métier — pas une source
générique remplaçable par un simple rafraîchissement du registre officiel."""


def _apply_entries(
    conn: sqlite3.Connection, entries: list[tuple[int, str, str]], *, source: str
) -> int:
    """Upsert `entries` en base sous `source`, sans jamais écraser une entrée
    `'custom'`, `'metier'` ou `'grand_public'` déjà présente sur le même
    (port, proto).

    Idempotent : relancer avec les mêmes `entries` ne duplique rien (clé
    primaire `(port, proto)`) et ne change rien au contenu déjà identique.

    Retourne le nombre d'entrées EFFECTIVEMENT écrites sous `source` (celles
    protégées par une surcharge custom/metier/grand_public ne comptent pas).
    """
    # La clause WHERE est générée à partir de `_PROTECTED_FROM_IANA_RELOAD`
    # (source UNIQUE de la liste protégée, jamais dupliquée en dur dans le
    # SQL) : un défaut mesuré ici pendant le développement — le check Python
    # ci-dessous ET une clause SQL codée en dur séparément avaient DIVERGÉ
    # silencieusement (la clause SQL restait une garde de secours correcte
    # même quand le tuple Python était altéré), rendant le test de morsure
    # sur `_PROTECTED_FROM_IANA_RELOAD` inefficace. `?` * N reste une requête
    # PARAMÉTRÉE (valeurs liées, jamais interpolées) : seul le NOMBRE de `?`
    # est construit dynamiquement à partir d'une constante interne fixe,
    # jamais d'une entrée utilisateur.
    _placeholders = ", ".join("?" for _ in _PROTECTED_FROM_IANA_RELOAD)
    _upsert_sql = f"""
        INSERT INTO port_mappings (port, proto, application, source)
        VALUES (?, ?, ?, ?)
        ON CONFLICT(port, proto) DO UPDATE SET
            application = excluded.application,
            source = excluded.source
        WHERE port_mappings.source NOT IN ({_placeholders})
        """
    written = 0
    for port, proto, application in entries:
        existing = portmap.get_mapping(conn, port, proto)
        if existing is not None and existing.source in _PROTECTED_FROM_IANA_RELOAD:
            continue
        conn.execute(
            _upsert_sql,
            (port, proto, application, source, *_PROTECTED_FROM_IANA_RELOAD),
        )
        written += 1
    conn.commit()
    return written


# ---------------------------------------------------------------------------
# Rechargement IANA — déclenchable à la souris, idempotent
# ---------------------------------------------------------------------------


def reload_from_iana(
    conn: sqlite3.Connection, *, timeout_seconds: float | None = None
) -> ReloadStatus:
    """Recharge le catalogue depuis le registre IANA officiel (réseau), avec
    repli embarqué si le réseau échoue.

    Séquence :
    1. Tente le téléchargement du CSV officiel IANA (~700 Ko).
    2. Succès réseau -> parse + applique (source='iana'), statut 'ok'.
    3. Échec réseau (timeout, DNS, HTTP non-2xx, proxy d'entreprise probable
       chez SFR) -> bascule sur le repli embarqué versionné dans le dépôt,
       statut 'offline_fallback' — DISTINCT d'un succès réseau, mais le
       catalogue reste UTILE (~11 600 entrées) plutôt que vide.
    4. Ni le réseau ni le repli n'ont fonctionné -> statut 'error', catalogue
       inchangé, JAMAIS présenté comme un succès silencieux.

    Idempotent dans tous les cas : `_apply_entries` upsert sur la clé
    primaire, ne duplique jamais, et ne touche jamais une entrée
    `'custom'`/`'metier'`.
    """
    effective_timeout = timeout_seconds if timeout_seconds is not None else _HTTP_TIMEOUT_SECONDS

    try:
        response = httpx.get(IANA_CSV_URL, timeout=effective_timeout, follow_redirects=True)
        response.raise_for_status()
        entries = _parse_iana_official_csv(response.text)
        if not entries:
            raise ValueError("CSV IANA telecharge mais aucune entree exploitable extraite")
    except Exception as exc:  # noqa: BLE001 - tout echec reseau/parsing -> repli, jamais un 500
        log.error("app_catalog: echec telechargement IANA, bascule sur repli embarque: %s", exc)
        fallback = _load_embedded_fallback()
        if fallback is None:
            return _record_and_return(
                conn,
                status="error",
                detail=(
                    f"Téléchargement IANA impossible ({exc}) ET repli embarqué "
                    "illisible/absent : catalogue inchangé."
                ),
                entries_iana=0,
            )
        written = _apply_entries(conn, fallback, source="iana")
        return _record_and_return(
            conn,
            status="offline_fallback",
            detail=(
                f"Téléchargement IANA impossible ({exc}) : repli embarqué appliqué "
                f"({written} entrée(s) IANA à jour, protégées custom/métier exclues)."
            ),
            entries_iana=written,
        )

    written = _apply_entries(conn, entries, source="iana")
    return _record_and_return(
        conn,
        status="ok",
        detail=f"{written} entrée(s) IANA appliquée(s) (protégées custom/métier exclues).",
        entries_iana=written,
    )


def _record_and_return(
    conn: sqlite3.Connection, *, status: str, detail: str, entries_iana: int
) -> ReloadStatus:
    _record_reload_status(conn, status=status, detail=detail, entries_iana=entries_iana)
    return ReloadStatus(status=status, detail=detail, entries_iana=entries_iana, happened_at=None)


def ensure_catalog_seeded_at_startup(conn: sqlite3.Connection) -> ReloadStatus:
    """Amorce le catalogue au premier démarrage, SANS accès réseau.

    Distinct de `reload_from_iana()` (qui tente le réseau) : au démarrage, on
    ne veut pas bloquer le boot de l'application sur un appel réseau
    potentiellement long/en échec (proxy d'entreprise). On applique
    directement le repli embarqué — un rechargement réseau reste
    déclenchable ensuite, à la souris, depuis l'écran.

    Idempotent et sans effet destructeur : n'écrase jamais une entrée
    `'custom'`/`'metier'`, et ne fait rien de plus qu'un upsert si le
    catalogue IANA est déjà à jour depuis un rechargement précédent.
    """
    fallback = _load_embedded_fallback()
    if fallback is None:
        return _record_and_return(
            conn,
            status="error",
            detail="Repli embarqué illisible/absent au démarrage : catalogue IANA non amorcé.",
            entries_iana=0,
        )
    written = _apply_entries(conn, fallback, source="iana")
    return _record_and_return(
        conn,
        status="offline_fallback",
        detail=f"Amorçage au démarrage depuis le repli embarqué ({written} entrée(s) IANA).",
        entries_iana=written,
    )


# ---------------------------------------------------------------------------
# Catalogue MÉTIER — ce qu'aucun registre ne connaît (cf. tâche, section 2)
# ---------------------------------------------------------------------------

# Chaque entrée est documentée : pourquoi elle est là, pas seulement ce
# qu'elle vaut. Choisies pour le cas de diagnostic RÉEL de l'utilisateur
# (SCCM sur 350 routeurs SFR) et les grands classiques d'entreprise que le
# registre IANA nomme mal ou ignore (ex. 1521 -> "ncube-lm" chez IANA, pas
# "Oracle-DB" ; 8530/8531 absents d'IANA, WSUS de facto uniquement — les
# deux vérifiés lors de la génération du repli embarqué).
_METIER_DEFAULTS: tuple[tuple[int, int | None, str, str], ...] = (
    # --- SCCM / Microsoft Configuration Manager -----------------------
    # Cas de diagnostic EXPLICITE de la tâche : un client SCCM parle SMB
    # (partage de contenu), HTTP/HTTPS (Management Point, distribution de
    # contenu) et BITS (arrière-plan, réutilise le port HTTP/HTTPS du MP —
    # pas de port dédié dans NetFlow, donc pas d'entrée séparée ici).
    (445, None, "tcp", "SCCM - SMB (partage de contenu)"),
    (80, None, "tcp", "SCCM - HTTP (Management Point / BITS)"),
    (443, None, "tcp", "SCCM - HTTPS (Management Point / BITS)"),
    (10123, None, "tcp", "SCCM - client notification (fast channel)"),
    (135, None, "tcp", "SCCM - RPC endpoint mapper (WMI/inventaire)"),
    # --- Tailscale -------------------------------------------------------
    # Port le plus lourd mesuré chez l'utilisateur (215 GiB), absent de tout
    # registre (protocole WireGuard, port applicatif propriétaire).
    (41641, None, "udp", "Tailscale (WireGuard) - port le plus lourd mesuré"),
    # --- Grands classiques d'entreprise mal nommés ou absents d'IANA -----
    (3389, None, "tcp", "RDP (Bureau à distance)"),
    (3389, None, "udp", "RDP (Bureau à distance, UDP)"),
    (389, None, "tcp", "LDAP (Active Directory)"),
    (389, None, "udp", "LDAP (Active Directory, UDP)"),
    (636, None, "tcp", "LDAPS (Active Directory sur TLS)"),
    (88, None, "tcp", "Kerberos (authentification AD)"),
    (88, None, "udp", "Kerberos (authentification AD, UDP)"),
    (53, None, "tcp", "DNS"),
    (53, None, "udp", "DNS"),
    (445, None, "udp", "SMB (partage de fichiers, UDP - legacy)"),
    (139, None, "tcp", "SMB sur NetBIOS (legacy)"),
    # WSUS : ports de facto Microsoft, absents du registre IANA officiel
    # (vérifié lors de la génération du repli embarqué : ni 8530 ni 8531 n'y
    # figurent) — sans cette entrée métier, ils resteraient affichés en
    # "tcp/8530" brut malgré leur usage massif en entreprise.
    (8530, None, "tcp", "WSUS (Windows Server Update Services, HTTP)"),
    (8531, None, "tcp", "WSUS (Windows Server Update Services, HTTPS)"),
    (1433, None, "tcp", "SQL Server (Microsoft) - IANA le nomme 'ms-sql-s', renommé ici"),
    (1521, None, "tcp", "Oracle Database (TNS Listener) - IANA le nomme 'ncube-lm', renommé ici"),
    (5060, None, "udp", "SIP (téléphonie IP)"),
    (5060, None, "tcp", "SIP (téléphonie IP, TCP)"),
    (67, None, "udp", "DHCP (serveur)"),
    (68, None, "udp", "DHCP (client)"),
    (123, None, "udp", "NTP (synchronisation horaire)"),
    (161, None, "udp", "SNMP"),
    (162, None, "udp", "SNMP trap"),
)


def seed_metier_defaults(conn: sqlite3.Connection) -> int:
    """Précharge le catalogue métier (SCCM, Tailscale, grands classiques
    d'entreprise). Idempotent, jamais destructeur.

    N'écrase JAMAIS une entrée `'custom'` (surcharge saisie à la main par
    l'exploitant) déjà présente sur le même (port, proto) — mais PEUT
    remplacer une entrée `'iana'` existante (le nom métier prime sur le nom
    générique du registre, ex. "Oracle Database" plutôt que "ncube-lm") ou
    une entrée `'metier'` déjà posée par un seed antérieur (upsert sur la
    même valeur = idempotent).

    Retourne le nombre d'entrées effectivement (ré)écrites sous 'metier'.
    """
    written = 0
    for port, port_end, proto, application in _METIER_DEFAULTS:
        existing = portmap.get_mapping(conn, port, proto)
        if existing is not None and existing.source == "custom":
            continue
        conn.execute(
            """
            INSERT INTO port_mappings (port, proto, application, source, port_end)
            VALUES (?, ?, ?, 'metier', ?)
            ON CONFLICT(port, proto) DO UPDATE SET
                application = excluded.application,
                source = 'metier',
                port_end = excluded.port_end
            WHERE port_mappings.source != 'custom'
            """,
            (port, proto, application, port_end),
        )
        written += 1
    conn.commit()
    log.info("app_catalog: seed metier effectue (%d candidats)", len(_METIER_DEFAULTS))
    return written


# ---------------------------------------------------------------------------
# Catalogue GRAND PUBLIC — P2P, streaming, visio, messagerie, jeux, VoWiFi,
# cloud grand public, VPN grand public, IoT/domotique (cf. tâche, reproche
# fondé : les 28 entrées métier initiales étaient TOUTES des applications
# système/SCCM). Voir la documentation de `_GRAND_PUBLIC_FALLBACK_PATH`.
# ---------------------------------------------------------------------------


def _load_grand_public_fallback() -> list[tuple[int, str, str]] | None:
    """Lit le catalogue grand public versionné dans le dépôt. `None` si
    absent/illisible — ne lève JAMAIS (même contrat que
    `_load_embedded_fallback`) : un dépôt sans ce fichier (déploiement
    anormal) ne doit pas empêcher le démarrage de l'application."""
    try:
        content = _GRAND_PUBLIC_FALLBACK_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        log.error(
            "app_catalog: catalogue grand public illisible (%s): %s",
            _GRAND_PUBLIC_FALLBACK_PATH,
            exc,
        )
        return None
    parsed = _parse_embedded_fallback_csv(content)
    if not parsed:
        log.error(
            "app_catalog: catalogue grand public present mais vide/illisible: %s",
            _GRAND_PUBLIC_FALLBACK_PATH,
        )
        return None
    return parsed


def seed_grand_public_defaults(conn: sqlite3.Connection) -> int:
    """Précharge le catalogue GRAND PUBLIC (BitTorrent, Spotify, Teams/Zoom,
    appel WiFi/VoWiFi, jeux, cloud, VPN, IoT — voir
    `_GRAND_PUBLIC_FALLBACK_PATH`). Idempotent, jamais destructeur.

    Même règle de priorité que `seed_metier_defaults()` : n'écrase JAMAIS une
    entrée `'custom'` déjà présente sur le même (port, proto), mais PEUT
    remplacer une entrée `'iana'` existante — c'est précisément le but : le
    nom IANA trompeur (`4070/tcp` -> "tripe") doit être remplacé par le nom
    grand public (`4070/tcp` -> "[Streaming] Spotify"). Un rechargement IANA
    ultérieur ne pourra PAS écraser cette entrée en retour (voir
    `_PROTECTED_FROM_IANA_RELOAD` dans `_apply_entries`).

    Si le fichier de données est absent/illisible, retourne 0 sans lever
    (dégradation gracieuse au démarrage, cohérent avec
    `ensure_catalog_seeded_at_startup`) — mais log une erreur explicite,
    jamais un silence qui laisserait croire à un catalogue à jour.
    """
    entries = _load_grand_public_fallback()
    if entries is None:
        return 0
    written = 0
    for port, proto, application in entries:
        existing = portmap.get_mapping(conn, port, proto)
        if existing is not None and existing.source == "custom":
            continue
        conn.execute(
            """
            INSERT INTO port_mappings (port, proto, application, source)
            VALUES (?, ?, ?, 'grand_public')
            ON CONFLICT(port, proto) DO UPDATE SET
                application = excluded.application,
                source = 'grand_public'
            WHERE port_mappings.source != 'custom'
            """,
            (port, proto, application),
        )
        written += 1
    conn.commit()
    log.info("app_catalog: seed grand public effectue (%d candidats)", len(entries))
    return written


# ---------------------------------------------------------------------------
# Consultation paginée / recherche / filtre — écran (11 600+ entrées)
# ---------------------------------------------------------------------------

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 500
VALID_SOURCES = ("iana", "custom", "metier", "grand_public")


@dataclass(frozen=True)
class CatalogPage:
    items: list[PortMapping]
    total: int
    page: int
    page_size: int

    @property
    def total_pages(self) -> int:
        if self.page_size <= 0:
            return 1
        return max(1, -(-self.total // self.page_size))  # ceil sans import math


def list_catalog_page(
    conn: sqlite3.Connection,
    *,
    page: int = 1,
    page_size: int = DEFAULT_PAGE_SIZE,
    search: str = "",
    source: str = "",
) -> CatalogPage:
    """Liste paginée + recherche (port ou nom d'application) + filtre source.

    Requête paramétrée exclusivement (garde sécu n°1 du projet) : `search` et
    `source` transitent par des paramètres liés, jamais par interpolation.
    """
    page = max(1, page)
    page_size = min(max(1, page_size), MAX_PAGE_SIZE)

    conditions: list[str] = []
    params: list[object] = []

    search = search.strip()
    if search:
        conditions.append("(application LIKE ? OR CAST(port AS TEXT) LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like])

    if source in VALID_SOURCES:
        conditions.append("source = ?")
        params.append(source)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""

    total_row = conn.execute(f"SELECT COUNT(*) FROM port_mappings {where}", params).fetchone()
    total = int(total_row[0]) if total_row else 0

    offset = (page - 1) * page_size
    rows = conn.execute(
        f"SELECT port, proto, application, source, port_end FROM port_mappings {where} "
        f"ORDER BY port, proto LIMIT ? OFFSET ?",
        [*params, page_size, offset],
    ).fetchall()
    items = [
        PortMapping(port=row[0], proto=row[1], application=row[2], source=row[3], port_end=row[4])
        for row in rows
    ]
    return CatalogPage(items=items, total=total, page=page, page_size=page_size)


def count_by_source(conn: sqlite3.Connection) -> dict[str, int]:
    """Répartition du catalogue par source, pour l'en-tête de l'écran."""
    rows = conn.execute("SELECT source, COUNT(*) FROM port_mappings GROUP BY source").fetchall()
    return {row[0]: int(row[1]) for row in rows}


# ---------------------------------------------------------------------------
# Import/export CSV en masse — catalogue MÉTIER (350 routeurs, saisie manuelle
# exclue à cette échelle)
# ---------------------------------------------------------------------------
#
# Format `port;proto;application` (+ `port_end` optionnel en 4e colonne pour
# une plage) — même CONVENTION `valeur;désignation` que `app.services.csv_io`
# (clé métier ; désignation lisible), étendue à 3-4 colonnes parce qu'une
# correspondance port -> application n'est pas réductible à un couple
# clé/valeur unique : port ET proto forment ensemble la clé (`csv_io.py` n'a
# pas de format à clé composite, donc pas de `CsvFormat` réutilisable tel
# quel ici) — mêmes TOLÉRANCES reprises à l'identique (BOM, `\r\n`, lignes
# vides/commentaires ignorées, en-tête reconnue par mot-clé, tout-ou-rien).


@dataclass(frozen=True)
class CatalogCsvRow:
    line: int
    port: int
    proto: str
    application: str
    port_end: int | None = None


@dataclass(frozen=True)
class CatalogCsvParseResult:
    """Résultat tout-ou-rien, même contrat que `csv_io.CsvParseResult` :
    `rows` n'est peuplé QUE si `errors` est vide — jamais un mélange de lignes
    valides et d'erreurs appliqué partiellement."""

    rows: list[CatalogCsvRow]
    errors: list[str]


_CSV_HEADER_KEYWORDS = frozenset(
    {"port", "port;proto;application", "port;proto;application;port_end"}
)


def parse_catalog_csv(content: str) -> CatalogCsvParseResult:
    """Parse un CSV `port;proto;application[;port_end]` en résultat tout-ou-rien.

    Une ligne malformée REFUSE tout l'import et le DIT explicitement (message
    par ligne, numéro de ligne inclus) — jamais un sous-ensemble appliqué en
    silence, jamais une ligne ignorée sans message.
    """
    content = content.lstrip("﻿")  # BOM UTF-8
    errors: list[str] = []
    rows: list[CatalogCsvRow] = []
    seen: dict[tuple[int, str], int] = {}

    for line_number, raw_line in enumerate(content.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line_number == 1 and line.lower() in _CSV_HEADER_KEYWORDS:
            continue

        fields = [f.strip() for f in line.split(";")]
        if len(fields) not in (3, 4):
            errors.append(
                f"ligne {line_number}: format invalide (attendu "
                f"'port;proto;application' ou 'port;proto;application;port_end'): {raw_line!r}"
            )
            continue

        port_raw, proto_raw, application = fields[0], fields[1].lower(), fields[2]
        port_end_raw = fields[3] if len(fields) == 4 else ""

        try:
            port = int(port_raw)
        except ValueError:
            errors.append(f"ligne {line_number}: port non entier: {port_raw!r}")
            continue
        if not (portmap.MIN_PORT <= port <= portmap.MAX_PORT):
            errors.append(f"ligne {line_number}: port hors bornes (1-65535): {port}")
            continue

        if proto_raw not in portmap.VALID_PROTOS:
            errors.append(
                f"ligne {line_number}: protocole invalide (attendu tcp/udp): {proto_raw!r}"
            )
            continue

        if not application:
            errors.append(f"ligne {line_number}: application vide")
            continue
        if len(application) > _MAX_APPLICATION_LENGTH:
            errors.append(
                f"ligne {line_number}: application trop longue "
                f"({len(application)} caractères, max {_MAX_APPLICATION_LENGTH})"
            )
            continue

        port_end: int | None = None
        if port_end_raw:
            try:
                port_end = int(port_end_raw)
            except ValueError:
                errors.append(f"ligne {line_number}: fin de plage non entière: {port_end_raw!r}")
                continue
            if not (portmap.MIN_PORT <= port_end <= portmap.MAX_PORT):
                errors.append(f"ligne {line_number}: fin de plage hors bornes: {port_end}")
                continue
            if port_end < port:
                errors.append(
                    f"ligne {line_number}: fin de plage {port_end} inférieure au port de "
                    f"début {port}"
                )
                continue

        key = (port, proto_raw)
        if key in seen:
            errors.append(
                f"ligne {line_number}: doublon de {port}/{proto_raw} (déjà vu ligne {seen[key]})"
            )
            continue
        seen[key] = line_number

        rows.append(
            CatalogCsvRow(
                line=line_number,
                port=port,
                proto=proto_raw,
                application=application,
                port_end=port_end,
            )
        )

    if errors:
        return CatalogCsvParseResult(rows=[], errors=errors)
    return CatalogCsvParseResult(rows=rows, errors=[])


def apply_catalog_csv_import(
    conn: sqlite3.Connection, rows: list[CatalogCsvRow], *, source: str = "metier"
) -> int:
    """Applique un import CSV déjà parsé/validé. Marque les entrées `source`
    (par défaut `'metier'`, le cas du catalogue applicatif métier importé en
    masse pour 350 routeurs). Écrase une entrée `'iana'` existante (le nom
    métier prime), mais respecte les correspondances `'custom'` (source
    d'exploitant) — même garde que le rechargement IANA.

    Idempotent : ré-importer le même CSV ne duplique rien, ne change rien.
    """
    written = 0
    for row in rows:
        existing = portmap.get_mapping(conn, row.port, row.proto)
        if existing is not None and existing.source == "custom":
            continue
        portmap.create_mapping(
            conn,
            port=row.port,
            proto=row.proto,
            application=row.application,
            source=source,
            port_end=row.port_end,
        )
        written += 1
    return written


def export_catalog_csv(conn: sqlite3.Connection, *, source: str = "") -> str:
    """Exporte le catalogue (ou un sous-ensemble filtré par `source`) au
    format `port;proto;application;port_end` (`port_end` vide pour un port
    unique). Une base vide produit un CSV valide (en-tête seule)."""
    lines = ["port;proto;application;port_end"]
    if source in VALID_SOURCES:
        rows = conn.execute(
            "SELECT port, proto, application, port_end FROM port_mappings WHERE source = ? "
            "ORDER BY port, proto",
            (source,),
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT port, proto, application, port_end FROM port_mappings ORDER BY port, proto"
        ).fetchall()
    for port, proto, application, port_end in rows:
        safe_application = str(application).replace(";", ",")
        lines.append(
            f"{port};{proto};{safe_application};{port_end if port_end is not None else ''}"
        )
    return "\r\n".join(lines) + "\r\n"
