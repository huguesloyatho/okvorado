"""Configuration de l'application — aucune valeur d'infra en dur.

Tout est lu depuis l'environnement (préfixe `OKVORADO_`) via pydantic-settings.
Les défauts ci-dessous ne sont que des fallbacks de développement : les vraies
valeurs vivent dans `.env` (gitignored). Voir `.env.example`.

CONFIG_HARDCODE_OK: les IP/URL ci-dessous sont des FALLBACKS de `BaseSettings`,
surchargés par les variables d'env OKVORADO_* documentées dans .env.example.
Elles sont lues depuis l'environnement en priorité, jamais figées.
"""

import ipaddress
import os
from ipaddress import IPv4Network, IPv6Network

from pydantic_settings import BaseSettings, SettingsConfigDict


def parse_internal_networks(valeur: str) -> list[IPv4Network | IPv6Network]:
    """Parse une liste CSV de CIDR en réseaux VALIDÉS.

    Utilisée par `Settings.internal_networks_list()` et par le constructeur de
    filtre SQL (`app.services.diagnostics.build_internal_filter`) — une seule
    source de vérité pour la validation, plutôt que deux implémentations qui
    divergeraient.

    REFUSE BRUYAMMENT (`ValueError`) plutôt que d'ignorer une entrée fautive :
    un filtre amputé d'une plage, ou vide, produirait un écran de diagnostic
    FAUX sans le moindre message — l'exploitant lirait « aucune convergence »
    en croyant que tout va bien. C'est le « zéro silencieux » proscrit par
    CLAUDE.md, et il est ici particulièrement traître : le résultat a l'air
    normal.
    """
    reseaux: list[IPv4Network | IPv6Network] = []
    for brut in (part.strip() for part in valeur.split(",")):
        if not brut:
            continue
        try:
            reseaux.append(ipaddress.ip_network(brut, strict=False))
        except ValueError as exc:
            raise ValueError(
                f"plage réseau interne invalide : {brut!r} — attendu un CIDR "
                f"(ex. 10.0.0.0/8). Détail : {exc}"
            ) from exc

    if not reseaux:
        raise ValueError(
            "aucune plage réseau interne déclarée : le filtre de convergence "
            "ne correspondrait à AUCUN flux et l'écran afficherait « aucune "
            "convergence » comme si tout allait bien. Renseigner "
            "OKVORADO_INTERNAL_NETWORKS (ex. 10.0.0.0/8)."
        )
    return reseaux

WINDOW_CHOICES: tuple[str, ...] = ("1h", "6h", "24h", "7d")
"""Fenêtres de mesure proposées dans l'UI.

RÈGLE MÉTIER : aucune fenêtre < 1 heure. Un nœud à flux longs peut n'émettre qu'un
datagramme toutes les 75 s ; sur une fenêtre de 5 minutes il paraît en panne alors
qu'il fonctionne (incident de mesure vécu le 2026-08-01 sur poste-collecte).
"""

DEFAULT_WINDOW = "1h"

_WINDOW_INTERVALS: dict[str, str] = {
    "1h": "1 HOUR",
    "6h": "6 HOUR",
    "24h": "24 HOUR",
    "7d": "7 DAY",
}

_DEFAULT_AKVORADO_HOST = os.environ.get("OKVORADO_AKVORADO_HOST", "127.0.0.1")


_WINDOW_SECONDS: dict[str, int] = {
    "1h": 3600,
    "6h": 21600,
    "24h": 86400,
    "7d": 604800,
}


def window_to_seconds(window: str) -> int:
    """Traduit une fenêtre de l'UI en nombre de secondes.

    À préférer à `window_to_interval()` pour une requête ClickHouse : la syntaxe
    `INTERVAL {param:String}` est REFUSÉE par ClickHouse (INTERVAL exige un
    littéral, mesuré le 2026-08-05 : SYNTAX_ERROR). La forme qui accepte un
    paramètre lié est `now() - toIntervalSecond({s:UInt32})`, ce qui conserve la
    garde anti-injection sans interpolation de chaîne.

    Raises:
        ValueError: si la fenêtre n'est pas dans WINDOW_CHOICES.
    """
    try:
        return _WINDOW_SECONDS[window]
    except KeyError:
        raise ValueError(
            f"fenetre invalide: {window!r} (attendu: {', '.join(WINDOW_CHOICES)})"
        ) from None


def interval_to_seconds(interval: str) -> int:
    """Traduit un INTERVAL ClickHouse ('1 HOUR') en secondes.

    Permet aux appelants qui manipulent déjà un littéral d'intervalle de basculer
    vers la forme paramétrable sans changer leur signature.
    """
    for window, literal in _WINDOW_INTERVALS.items():
        if literal == interval:
            return _WINDOW_SECONDS[window]
    raise ValueError(f"interval inconnu: {interval!r}")


def window_to_interval(window: str) -> str:
    """Traduit une fenêtre de l'UI en INTERVAL ClickHouse.

    Le retour est un littéral issu d'une table figée : il n'est jamais dérivé
    d'une saisie utilisateur, ce qui interdit toute injection via ce chemin.

    Raises:
        ValueError: si la fenêtre n'est pas dans WINDOW_CHOICES.
    """
    try:
        return _WINDOW_INTERVALS[window]
    except KeyError:
        raise ValueError(
            f"fenetre invalide: {window!r} (attendu: {', '.join(WINDOW_CHOICES)})"
        ) from None


class Settings(BaseSettings):
    """Paramètres applicatifs, surchargés par l'environnement (OKVORADO_*)."""

    model_config = SettingsConfigDict(env_prefix="OKVORADO_", env_file=".env")

    akvorado_host: str = _DEFAULT_AKVORADO_HOST
    """Hôte par défaut, utilisé quand les hôtes par service ne sont pas précisés.

    En déploiement conteneurisé, chaque service a son propre nom DNS sur le
    réseau docker (`clickhouse`, `akvorado-outlet`, `akvorado-console`) : on
    surcharge alors `clickhouse_host` / `console_host` séparément. En dev depuis
    une station, un seul hôte (via tunnels) suffit — d'où ce défaut partagé.
    """

    clickhouse_host: str = ""
    console_host: str = ""

    clickhouse_port: int = 8123
    clickhouse_user: str = "default"
    clickhouse_password: str = ""
    clickhouse_database: str = "default"

    outlet_metrics_path: str = "/api/v0/outlet/metrics"
    """Chemin MESURÉ le 2026-08-05. Attention : `/metrics` renvoie 404 sur l'outlet."""

    outlet_port: int = 8080
    console_port: int = 8082

    akvorado_config_path: str = "/etc/akvorado-config/outlet.yaml"

    grafana_dashboards_path: str = "/etc/grafana-dashboards"
    """Dossier des dashboards Grafana provisionnés — source du décompte
    « champs exploités » de l'écran Champs disponibles.

    CONFIG_HARDCODE_OK: fallback de `BaseSettings`, surchargé par
    OKVORADO_GRAFANA_DASHBOARDS_PATH. C'est un montage `:ro` (docker-compose) :
    l'écran LIT les dashboards pour savoir quelles colonnes ils consomment, il
    n'en écrit jamais aucun.

    ⚠️ Sans ce montage, le dossier est absent et l'écran affiche « décompte
    indisponible » — un état DISTINCT, jamais « 0 champ exploité » qui
    annoncerait faussement 100 % de potentiel inexploité."""

    sqlite_path: str = "./data/okvorado.db"
    http_timeout_seconds: float = 10.0

    silent_threshold_hours: int = 1
    """Au-delà de N heures sans flux, un exportateur déclaré est dit silencieux."""

    restart_agent_host: str = "okvorado-restart-agent"
    restart_agent_port: int = 8098
    """Agent de restart d'Akvorado — service SÉPARÉ, seul à monter le socket docker.

    CONFIG_HARDCODE_OK: fallbacks de `BaseSettings`, surchargés par
    OKVORADO_RESTART_AGENT_HOST / _PORT (documentés dans .env.example). Le défaut
    est le nom DNS du service sur le réseau docker `akvorado_default`, pas une IP :
    les IP du bridge changent à chaque recréation de container.

    Okvorado ne monte JAMAIS `/var/run/docker.sock` : ce serait root sur l'hôte
    pour une application web exposée à des utilisateurs. L'agent n'expose qu'une
    capacité (redémarrer les services Akvorado d'une allowlist), protégée par token.
    """

    restart_agent_token: str = ""
    """Token d'authentification de l'agent. Vide = restart indisponible (fail-safe)."""

    restart_timeout_seconds: float = 180.0
    """Un restart + attente du retour `healthy` prend 60 à 120 s : le timeout HTTP
    par défaut (10 s) est bien trop court pour cette opération."""

    # CONFIG_HARDCODE_OK: fallback de BaseSettings, surchargé par la variable
    # d'environnement OKVORADO_FRAME_ANCESTORS (documentée dans .env.example) —
    # jamais une adresse de déploiement réelle, seulement le port par défaut
    # du stack local (GRAFANA_PORT dans .env.example).
    internal_networks: str = "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
    """Plages considérées comme le réseau INTERNE de ce déploiement (CIDR, CSV).

    RÉGLAGE DE DÉPLOIEMENT, pas une constante — décision utilisateur du
    2026-08-10, qui corrige une erreur de conception de ma part : ces bornes
    étaient écrites en dur dans `app/services/diagnostics.py` sous une
    justification « ce sont des préfixes RFC, donc universels ». L'argument ne
    tient pas : la RFC définit CE QUI EST privé, elle ne dit PAS ce que CE
    déploiement-ci utilise réellement.

    Ce que ce réglage décide : le filtre « source interne / destination
    interne » de la vue Convergence — celui-là même qui sépare le vrai motif du
    bruit (mesure décisive n°1 du 2026-08-07 : sans lui, le scan de ports
    Internet et le maillage P2P dominaient le classement).

    - Défaut = RFC1918 (10/8, 172.16/12, 192.168/16) + CGNAT RFC6598 (100.64/10),
      soit EXACTEMENT le comportement d'avant ce réglage : aucun déploiement
      existant ne change de comportement.
    - En entreprise, l'adressage est souvent 10/8 SEUL, sans aucun CGNAT.
      Laisser le CGNAT dans la liste y classerait « interne » du trafic qui ne
      l'est pas. À ajuster au déploiement — c'est le sens de ce réglage.

    Une valeur invalide ou vide est REFUSÉE bruyamment (voir
    `internal_networks_list`) : un filtre vide ne matcherait rien et l'écran
    afficherait « aucune convergence » comme si tout allait bien — le zéro
    silencieux que CLAUDE.md proscrit.
    """

    def internal_networks_list(self) -> list[IPv4Network | IPv6Network]:
        """Parse `internal_networks` en réseaux validés.

        Lève `ValueError` sur une entrée invalide ou une liste vide plutôt que
        de rendre une liste partielle : un filtre amputé produirait un écran
        FAUX sans le dire, ce qui est pire qu'une erreur visible.
        """
        return parse_internal_networks(self.internal_networks)

    interface_exclude_patterns: str = "lo,docker0,br-*,veth*"
    """Motifs d'interfaces SANS VALEUR NetFlow, exclues par défaut de la
    résolution SNMP (`app.services.exporters.filtrer_interfaces_exploitables`).
    CSV, un motif exact (`lo`, `docker0`) ou un préfixe wildcard (`br-*`,
    `veth*` — le `*` doit être en fin de motif, seul le préfixe compte).

    MESURE QUI MOTIVE CE RÉGLAGE (2026-08-11) : `outlet.yaml` en production
    déclarait pour un seul exportateur Docker du homelab 40 interfaces sans
    aucune valeur NetFlow (`lo`, `docker0`, 12 `br-*` bridges Docker, ~26
    `veth*` liens virtuels de conteneurs) — noyant les 3 interfaces réellement
    utiles. Aucun de ces bruits ne porte jamais de trafic routé mesurable : la
    loopback ne quitte pas la machine, les bridges/veth Docker sont des
    artefacts de virtualisation locale, pas des liens réseau physiques ou WAN.

    PAR MOTIF, JAMAIS PAR LISTE NOMINATIVE : le projet vise 350 routeurs SFR
    (cf. CLAUDE.md « L'auto-découverte n'est pas un confort, c'est la
    condition de déployabilité ») — une liste d'interfaces en dur ne tient
    pas à cette échelle, et c'est exactement le geste que ce projet supprime.

    CIBLE ENTREPRISE (pare-feu, routeurs) — volontairement PAS ajoutée au
    défaut, faute de mesure : les interfaces virtuelles d'un Palo Alto
    (`vlan.X`, `tunnel.X`) ou d'un routeur Cisco/SFR (`Null0`, `Loopback0`,
    `Tunnel0`) n'ont pas les mêmes noms qu'un bridge Linux, et inventer ces
    motifs sans les avoir vus sur un équipement réel produirait un filtre
    FAUX plus dangereux qu'utile (il écarterait potentiellement une vraie
    interface WAN nommée `Tunnel0`). Le réglage EST la réponse à ce besoin :
    chaque déploiement ajoute ses propres motifs via
    `OKVORADO_INTERFACE_EXCLUDE_PATTERNS` une fois les noms réels observés,
    plutôt que de faire deviner au code des conventions de nommage
    constructeur non vérifiées.

    Une interface DÉJÀ déclarée dans `outlet.yaml` (ex. un exploitant qui
    veut mesurer `docker0`) n'est JAMAIS écartée par ce filtre, quel que soit
    le motif — voir `filtrer_interfaces_exploitables(declared_names=...)`."""

    def interface_exclude_patterns_list(self) -> list[str]:
        """Parse `interface_exclude_patterns` en liste de motifs non vides."""
        return [part.strip() for part in self.interface_exclude_patterns.split(",") if part.strip()]

    snmp_community: str = ""
    """Communauté SNMPv2c utilisée pour interroger la MIB-II système
    (inventaire équipement, `app.services.snmp_inventory`). Vide = collecte
    désactivée (fail-safe, même choix que `restart_agent_token`) : jamais de
    valeur en dur, jamais loguée ni rendue en clair — voir `mask_community`
    dans `app.services.config_sections`, réutilisée telle quelle ici plutôt
    que dupliquée."""

    snmp_timeout_seconds: float = 3.0
    """Délai avant de considérer un agent SNMP muet (état `no_response`)."""

    snmp_poll_interval_seconds: int = 300
    """Période de la collecte automatique en tâche de fond (LOT inventaire)."""

    snmp_v3_username: str = ""
    """Nom d'utilisateur SNMPv3 (USM) par défaut, partagé par tous les
    équipements basculés en v3. Vide = v3 non configuré (fail-safe, même
    convention que `snmp_community`)."""

    snmp_v3_security_level: str = "authPriv"
    """`noAuthNoPriv` | `authNoPriv` | `authPriv` — niveau de sécurité USM
    appliqué au username ci-dessus."""

    snmp_v3_auth_protocol: str = "SHA256"
    """Protocole d'authentification USM (`MD5`, `SHA`, `SHA224`, `SHA256`,
    `SHA384`, `SHA512`). Ignoré si `snmp_v3_security_level='noAuthNoPriv'`."""

    snmp_v3_auth_password: str = ""
    """Mot de passe d'authentification SNMPv3. JAMAIS logué ni rendu en clair
    (même garde que `snmp_community`/`mask_community`) : ce champ ne doit
    apparaître dans aucun `log.*` ni aucun modèle rendu en HTML."""

    snmp_v3_priv_protocol: str = "AES256"
    """Protocole de chiffrement USM (`DES`, `AES`, `AES192`, `AES256`,
    `3DES`). Ignoré si `snmp_v3_security_level` != `authPriv`."""

    snmp_v3_priv_password: str = ""
    """Mot de passe de chiffrement (privacy) SNMPv3. JAMAIS logué ni rendu en
    clair, même garde que `snmp_v3_auth_password` ci-dessus."""

    ssh_ifindex_fallback_enabled: bool = False
    """Active le repli SSH (`ip -o link show`) pour résoudre les ifIndex quand
    SNMP rend `no_response`. Défaut `False` : DÉLIBÉRÉ, ne dégrade jamais la
    cible entreprise (Palo Alto, routeurs SFR répondent nativement en SNMP,
    cf. CLAUDE.md « transposable en entreprise »). SNMP reste la voie
    PRINCIPALE dans tous les cas ; SSH n'est qu'un COMPLÉMENT de secours,
    utile sur un parc homelab où `snmpd` n'est pas déployé. À activer via
    `OKVORADO_SSH_IFINDEX_FALLBACK_ENABLED=true` sur les déploiements
    concernés."""

    ssh_ifindex_user: str = "root"
    """Utilisateur SSH utilisé pour le sondage `ip -o link show` (repli
    ifIndex). Se règle via `OKVORADO_SSH_IFINDEX_USER` — jamais en dur dans
    la commande, l'adresse cible venant elle de la base des exportateurs."""

    ssh_ifindex_timeout_seconds: float = 5.0
    """Délai avant de considérer un hôte SSH muet (état `no_response`),
    même sémantique que `snmp_timeout_seconds`. Se règle via
    `OKVORADO_SSH_IFINDEX_TIMEOUT_SECONDS`."""

    snmp_version_default: str = "v2c"
    """`"v2c"` ou `"v3"` — version SNMP utilisée par défaut pour tout
    exportateur sans override explicite par device. Le parc migre
    progressivement de v2c vers v3 : la version effective par device est
    stockée dans `snmp_inventory.snmp_version` (colonne DB), ce réglage n'est
    que le défaut appliqué en l'absence d'override."""

    purge_poll_interval_seconds: int = 3600
    """Période de la tâche de fond de purge (Lot B/D).

    Même mécanisme que `snmp_poll_interval_seconds` : une tâche `asyncio` de
    fond dans `lifespan` (voir `app.main._purge_periodic_loop`), pas de
    scheduler externe. Défaut 1h : la purge (rétention ClickHouse) n'a pas
    besoin d'un cycle serré comme la collecte SNMP — c'est un ménage
    périodique, pas une donnée consultée en direct."""

    db_health_poll_interval_seconds: int = 300
    """Période de la collecte automatique de santé DB en tâche de fond.

    Même mécanisme que `snmp_poll_interval_seconds` : une tâche `asyncio` de
    fond dans `lifespan` (voir `app.main._db_health_periodic_loop`), pas de
    scheduler externe. 5 minutes par défaut : assez serré pour détecter une
    dérive de parts avant qu'elle n'atteigne les seuils ClickHouse (mesuré
    sur .6 : ~600 parts créées/h, soit ~10/min — un cycle de 5 min voit
    passer ~50 parts, largement suffisant pour repérer une accélération)."""

    db_health_history_max_age_days: int = 30
    """Âge maximal des lignes conservées dans `db_health_history` (purge
    périodique, même mécanisme que `_purge_periodic_loop` pour les autres
    tables internes)."""

    db_health_memory_limit_bytes: int = 2 * 1024**3
    """Limite mémoire du conteneur ClickHouse, pour le calcul du % utilisé.

    CONFIG_HARDCODE_OK: fallback de `BaseSettings`, surchargé par
    OKVORADO_DB_HEALTH_MEMORY_LIMIT_BYTES. Le défaut (2 Gio) correspond à la
    limite mesurée sur le déploiement de référence (.6, `docker inspect
    akvorado-clickhouse-1` → `HostConfig.Memory=2147483648`) — PAS une
    valeur universelle, à ajuster par déploiement via la variable d'env si
    le conteneur ClickHouse est dimensionné différemment."""

    frame_ancestors: str = "http://localhost:3000"
    """Origines autorisées à afficher Okvorado dans un `<iframe>` (CSP
    `frame-ancestors`), séparées par des espaces.

    DEMANDE UTILISATEUR : « qu'en prod je dise pas à mon manager qu'il faut
    jongler sur 4 url » — Grafana devient la porte d'entrée unique et embarque
    Okvorado dans un panneau. Sans cette allowlist, la CSP `frame-ancestors
    'none'` bloquerait tout affichage encadré, y compris depuis Grafana.

    Le défaut ci-dessus n'est PAS `*` : autoriser toute origine annulerait la
    protection anti-clickjacking pour gagner en confort — jamais fait ici. La
    valeur réelle du déploiement (l'origine publique de Grafana) se règle via
    `OKVORADO_FRAME_ANCESTORS` dans `.env` ; le défaut couvre le premier
    démarrage local (Grafana sur `localhost` au port `GRAFANA_PORT`, cf.
    `.env.example`)."""

    auth_user: str = "admin"
    """Identifiant de l'admin initial. Se règle via `OKVORADO_AUTH_USER`.

    Utilisé UNIQUEMENT au tout premier démarrage (aucun utilisateur en base) :
    voir `app.auth.ensure_bootstrap_user`, qui n'écrase jamais un utilisateur
    déjà créé."""

    auth_password: str = ""
    """Mot de passe en clair de l'admin initial — lu UNE FOIS au démarrage,
    haché en mémoire (PBKDF2-HMAC-SHA256), jamais réécrit en clair nulle part
    (ni en base, ni en log). Se règle via `OKVORADO_AUTH_PASSWORD`.

    Vide -> un mot de passe ALÉATOIRE est généré et affiché UNE SEULE FOIS
    dans les logs au premier démarrage (voir `app.auth.BootstrapAdmin` pour
    la justification complète du choix). Ce n'est PAS un défaut faible type
    "admin" : les routes protégées ici redémarrent des conteneurs, purgent
    ClickHouse et éditent la configuration réseau d'un parc — un identifiant
    prévisible serait un risque disproportionné pour gagner un confort de
    démarrage que le générateur aléatoire offre déjà (le stack démarre quand
    même sans .env)."""

    auth_session_secret: str = ""
    """Clé de signature HMAC des cookies de session. Se règle via
    `OKVORADO_AUTH_SESSION_SECRET` (générer avec `openssl rand -hex 32`).

    Vide -> génération aléatoire au démarrage : les sessions ne survivent
    alors pas à un redémarrage du processus (tous les cookies signés avec
    l'ancienne clé sont rejetés), ce qui est acceptable et volontaire — une
    clé par défaut connue à l'avance permettrait de FORGER un cookie de
    session valide pour n'importe quel compte."""

    auth_session_max_age_seconds: int = 12 * 3600
    """Durée de vie d'une session, en secondes. Défaut 12h : une journée de
    travail sans devoir se reconnecter, sans laisser une session ouverte
    indéfiniment sur un poste partagé."""

    auth_cookie_secure: bool = False
    """`Secure` sur le cookie de session. Défaut `False` car le stack tourne
    en HTTP nu par défaut (pas de TLS interne imposé, cf. contrainte "zéro
    dépendance à l'infrastructure du homelab" — pas de reverse proxy TLS
    supposé) : un cookie `Secure` ne serait JAMAIS envoyé par le navigateur
    sur une connexion HTTP, ce qui casserait l'authentification en silence.
    À activer via `OKVORADO_AUTH_COOKIE_SECURE=true` dès que l'app est servie
    derrière TLS (reverse proxy en entreprise)."""

    auth_login_max_attempts: int = 5
    """Nombre de tentatives de connexion autorisées par fenêtre glissante
    avant blocage temporaire (`app.auth.RateLimiter`) — protège `/login`
    contre la force brute sur le mot de passe."""

    auth_login_window_seconds: int = 300
    """Fenêtre glissante (secondes) sur laquelle `auth_login_max_attempts`
    s'applique. Défaut 5 minutes."""

    url_prefix: str = ""
    """Préfixe ajouté devant TOUS les chemins absolus rendus par les templates
    (`href`, `src`, `hx-get`/`hx-post`/`hx-delete`) — `""` = comportement actuel
    inchangé, aucun préfixe.

    RAISON D'ÊTRE : Grafana peut proxifier Okvorado via une datasource de
    plugin (`GET`/`POST`/`DELETE` passent, corps intact, accès soumis à une
    session Grafana). L'URL servie devient alors
    `/api/datasources/proxy/uid/<uid>/exporters` au lieu de `/exporters` — un
    chemin absolu écrit en dur (`href="/exporters"`) se résoudrait à la racine
    de Grafana, cassant CSS/JS/navigation.

    MESURÉ (pas supposé) : la balise `<base href>` NE corrige PAS ce cas.
    Elle ne réécrit que les chemins RELATIFS ; un chemin qui commence par `/`
    (absolu) ignore `<base>` et se résout toujours à la racine du document,
    conformément à la résolution d'URL standard (RFC 3986 §5.3 : une référence
    de chemin absolu remplace entièrement le chemin de la base). D'où le choix
    retenu : préfixer explicitement chaque chemin via le filtre Jinja
    `prefixed` plutôt que de compter sur `<base href>`.

    Se règle via `OKVORADO_URL_PREFIX` (ex. `/api/datasources/proxy/uid/abc123`).
    Ne JAMAIS terminer par `/` : le filtre `prefixed` concatène directement
    (`{prefix}{chemin}`, chemin commençant toujours par `/`) — un `/` final
    produirait un double slash."""

    @property
    def restart_agent_url(self) -> str:
        return f"http://{self.restart_agent_host}:{self.restart_agent_port}"

    @property
    def effective_clickhouse_host(self) -> str:
        """Hôte ClickHouse : le sien s'il est précisé, sinon l'hôte partagé."""
        return self.clickhouse_host or self.akvorado_host

    @property
    def effective_console_host(self) -> str:
        """Hôte de la console Akvorado : le sien s'il est précisé, sinon l'hôte partagé."""
        return self.console_host or self.akvorado_host

    @property
    def clickhouse_url(self) -> str:
        return f"http://{self.effective_clickhouse_host}:{self.clickhouse_port}"

    @property
    def outlet_metrics_url(self) -> str:
        return f"http://{self.akvorado_host}:{self.outlet_port}{self.outlet_metrics_path}"

    @property
    def akvorado_console_url(self) -> str:
        return f"http://{self.effective_console_host}:{self.console_port}"


settings = Settings()
