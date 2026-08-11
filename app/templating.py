"""Moteur de templates partagé et ses filtres de présentation.

Défini ici plutôt que dans `app.main` pour que TOUT consommateur (routers,
tests de rendu) obtienne le même environnement Jinja, filtres compris. Un
template rendu par un moteur dépourvu de ces filtres lèverait
`TemplateAssertionError` — le filtre doit vivre au même niveau que le moteur.
"""

import hashlib
import logging
import sqlite3
from pathlib import Path
from typing import Any

from fastapi import Request
from fastapi.templating import Jinja2Templates
from jinja2 import pass_context

from app.config import settings
from app.db import open_connection
from app.services.diagnostics import resolve_protocol_label
from app.services.flow_sample import format_display_address

log = logging.getLogger(__name__)

TEMPLATES_DIR = Path(__file__).parent / "templates"


def _auth_context(request: Request) -> dict[str, Any]:
    """Publie l'état d'authentification à TOUS les templates sans que chaque
    route ait à le repasser explicitement (LOT auth, étendu LOT accounts).

    `request.state.auth_default_password_warning`, `auth_username` et
    `auth_role` sont posés par le middleware `app.main.require_authentication`
    — un routeur qui les oublierait dans son contexte de rendu ferait
    disparaître le bandeau d'avertissement (ou l'identité affichée) en
    silence, exactement le genre de défaut que ce mécanisme évite (même
    logique que `static_version` en global Jinja plutôt qu'en contexte par
    route, voir `build_templates` ci-dessous).

    `auth_username`/`auth_role` alimentent l'état de connexion affiché dans
    `base.html` (LOT accounts, demande utilisateur : « pas de management de
    compte, etat de connexion user » — aujourd'hui `base.html` affiche
    « Déconnexion » sans dire QUI est connecté)."""
    return {
        "auth_default_password_warning": getattr(
            request.state, "auth_default_password_warning", False
        ),
        "auth_username": getattr(request.state, "auth_username", None),
        "auth_role": getattr(request.state, "auth_role", None),
    }


def _pending_changes_context(_request: Request) -> dict[str, Any]:
    """Publie le NOMBRE de changements de configuration en attente à TOUS les
    templates, pour le bandeau global de `base.html`.

    DÉFAUT MESURÉ EN PRODUCTION (2026-08-11) — demande explicite de
    l'utilisateur : « il faut surtout soit mettre un bouton pour appliquer ce
    qui est en attente, quelque chose du genre ».

    Ce qui s'est passé : les écrans METTENT EN ATTENTE (`stage_change`) sans
    rien écrire, et SEUL `/config` portait le bouton « Appliquer ». Ayant
    déclaré son pare-feu depuis un écran dépourvu de ce bouton, l'utilisateur a
    cru que l'opération échouait et l'a refaite — 21 changements se sont
    accumulés dans `pending_config_changes` sans qu'aucun écran ne le signale.

    POURQUOI ICI, ET PAS UN BOUTON AJOUTÉ AUX DEUX ÉCRANS MANQUANTS
    (`exporters.py`, `config_sections.py`) : ce serait corriger les deux
    occurrences du jour et laisser le défaut intact — le prochain écran qui
    mettra en attente l'oubliera à son tour. Publié en context processor, le
    compte est disponible pour `base.html` sur TOUTE page qui hérite du
    gabarit, sans qu'aucun routeur n'ait à y penser. Même raisonnement que
    `_auth_context` et que `static_version` (voir `build_templates`), et même
    famille de défauts que celui corrigé pour `akvorado_url`.

    OUVERTURE DIRECTE DE SQLITE, ET NON UNE DÉPENDANCE FASTAPI : un context
    processor ne reçoit QUE le `Request`, il ne traverse pas le système
    d'injection — `settings.sqlite_path` est donc lu ici. Le coût est
    acceptable : c'est un `COUNT(*)` sur une table minuscule (la file est vidée
    à chaque application), en lecture seule, sur un fichier local.

    ZÉRO SILENCIEUX (CLAUDE.md, règle dure du projet) : un échec de lecture
    (base verrouillée, fichier absent, table manquante) rend `None` — un état
    DISTINCT signifiant « indéterminé » — et JAMAIS `0`. Un `0` serait
    indiscernable d'une file réellement vide : le bandeau disparaîtrait en
    affirmant faussement qu'il n'y a rien à appliquer, ce qui est exactement le
    mensonge rassurant que ce projet proscrit. `base.html` n'affiche le bandeau
    que sur un entier strictement positif, donc `None` n'affiche rien plutôt
    que d'affirmer quoi que ce soit.
    """
    try:
        # `open_connection` (app/db.py) plutôt qu'un `sqlite3.connect` nu :
        # porte d'entrée UNIQUE vers SQLite depuis le 2026-08-11, qui garantit
        # `row_factory = sqlite3.Row`. Cette lecture-ci n'indexe que par
        # position, mais la règle est SANS EXCEPTION — c'est exactement le
        # « ce site-là n'en a pas besoin » qui a laissé la boucle de collecte
        # SNMP ouvrir une connexion nue et ne jamais fonctionner.
        conn = open_connection()
        try:
            row = conn.execute("SELECT COUNT(*) FROM pending_config_changes").fetchone()
        finally:
            conn.close()
    except (sqlite3.Error, OSError):
        log.error(
            "lecture du compte de changements en attente impossible, "
            "bandeau masque (etat indetermine, jamais '0'): sqlite_path=%s",
            settings.sqlite_path,
            exc_info=True,
        )
        return {"pending_changes_count": None}

    if row is None:
        # Un COUNT(*) rend toujours une ligne : une absence de ligne signale une
        # anomalie du pilote, pas une file vide. On ne l'interprète donc PAS
        # comme 0 (même garde zéro silencieux que le bloc d'exception ci-dessus).
        log.error("COUNT(*) sur pending_config_changes n'a rendu aucune ligne (anomalie)")
        return {"pending_changes_count": None}

    return {"pending_changes_count": int(row[0])}


def humanize_bytes(value: int | float | None) -> str:
    """Formate un volume d'octets en unité lisible.

    Un opérateur ne lit pas « 8103663968 octets », il lit « 7.5 Go ».
    """
    if value is None:
        return "—"
    size = float(value)
    for unit in ("o", "Ko", "Mo", "Go", "To"):
        if size < 1024 or unit == "To":
            return f"{size:.0f} {unit}" if unit == "o" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} To"


def humanize_number(value: int | float | None) -> str:
    """Sépare les milliers par une espace (1453825 -> 1 453 825)."""
    if value is None:
        return "—"
    return f"{int(value):,}".replace(",", " ")


def compute_static_version() -> str:
    """Empreinte courte des fichiers statiques, pour invalider le cache navigateur.

    Sans cette empreinte dans l'URL, le navigateur reconduit son CSS en cache
    après un déploiement. Constaté le 2026-08-05 : l'écran de configuration
    s'affichait entièrement SANS STYLE (liens bleus soulignés, cartes sans
    bordure) — le navigateur servait une version antérieure du fichier, qui
    s'arrêtait au `@media` et ignorait toutes les règles ajoutées ensuite.

    L'empreinte est calculée UNE FOIS au démarrage : le contenu statique ne
    change pas en cours d'exécution, et la recalculer à chaque requête coûterait
    une lecture disque pour rien.
    """
    static_dir = Path(__file__).parent / "static"
    digest = hashlib.sha256()
    try:
        for file in sorted(static_dir.glob("*")):
            if file.is_file():
                digest.update(file.read_bytes())
    except OSError:
        # Répertoire illisible : on retombe sur une valeur fixe plutôt que de
        # faire échouer le rendu de TOUTES les pages pour un problème de cache.
        return "dev"
    return digest.hexdigest()[:12]


STATIC_VERSION = compute_static_version()


@pass_context
def prefixed(_context: object, path: str) -> str:
    """Préfixe un chemin ABSOLU (commençant par `/`) avec `settings.url_prefix`.

    Existe pour le déploiement derrière le proxy Grafana (voir docstring de
    `Settings.url_prefix`) : `<base href>` ne réécrit PAS les chemins absolus
    (mesuré — RFC 3986 §5.3, une référence de chemin absolu remplace tout le
    chemin de la base), donc chaque `href`/`src`/`hx-get`/... écrit en dur
    (`/exporters`, `/static/style.css`) doit passer par ce filtre plutôt que
    par une balise `<base>` qui ne corrigerait rien pour ces cas.

    `settings.url_prefix` est lu à CHAQUE appel (pas figé à l'import comme
    `STATIC_VERSION`) : un test qui bascule `settings.url_prefix` en cours de
    session doit voir l'effet immédiatement, sans redémarrer l'application.

    `@pass_context` est OBLIGATOIRE ici, pas cosmétique : Jinja2 replie (constant
    folding) tout filtre appliqué à un argument littéral (`'/x' | prefixed`) en
    évaluant l'appel UNE SEULE FOIS À LA COMPILATION du template, puis fige le
    résultat dans le bytecode compilé — mesuré (2026-08-08) avec ce filtre AVANT
    ce décorateur : `settings.url_prefix` changé après la première compilation
    restait invisible pour tous les rendus suivants du même template en cache
    (silencieux, aucune exception). `@pass_context` marque le filtre comme
    dépendant du contexte de rendu, ce qui désactive ce repli constant (le seul
    argument ajouté, `_context`, n'est pas utilisé : la lecture réelle passe
    par `settings`, mais la présence du décorateur suffit à forcer une
    ré-évaluation à CHAQUE rendu).

    Préfixe vide (défaut) -> chemin inchangé, comportement actuel préservé à
    l'identique. Un chemin qui ne commence pas par `/` (déjà relatif, ou une
    URL externe absolue) traverse sans modification : seuls les chemins
    absolus-racine sont concernés par le problème que ce filtre corrige.
    """
    prefix = settings.url_prefix
    if not prefix or not path.startswith("/"):
        return path
    return f"{prefix}{path}"


def build_templates(directory: str | Path = TEMPLATES_DIR) -> Jinja2Templates:
    """Construit un moteur Jinja avec les filtres de présentation d'Okvorado."""
    # `_pending_changes_context` alimente le bandeau global « changements en
    # attente » de `base.html`. Branché ICI, au même niveau que `_auth_context`
    # : c'est ce qui garantit qu'AUCUN écran ne peut l'oublier (voir la
    # docstring du processeur pour le défaut mesuré le 2026-08-11).
    engine = Jinja2Templates(
        directory=str(directory),
        context_processors=[_auth_context, _pending_changes_context],
    )
    engine.env.filters["humanize_bytes"] = humanize_bytes
    engine.env.filters["humanize_number"] = humanize_number
    # Adresse IPv4-mappée (`::ffff:x.x.x.x`) -> forme v4 lisible ; IPv6 native
    # inchangée. Défaut mesuré à l'écran le 2026-08-07, cf. docstring de
    # `format_display_address` (flow_sample.py) pour le piège `cutIPv6` évité.
    engine.env.filters["format_ip"] = format_display_address
    # Numéro de protocole IP (6/17/1/58...) -> nom lisible (TCP/UDP/ICMP/...).
    # Source unique du mécanisme : `app.services.diagnostics.resolve_protocol_label`
    # (défaut mesuré à l'écran le 2026-08-07 : colonne Protocole affichait le
    # numéro brut sur le tableau de convergence).
    engine.env.filters["protocol_label"] = resolve_protocol_label
    # Préfixe tout chemin absolu-racine (`/exporters`, `/static/x.css`) pour le
    # déploiement derrière le proxy Grafana — voir docstring de `prefixed()` et
    # de `Settings.url_prefix` (measure : `<base href>` ne suffit pas ici).
    engine.env.filters["prefixed"] = prefixed
    # Disponible dans TOUS les templates sans avoir à le passer route par route
    # (une route qui l'oublierait réintroduirait silencieusement le bug de cache).
    engine.env.globals["static_version"] = STATIC_VERSION

    # MÊME RAISON, DÉFAUT MESURÉ À L'ÉCRAN (2026-08-09) : `akvorado_url` est
    # utilisée par le lien « Akvorado ↗ » de `base.html`, donc par TOUTES les
    # pages — mais elle était passée à la main par chaque routeur
    # (`app/routers/config.py`, `views.py`...). Les écrans d'authentification,
    # nouveaux, ne la fournissaient pas : Jinja rend alors une chaîne VIDE et
    # `<a href="">` renvoie sur la page courante. Constaté sur l'écran
    # Sécurité, où « Akvorado ↗ » pointait vers `/settings/security`.
    #
    # Un lien du gabarit COMMUN ne doit pas dépendre de ce que chaque routeur
    # pense à passer : toute page future oublierait la variable et le défaut
    # reviendrait, silencieusement (aucune erreur, juste un lien mort).
    # Lu à chaque construction du moteur, comme le reste de la configuration.
    engine.env.globals["akvorado_url"] = settings.akvorado_console_url

    # DÉFAUT PAR DÉFAUT du compte de changements en attente — `None`, jamais 0.
    #
    # `_pending_changes_context` ne s'exécute QUE via `TemplateResponse` (c'est
    # le mécanisme des context processors de Starlette). Tout rendu qui court-
    # circuite ce chemin — `env.get_template(...).render(...)`, utilisé par
    # plusieurs tests de gabarit, et n'importe quel rendu direct futur —
    # n'aurait donc PAS la variable et `base.html` lèverait `UndefinedError` :
    # une page blanche, sur un écran qui fonctionnait, pour un bandeau qui
    # n'est qu'un confort. Le global fournit le repli ; le processeur écrase ce
    # repli par la vraie mesure sur le chemin normal.
    #
    # ZÉRO SILENCIEUX : le repli vaut `None` (« indéterminé »), PAS `0`. Un `0`
    # affirmerait que la file est vide sur un chemin où on ne l'a jamais lue.
    # `base.html` teste `is not none` avant `> 0` : `None` n'affiche rien.
    engine.env.globals["pending_changes_count"] = None
    return engine


templates = build_templates()
"""Instance partagée — à utiliser partout plutôt que d'instancier Jinja2Templates."""
