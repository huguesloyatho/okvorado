"""Router — édition à la souris des sections de configuration Akvorado.

Aujourd'hui, la configuration d'Akvorado vit dans 4 fichiers YAML (`outlet.yaml`,
`akvorado.yaml`, `console.yaml`, `inlet.yaml`) qu'un opérateur doit éditer en
SSH. Ce module expose CHAQUE section utile du catalogue (plan d'adressage,
noms d'AS, filtres enregistrés, widgets d'accueil, options de Visualize, ports
d'écoute, règles de classification, rétention Kafka) comme un écran web
indépendant, avec tables éditables à la souris et validation métier avant
mise en file d'attente.

La lecture/écriture générique du YAML (`read_section` / `write_section` /
`compute_file_hash` / `ConcurrentModificationError`) et le catalogue des
sections (`SECTIONS` / `ConfigSection` / `get_section` / `list_sections`)
viennent du lot socle (`app.clients.yaml_editor`, `app.services.config_sections`)
— ce module ne fait QUE traduire des requêtes HTTP (formulaires
`application/x-www-form-urlencoded`) en changements structurés, les valider
via `section.validator`, et les mettre en file d'attente via
`app.services.config_writer` (déjà utilisé par `app/routers/config.py`, même
pattern).

⚠️ La `key` de section vient TOUJOURS de `SECTIONS` (catalogue fermé, jamais
d'une saisie libre) : `get_section(key)` lève `ValueError` sur une clé
inconnue -> traduit en 404 ici, jamais d'écriture d'un chemin arbitraire.

⚠️ `apply_pending_changes` (dans `app.services.config_writer`, hors périmètre
de ce lot) n'connaît aujourd'hui QUE les 4 `change_type` liés aux exportateurs
(`add_exporter`, `update_exporter`, `delete_exporter`, `fix_ifindex`) — son
`_APPLIERS` et son alias `ChangeType` sont un `Literal` fermé. Les changements
mis en file ici portent le type `"update_section"` : ils sont bien stockés et
listés dans la file d'attente commune (même table SQLite), mais tant que
`config_writer.py` n'apprend pas à les appliquer (ajouter un applier qui
route par `payload["section_key"]` vers `write_section`), le bouton
« Appliquer » existant ne les traduira pas en écriture YAML. Signalé dans le
rapport final — gap d'intégration entre lots, pas une régression introduite ici.

Dépendances (à câbler dans `app/main.py`, LOT 0) :
  - `get_db_connection` : même connexion SQLite que `app/routers/config.py`.
  - `get_config_dir` : répertoire contenant les 4 fichiers YAML d'Akvorado
    (chaque `ConfigSection.file` du catalogue y est résolu par simple jointure
    de chemin, ex. `Path(config_dir) / section.file`). En prod, c'est le
    répertoire parent de `settings.akvorado_config_path`.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import sqlite3
from dataclasses import dataclass
from html import escape
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Form, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.templating import Jinja2Templates

from app.services.config_sections import (
    MAIN_TABLE_ONLY_COLUMNS,
    SCHEMA_COLUMN_CHOICES,
    ConfigSection,
    check_cascade_order,
    get_section,
    is_env_reference,
    list_sections,
    mask_community,
)
from app.services.config_writer import (
    ChangeType,
    discard_change,
    list_pending_changes,
    stage_change,
)
from app.services.csv_io import (
    ASNS_CSV_FORMAT,
    EXPORTER_CLASSIFIERS_CSV_FORMAT,
    INTERFACE_CLASSIFIERS_CSV_FORMAT,
    NETWORKS_CSV_FORMAT,
    SAVED_FILTERS_CSV_FORMAT,
    CsvFormat,
    CsvRow,
    export_csv,
    parse_csv,
)
from app.templating import build_templates

log = logging.getLogger(__name__)

router = APIRouter(tags=["config-sections"])

_DEFAULT_AUTHOR = "ui"
_MAX_FIELD_LENGTH = 512
_MIN_PORT = 1
_MAX_PORT = 65535
_MAX_CSV_UPLOAD_BYTES = 1_048_576  # 1 Mo — refus explicite au-delà, jamais un timeout silencieux
_UPDATE_SECTION: ChangeType = "update_section"
"""`config_writer.ChangeType` est un Literal fermé sur les 4 types liés aux
exportateurs (hors périmètre de ce lot, voir docstring de module). Le cast
documente explicitement l'écart plutôt que de le masquer."""


# ---------------------------------------------------------------------------
# Dépendances — placeholders câblés par app/main.py (LOT 0)
# ---------------------------------------------------------------------------


def get_db_connection() -> sqlite3.Connection:
    """Placeholder — LOT 0 fournit la vraie connexion via app/db.py.

    Jamais appelée telle quelle en test (toujours surchargée par
    `app.dependency_overrides`), comme dans `app/routers/config.py`.
    """
    raise RuntimeError(
        "get_db_connection non câblée : app/main.py (LOT 0) doit surcharger "
        "cette dépendance avec la connexion SQLite réelle."
    )


def get_config_dir() -> str:
    """Placeholder — LOT 0 câble le répertoire des 4 fichiers YAML d'Akvorado
    (répertoire parent de `settings.akvorado_config_path`)."""
    raise RuntimeError(
        "get_config_dir non câblée : app/main.py (LOT 0) doit surcharger "
        "cette dépendance avec le répertoire contenant outlet.yaml/akvorado.yaml/"
        "console.yaml/inlet.yaml."
    )


def get_templates() -> Jinja2Templates:
    return build_templates()


DbConnection = Annotated[sqlite3.Connection, Depends(get_db_connection)]
ConfigDir = Annotated[str, Depends(get_config_dir)]
Templates = Annotated[Jinja2Templates, Depends(get_templates)]


# ---------------------------------------------------------------------------
# Résolution de chemin — jamais dérivée d'une entrée utilisateur
# ---------------------------------------------------------------------------


def _resolve_path(config_dir: str, section: ConfigSection) -> str:
    """Chemin absolu du fichier YAML porté par une section du catalogue.

    `section.file` provient TOUJOURS de `SECTIONS` (catalogue fermé importé au
    chargement du module), jamais d'un paramètre de requête : aucune traversée
    de chemin possible depuis l'extérieur.
    """
    return str(Path(config_dir) / section.file)


# ---------------------------------------------------------------------------
# Erreurs — messages lisibles, jamais de 500
# ---------------------------------------------------------------------------


def _error_response(errors: list[str]) -> HTMLResponse:
    items = "".join(f"<li>{escape(err)}</li>" for err in errors)
    return HTMLResponse(
        f'<div class="notice notice-crit"><strong>Changement refusé</strong><ul>{items}</ul></div>',
        status_code=422,
    )


def _section_not_found(key: str) -> HTMLResponse:
    log.error("config_sections: section inconnue demandee: key=%s", key)
    return HTMLResponse(
        f'<div class="notice notice-crit"><strong>Section inconnue</strong>'
        f"<p>{escape(key)} ne correspond à aucune section de configuration connue.</p></div>",
        status_code=404,
    )


def _get_section_or_none(key: str) -> ConfigSection | None:
    try:
        return get_section(key)
    except ValueError:
        return None


# ---------------------------------------------------------------------------
# Validation champ par champ — messages lisibles avant d'atteindre le validator
# ---------------------------------------------------------------------------


def _validate_cidr_input(cidr: str) -> str | None:
    try:
        ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return f"CIDR invalide : {cidr!r}"
    return None


def _validate_required_text(value: str, *, field_label: str) -> str | None:
    if not value or not value.strip():
        return f"le champ « {field_label} » ne peut pas être vide"
    if len(value) > _MAX_FIELD_LENGTH:
        return f"« {field_label} » trop long ({len(value)} caractères, max {_MAX_FIELD_LENGTH})"
    return None


def _validate_asn_input(asn_raw: str) -> tuple[int | None, str | None]:
    try:
        asn = int(asn_raw)
    except (TypeError, ValueError):
        return None, f"numéro d'AS non entier : {asn_raw!r}"
    if asn <= 0:
        return None, f"numéro d'AS invalide (doit être positif) : {asn}"
    return asn, None


def _validate_port_input(port_raw: str) -> tuple[int | None, str | None]:
    try:
        port = int(port_raw)
    except (TypeError, ValueError):
        return None, f"port non entier : {port_raw!r}"
    if not (_MIN_PORT <= port <= _MAX_PORT):
        return None, f"port hors bornes ({_MIN_PORT}-{_MAX_PORT}) : {port}"
    return port, None


# ---------------------------------------------------------------------------
# Construction du payload par section — mapping / list, table par table
# ---------------------------------------------------------------------------


def _apply_networks_form(
    current: dict[str, Any] | None, action: str, form: dict[str, str]
) -> tuple[dict[str, Any] | None, list[str]]:
    working = dict(current or {})
    if action == "add":
        cidr = form.get("cidr", "")
        name = form.get("name", "")
        errors = [
            err
            for err in (
                _validate_cidr_input(cidr),
                _validate_required_text(name, field_label="nom"),
            )
            if err is not None
        ]
        if errors:
            return None, errors
        working[cidr] = {"name": name.strip()}
        return working, []
    if action == "remove":
        working.pop(form.get("cidr", ""), None)
        return working, []
    return None, [f"action inconnue : {action!r}"]


def _apply_asns_form(
    current: dict[str, Any] | None, action: str, form: dict[str, str]
) -> tuple[dict[str, Any] | None, list[str]]:
    working = dict(current or {})
    if action == "add":
        asn, asn_err = _validate_asn_input(form.get("asn", ""))
        name_err = _validate_required_text(form.get("name", ""), field_label="nom")
        errors = [err for err in (asn_err, name_err) if err is not None]
        if errors or asn is None:
            return None, errors
        working[str(asn)] = form.get("name", "").strip()
        return working, []
    if action == "remove":
        working.pop(form.get("asn", ""), None)
        return working, []
    return None, [f"action inconnue : {action!r}"]


def _apply_saved_filters_form(
    current: list[Any] | None, action: str, form: dict[str, str]
) -> tuple[list[Any] | None, list[str]]:
    working = list(current or [])
    if action == "add":
        description = form.get("description", "")
        content = form.get("content", "")
        errors = [
            err
            for err in (
                _validate_required_text(description, field_label="description"),
                _validate_required_text(content, field_label="expression"),
            )
            if err is not None
        ]
        if errors:
            return None, errors
        working.append({"description": description.strip(), "content": content.strip()})
        return working, []
    if action == "remove":
        return _remove_by_index(working, form.get("index", ""))
    return None, [f"action inconnue : {action!r}"]


def _apply_flow_inputs_form(
    current: list[Any] | None, action: str, form: dict[str, str]
) -> tuple[list[Any] | None, list[str]]:
    working = list(current or [])
    if action == "add":
        flow_type = form.get("type", "")
        decoder = form.get("decoder", "")
        host = form.get("host", "").strip() or "0.0.0.0"  # noqa: S104 - littéral de formulaire, pas un bind
        port, port_err = _validate_port_input(form.get("port", ""))
        errors = [
            err
            for err in (
                _validate_required_text(flow_type, field_label="type"),
                _validate_required_text(decoder, field_label="décodeur"),
                port_err,
            )
            if err is not None
        ]
        if errors or port is None:
            return None, errors
        working.append(
            {"type": flow_type.strip(), "decoder": decoder.strip(), "listen": f"{host}:{port}"}
        )
        return working, []
    if action == "remove":
        return _remove_by_index(working, form.get("index", ""))
    return None, [f"action inconnue : {action!r}"]


# ---------------------------------------------------------------------------
# Découverte des interfaces (`metadata_providers`) — la cascade SNMP/static
# ---------------------------------------------------------------------------
#
# RÈGLE STRUCTURANTE DE TOUT CE BLOC : les fournisseurs que cet écran ne sait
# pas construire (`static`, `gnmi`, `bioris`) sont RELUS ET REPOSÉS TELS QUELS,
# jamais reconstruits champ par champ.
#
# Ce n'est pas de la prudence abstraite. En production, le fournisseur `static`
# pèse ~200 lignes : 12 exportateurs et, pour chacun, la table de ses ifIndex.
# Le reconstruire — même « à l'identique » — c'est risquer d'en perdre un champ
# que cet écran ignore. Et un ifIndex perdu ne produit AUCUNE erreur : les flux
# concernés retombent simplement en `unknown`. C'est très exactement le défaut
# vécu le 2026-08-05 (76 000 flux classés `unknown` après une dérive d'ifIndex).
#
# Le seul objet que ce module construit est le fournisseur `snmp`. Tout le
# reste est déplacé, jamais réécrit.


def guard_static_provider_survives(current: Any, new_value: Any) -> list[str]:
    """Refuse tout changement qui ferait DISPARAÎTRE un fournisseur `static`.

    DÉFAUT MESURÉ (2026-08-07, end-to-end) : la suppression de masse
    (`action=remove_selected`) est traitée AVANT le dispatch par section, et
    suit la FORME de la donnée — une liste indexée — sans regarder de quelle
    section il s'agit. `metadata.providers` étant une liste, un simple
    `POST {action: remove_selected, selected: ["0"]}` retirait le fournisseur
    `static` et retournait **HTTP 201**. Le validateur ne rattrapait rien : une
    cascade `[snmp]` seule est parfaitement valide.

    Conséquence : les ~200 lignes de table d'ifIndex (12 exportateurs) partaient
    en file d'attente, étaient écrites, l'outlet redémarrait sans la moindre
    erreur — et tout ce que SNMP ne résout pas retombait en `unknown`. C'est le
    défaut du 2026-08-05 (76 000 flux `unknown`), en pire, et sur un chemin qui
    affiche un succès.

    Le garde-fou est posé ICI plutôt que dans le validateur de section parce
    qu'un validateur ne voit QUE la nouvelle valeur : il ne peut pas distinguer
    « il n'y a jamais eu de static » (légitime) de « le static a été supprimé »
    (ce qu'on refuse). Il faut les deux états, donc l'appelant.

    Ce n'est pas un refus de principe de supprimer un `static` — c'est un refus
    de le supprimer PAR CE CHEMIN, qui ne le nomme pas et ne le montre pas. La
    section a un écran dédié pour cela.
    """
    if not isinstance(current, list) or not isinstance(new_value, list):
        return []

    def _count_static(providers: list[Any]) -> int:
        return sum(
            1
            for provider in providers
            if isinstance(provider, dict) and str(provider.get("type", "")) == "static"
        )

    before = _count_static(current)
    after = _count_static(new_value)
    if after >= before:
        return []

    return [
        f"ce changement supprimerait {before - after} fournisseur(s) « static » de la "
        "cascade. C'est la table d'ifIndex saisie à la main : sans elle, toute "
        "interface que SNMP ne résout pas retombe en « unknown », sans aucune "
        "erreur. Utilisez l'écran « Découverte des interfaces » pour modifier la "
        "cascade fournisseur par fournisseur."
    ]


def _split_providers(current: Any) -> tuple[list[Any], int | None]:
    """Sépare la cascade courante en `(liste, index du fournisseur snmp)`.

    Retourne la liste TELLE QUELLE (mêmes objets, non copiés en profondeur) :
    c'est ce qui garantit que `static` ressort identique — on ne le touche pas.
    `None` en second membre si aucun fournisseur `snmp` n'est déclaré.
    """
    providers = list(current or [])
    for index, provider in enumerate(providers):
        if isinstance(provider, dict) and str(provider.get("type", "")) == "snmp":
            return providers, index
    return providers, None


def _build_snmp_provider(form: dict[str, str], existing: Any) -> tuple[dict[str, Any], list[str]]:
    """Construit le fournisseur `snmp` depuis le formulaire.

    `existing` (le fournisseur snmp déjà en place, ou `None`) sert de BASE :
    les clés qu'Akvorado accepte mais que cet écran n'expose pas (`ports`,
    `agents`) survivent à une modification faite ici. Sans cette base, régler
    `workers` depuis l'écran effacerait un mappage d'agents SNMP posé en SSH —
    une perte silencieuse de configuration, sur un chemin de succès.
    """
    provider: dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}
    provider["type"] = "snmp"

    errors: list[str] = []

    for field_name, form_key in (
        ("workers", "workers"),
        ("poller-retries", "poller_retries"),
    ):
        raw = form.get(form_key, "").strip()
        if not raw:
            # Champ laissé vide = « ne pas fixer ce réglage » : on retire la clé
            # pour qu'Akvorado applique SON défaut, plutôt que d'écrire un 0 qui
            # serait un réglage bien réel (et absurde).
            provider.pop(field_name, None)
            continue
        try:
            provider[field_name] = int(raw)
        except ValueError:
            errors.append(f"« {field_name} » doit être un entier (obtenu : {raw!r})")

    timeout = form.get("poller_timeout", "").strip()
    if timeout:
        provider["poller-timeout"] = timeout
    else:
        provider.pop("poller-timeout", None)

    credentials, credential_errors = _build_snmp_credentials(form, provider.get("credentials"))
    errors.extend(credential_errors)
    provider["credentials"] = credentials

    return provider, errors


def _build_snmp_credentials(
    form: dict[str, str], existing: Any
) -> tuple[dict[str, Any], list[str]]:
    """Construit la table `sous-réseau -> {communities: [...]}`.

    Un seul couple (sous-réseau, communauté) est saisi par soumission — la
    table s'enrichit couple par couple, comme les autres écrans de cette page.
    Un parc hétérogène a souvent une communauté par site : les entrées
    existantes sont donc CONSERVÉES, et une réécriture du même sous-réseau
    remplace uniquement celui-là.

    ⚠️ Aucun message d'erreur ne cite la communauté (secret) — seulement le
    sous-réseau, qui n'en est pas un.
    """
    credentials: dict[str, Any] = dict(existing) if isinstance(existing, dict) else {}
    errors: list[str] = []

    subnet = form.get("subnet", "").strip()
    community = form.get("community", "").strip()

    if not subnet and not community:
        # Rien de nouveau à déclarer : la personne règle `workers` ou retire une
        # entrée. Ce n'est PAS une erreur.
        return credentials, errors

    if not subnet:
        errors.append("le champ « sous-réseau » ne peut pas être vide")
    else:
        cidr_error = _validate_cidr_input(subnet)
        if cidr_error is not None:
            errors.append(cidr_error)

    if not community:
        errors.append(f"aucune communauté fournie pour le sous-réseau {subnet!r}")
    elif len(community) > _MAX_FIELD_LENGTH:
        # La LONGUEUR est citée, jamais la valeur.
        errors.append(
            f"la communauté fournie est trop longue ({len(community)} caractères, "
            f"max {_MAX_FIELD_LENGTH})"
        )

    if errors:
        return credentials, errors

    # DÉFAUT MESURÉ (2026-08-07) : `credentials[subnet] = {"communities": [x]}`
    # remplaçait TOUT le mapping du sous-réseau. Or une liste à plusieurs
    # communautés est le motif normal d'une ROTATION : on déclare l'ancienne ET
    # la nouvelle en parallèle le temps que le parc bascule. Ajouter la nouvelle
    # depuis l'écran effaçait donc l'ancienne — et les équipements pas encore
    # migrés cessaient de répondre, sans erreur, sur un HTTP 201.
    #
    # Les champs voisins éventuels du sous-réseau (que cet écran n'expose pas)
    # sont préservés pour la même raison : ce qu'on ne sait pas construire, on
    # ne le réécrit pas.
    existing_entry = credentials.get(subnet)
    entry = dict(existing_entry) if isinstance(existing_entry, dict) else {}
    previous = entry.get("communities")
    communities = [str(item) for item in previous] if isinstance(previous, list) else []
    if community not in communities:
        communities.append(community)
    entry["communities"] = communities
    credentials[subnet] = entry
    return credentials, errors


def _apply_metadata_providers_form(
    current: list[Any] | None, action: str, form: dict[str, str]
) -> tuple[list[Any] | None, list[str]]:
    """Active/désactive SNMP, règle ses paramètres, ou réordonne la cascade.

    Quatre actions, toutes NON DESTRUCTIVES pour les fournisseurs que cet écran
    ne construit pas :

    - `enable_snmp`  : insère (ou met à jour) le fournisseur snmp. Il est placé
      APRÈS le dernier `static` — l'ordre correct de la cascade, celui qui
      préserve le repli statique. Voir `check_cascade_order`.
    - `disable_snmp` : retire le SEUL fournisseur snmp. `static` reste intact.
    - `move_up` / `move_down` : déplace un fournisseur d'un cran. L'ordre étant
      sémantique, il doit être réglable à la souris — sinon corriger une
      cascade inversée imposerait de rouvrir le YAML en SSH, ce que cet écran
      existe précisément pour éviter.
    """
    providers, snmp_index = _split_providers(current)

    if action == "enable_snmp":
        existing = providers[snmp_index] if snmp_index is not None else None
        provider, errors = _build_snmp_provider(form, existing)
        if errors:
            return None, errors

        if snmp_index is not None:
            providers[snmp_index] = provider
            return providers, []

        # Position d'insertion : juste après le DERNIER fournisseur capable de
        # laisser passer la requête (`static`). Insérer en tête placerait snmp
        # avant static et neutraliserait le repli — sans erreur visible.
        insert_at = len(providers)
        for index, item in enumerate(providers):
            if isinstance(item, dict) and str(item.get("type", "")) == "static":
                insert_at = index + 1
        providers.insert(insert_at, provider)
        return providers, []

    if action == "disable_snmp":
        if snmp_index is None:
            return None, ["la découverte SNMP n'est pas active : rien à désactiver"]
        providers.pop(snmp_index)
        return providers, []

    if action == "remove_subnet":
        if snmp_index is None:
            return None, ["la découverte SNMP n'est pas active"]
        subnet = form.get("subnet", "").strip()
        provider = dict(providers[snmp_index])
        credentials = dict(provider.get("credentials") or {})
        if subnet not in credentials:
            return None, [f"sous-réseau inconnu : {subnet!r}"]
        credentials.pop(subnet)
        provider["credentials"] = credentials
        providers[snmp_index] = provider
        return providers, []

    if action in ("move_up", "move_down"):
        return _move_provider(providers, form.get("index", ""), action)

    return None, [f"action inconnue : {action!r}"]


def _move_provider(
    providers: list[Any], index_raw: str, action: str
) -> tuple[list[Any] | None, list[str]]:
    """Déplace un fournisseur d'un cran dans la cascade.

    Le déplacement passe par un échange de positions plutôt qu'un
    `pop` + `insert` : l'objet déplacé n'est jamais recréé, donc un `static` de
    200 lignes traverse l'opération inchangé.
    """
    try:
        index = int(index_raw)
    except (TypeError, ValueError):
        return None, [f"index invalide : {index_raw!r}"]
    if not (0 <= index < len(providers)):
        return None, [f"index hors bornes : {index}"]

    target = index - 1 if action == "move_up" else index + 1
    if not (0 <= target < len(providers)):
        # Premier vers le haut / dernier vers le bas : demande sans effet, dite
        # explicitement plutôt qu'un succès qui n'a rien changé.
        return None, ["ce fournisseur est déjà à cette extrémité de la cascade"]

    providers[index], providers[target] = providers[target], providers[index]
    return providers, []


def _remove_selected_from_list(
    working: list[Any], selected: list[str]
) -> tuple[list[Any] | None, list[str]]:
    """Retire plusieurs entrées d'une liste, désignées par leur index.

    ⚠️ L'ordre DÉCROISSANT n'est pas un détail de style : chaque `pop` décale
    tous les index suivants. Mesuré avant d'écrire cette fonction — supprimer
    les index 0 et 2 de `["a","b","c","d"]` en boucle croissante donne
    `["b","c"]` au lieu de `["b","d"]` : **c'est la mauvaise entrée qui
    disparaît, sans la moindre erreur**. Sur une suppression de masse de
    configuration de production, c'est le pire profil de défaut — un succès
    apparent qui détruit autre chose que ce qui était coché.

    Tous les index sont validés AVANT le premier retrait : un seul index
    invalide annule toute l'opération plutôt que d'en appliquer la moitié.
    """
    if not selected:
        return None, ["aucune entrée sélectionnée"]

    indexes: set[int] = set()
    errors: list[str] = []
    for raw in selected:
        try:
            index = int(raw)
        except (TypeError, ValueError):
            errors.append(f"index invalide : {raw!r}")
            continue
        if not (0 <= index < len(working)):
            errors.append(f"index hors bornes : {index}")
            continue
        indexes.add(index)

    if errors:
        return None, errors
    if not indexes:
        return None, ["aucune entrée sélectionnée"]

    for index in sorted(indexes, reverse=True):
        working.pop(index)
    return working, []


def _remove_selected_from_mapping(
    working: dict[Any, Any], selected: list[str]
) -> tuple[dict[Any, Any] | None, list[str]]:
    """Retire plusieurs entrées d'un mapping, désignées par leur clé métier.

    Les clés viennent du formulaire en `str`, alors que le YAML rend les
    numéros d'AS en `int` : une comparaison directe ne trouverait jamais
    l'entrée et la suppression échouerait en annonçant « clé inconnue » sur
    une clé pourtant affichée à l'écran. La correspondance se fait donc sur la
    forme `str` des clés existantes.

    Comme pour les listes, tout est validé avant le premier retrait.
    """
    if not selected:
        return None, ["aucune entrée sélectionnée"]

    by_text = {str(existing): existing for existing in working}
    errors: list[str] = []
    to_remove: list[Any] = []
    for raw in selected:
        actual = by_text.get(raw.strip())
        if actual is None:
            errors.append(f"entrée inconnue : {raw!r}")
            continue
        to_remove.append(actual)

    if errors:
        return None, errors
    if not to_remove:
        return None, ["aucune entrée sélectionnée"]

    for actual in to_remove:
        working.pop(actual, None)
    return working, []


def _remove_by_index(working: list[Any], index_raw: str) -> tuple[list[Any] | None, list[str]]:
    try:
        index = int(index_raw)
    except (TypeError, ValueError):
        return None, [f"index invalide : {index_raw!r}"]
    if not (0 <= index < len(working)):
        return None, [f"index hors bornes : {index}"]
    working.pop(index)
    return working, []


_TableHandler = Any  # Callable[[Any, str, dict[str, str]], tuple[Any, list[str]]]

_TABLE_HANDLERS: dict[str, _TableHandler] = {
    "networks": _apply_networks_form,
    "asns": _apply_asns_form,
    "saved_filters": _apply_saved_filters_form,
    "flow_inputs": _apply_flow_inputs_form,
    "metadata_providers": _apply_metadata_providers_form,
}

_HOMEPAGE_WIDGET_CHOICES: tuple[str, ...] = (
    "exporter",
    "src-as",
    "dst-as",
    "src-country",
    "dst-country",
    "protocol",
    "etype",
    "src-port",
    "dst-port",
)


# ---------------------------------------------------------------------------
# Consultation
# ---------------------------------------------------------------------------


def _read_current_value(config_dir: str, section: ConfigSection) -> Any:
    from app.clients.yaml_editor import read_section

    path = _resolve_path(config_dir, section)
    return read_section(path, section.dotted_key)


def _empty_value_for(section: ConfigSection) -> Any:
    return {} if section.kind == "mapping" else []


def _section_summary(section: ConfigSection) -> dict[str, Any]:
    return {
        "key": section.key,
        "label": section.label,
        "description": section.description,
        "file": section.file,
        "kind": section.kind,
        "restart_services": list(section.restart_services),
    }


@router.get("/api/config/sections")
def get_sections_api() -> JSONResponse:
    """Retourne le catalogue au format `{"items": [...], "total": N}`."""
    sections = list_sections()
    return JSONResponse(
        content={"items": [_section_summary(s) for s in sections], "total": len(sections)}
    )


@router.get("/config/sections")
def get_sections_page(
    request: Request,
    templates: Templates,
) -> HTMLResponse:
    """Vue d'ensemble : toutes les sections de configuration, avec leur état."""
    return templates.TemplateResponse(
        request,
        "config_sections.html",
        {
            "sections": list_sections(),
            "active_page": "config",
            "detail": None,
        },
    )


def _metadata_providers_context(value: Any) -> dict[str, Any]:
    """Contexte d'affichage de la cascade — AUCUNE communauté en clair n'en sort.

    C'est le point de passage OBLIGÉ entre le YAML et le gabarit pour cette
    section : le gabarit ne lit jamais `credentials` directement, il lit
    `snmp_credentials`, dont les valeurs sont déjà masquées par
    `mask_community`. Une communauté ne peut donc pas atteindre le HTML par
    inadvertance — il faudrait réécrire ce dictionnaire pour l'y faire entrer.

    Retourne un dictionnaire vide si aucun fournisseur `snmp` n'est déclaré :
    le gabarit distingue alors « SNMP inactif » de « SNMP actif sans
    sous-réseau », deux états qui appellent des messages différents.
    """
    providers = list(value or [])
    snmp: dict[str, Any] | None = None
    types_in_order: list[str] = []

    for provider in providers:
        if not isinstance(provider, dict):
            continue
        provider_type = str(provider.get("type", ""))
        types_in_order.append(provider_type)
        if provider_type == "snmp" and snmp is None:
            snmp = provider

    credentials_view: dict[str, dict[str, Any]] = {}
    cleartext_count = 0
    if snmp is not None:
        raw_credentials = snmp.get("credentials")
        if isinstance(raw_credentials, dict):
            for subnet, spec in raw_credentials.items():
                communities = spec.get("communities") if isinstance(spec, dict) else None
                first = communities[0] if isinstance(communities, list) and communities else ""
                env_ref = is_env_reference(first)
                if first and not env_ref:
                    cleartext_count += 1
                credentials_view[str(subnet)] = {
                    "masked": mask_community(first),
                    "is_env_ref": env_ref,
                }

    # L'avertissement d'ordre est calculé ICI plutôt qu'au moment de la
    # validation seule : une cascade DÉJÀ inversée sur disque (posée en SSH
    # avant l'existence de cet écran) doit se voir à l'ouverture, sans attendre
    # que quelqu'un tente une modification.
    warning = ""
    order_errors = check_cascade_order(types_in_order)
    if order_errors:
        warning = order_errors[0]

    return {
        "snmp_provider": snmp,
        "snmp_credentials": credentials_view,
        "snmp_cleartext_count": cleartext_count,
        "cascade_warning": warning,
    }


@router.get("/config/sections/{key}")
def get_section_detail(
    request: Request,
    config_dir: ConfigDir,
    templates: Templates,
    key: str,
) -> HTMLResponse:
    """Écran d'édition d'une section : table éditable ou zone de texte (classifiers)."""
    section = _get_section_or_none(key)
    if section is None:
        return _section_not_found(key)

    error: str | None = None
    try:
        value = _read_current_value(config_dir, section)
    except Exception as exc:  # noqa: BLE001 - dégradation visible, jamais de 500 nu
        log.error("get_section_detail: echec lecture section=%s erreur=%s", key, exc, exc_info=True)
        value = None
        error = f"Impossible de lire la configuration actuelle : {exc}"

    if value is None:
        value = _empty_value_for(section)

    # Contexte propre à la découverte des interfaces. Calculé pour CETTE section
    # seulement : le construire systématiquement ferait parcourir des
    # `credentials` inexistants sur les 10 autres écrans, pour rien.
    providers_context = (
        _metadata_providers_context(value) if section.key == "metadata_providers" else {}
    )

    return templates.TemplateResponse(
        request,
        "config_sections.html",
        {
            **providers_context,
            "sections": list_sections(),
            "active_page": "config",
            "detail": section,
            "value": value,
            "widget_choices": _HOMEPAGE_WIDGET_CHOICES,
            # Le catalogue (service) porte l'allowlist ET l'ordre d'affichage :
            # le gabarit ne réinvente aucune liste de colonnes, il rend celle
            # qui sert aussi à valider. Une seule source, donc pas de dérive
            # possible entre ce qui est proposé et ce qui est accepté.
            "schema_column_choices": SCHEMA_COLUMN_CHOICES,
            "main_table_only_columns": MAIN_TABLE_ONLY_COLUMNS,
            "error": error,
        },
    )


# ---------------------------------------------------------------------------
# Mise en file d'attente
# ---------------------------------------------------------------------------


def _pending_section_change_ids(conn: sqlite3.Connection, section: ConfigSection) -> list[int]:
    """Identifiants des changements DÉJÀ en file pour cette section.

    `apply_pending_changes` applique « le dernier `update_section` gagne » par
    clé pointée : deux changements sur la même section ne fusionnent pas, le
    plus récent écrase l'autre. Or l'import CSV pousse la valeur ENTIÈRE du
    plan d'adressage, recalculée depuis le YAML sur DISQUE — donc sans ce qui
    est en file.

    Conséquence mesurée : un ajout manuel mis en file, puis un import CSV, puis
    « Appliquer » → l'ajout manuel disparaît. Sans erreur, avec un apply en
    succès. C'est un zéro silencieux appliqué à de la configuration.

    Ce helper permet à l'appelant de REFUSER plutôt que d'écraser. Il lit le
    payload JSON plutôt qu'une colonne dédiée, car la section visée n'existe
    que là (`{"section_key": ..., "value": ...}`).
    """
    pending: list[int] = []
    rows = conn.execute(
        "SELECT id, payload FROM pending_config_changes WHERE change_type = ? ORDER BY id",
        (_UPDATE_SECTION,),
    ).fetchall()

    for row in rows:
        change_id, payload_raw = row[0], row[1]
        try:
            payload = json.loads(payload_raw)
        except (TypeError, ValueError):
            # Payload illisible : on ne peut pas prouver qu'il ne concerne PAS
            # cette section. On le signale comme conflit — refuser à tort coûte
            # un message, écraser à tort coûte de la configuration.
            log.error(
                "_pending_section_change_ids: payload illisible id=%s, traite comme conflit",
                change_id,
            )
            pending.append(int(change_id))
            continue
        if isinstance(payload, dict) and payload.get("section_key") == section.key:
            pending.append(int(change_id))

    return pending


def _stage_section_change(conn: sqlite3.Connection, section: ConfigSection, new_value: Any) -> int:
    change_id = stage_change(
        conn,
        _UPDATE_SECTION,
        {"section_key": section.key, "value": new_value},
        _DEFAULT_AUTHOR,
    )
    log.info("config_sections: change_id=%d section=%s mis en attente", change_id, section.key)
    return change_id


@router.post("/config/sections/{key}", response_class=HTMLResponse)
async def create_pending_section_change(
    request: Request,
    conn: DbConnection,
    config_dir: ConfigDir,
    key: str,
) -> HTMLResponse:
    """Valide un formulaire de section puis met le résultat en file d'attente.

    Les formulaires HTML envoient de l'`application/x-www-form-urlencoded` : on
    lit `request.form()` plutôt que des `Annotated[..., Form()]` un par un, car
    la forme du formulaire varie selon `section.key` (table CIDR/nom, table
    AS/nom, texte multi-lignes pour les classifiers, cases à cocher pour les
    widgets, champs scalaires pour Visualize) — un seul point d'entrée évite de
    dupliquer la route par section.
    """
    section = _get_section_or_none(key)
    if section is None:
        return _section_not_found(key)

    form = await request.form()
    form_dict: dict[str, str] = {
        k: str(v) for k, v in form.items() if k not in ("widgets", "columns")
    }
    widgets = [str(v) for v in form.getlist("widgets")] if "widgets" in form else None
    # `columns` est répété une fois par case COCHÉE (contrat des cases à cocher
    # HTML : une case décochée n'est pas envoyée du tout). D'où la distinction
    # entre `None` — le formulaire n'a pas ce champ, ce n'est pas son écran — et
    # `[]` — l'écran des colonnes a été soumis avec zéro case cochée, ce qui est
    # une demande légitime de tout désactiver.
    columns = [str(v) for v in form.getlist("columns")] if "columns" in form else None

    try:
        current_value = _read_current_value(config_dir, section)
    except Exception as exc:  # noqa: BLE001 - dégradation visible, jamais de 500 nu
        log.error(
            "create_pending_section_change: echec lecture section=%s erreur=%s",
            key,
            exc,
            exc_info=True,
        )
        return _error_response([f"impossible de lire la configuration actuelle : {exc}"])

    new_value: Any
    errors: list[str]

    # La suppression de masse est traitée AVANT le dispatch par section : elle
    # suit la FORME de la donnée (liste indexée ou mapping à clé métier), pas
    # la section. Cinq branches par section auraient chacune pu réintroduire le
    # décalage d'index — un seul chemin, un seul endroit où le défaut peut
    # vivre, un seul endroit à tester.
    if form_dict.get("action") == "remove_selected":
        selected = [str(v) for v in form.getlist("selected")]
        if isinstance(current_value, list):
            new_value, errors = _remove_selected_from_list(list(current_value), selected)
        elif isinstance(current_value, dict):
            new_value, errors = _remove_selected_from_mapping(dict(current_value), selected)
        else:
            log.error(
                "create_pending_section_change: remove_selected sur une valeur "
                "ni liste ni mapping: section=%s type=%s",
                key,
                type(current_value).__name__,
            )
            return _error_response(
                [f"la section « {section.label} » ne se prête pas à une suppression multiple"]
            )
        if new_value is not None and not errors:
            errors = section.validator(new_value)
        # Garde-fou propre à la découverte des interfaces : la suppression de
        # masse suit la FORME de la donnée (une liste) et ne sait pas que le
        # fournisseur `static` porte 200 lignes d'ifIndex saisies à la main.
        # Mesuré le 2026-08-07 : sans ce test, un `selected=["0"]` le supprimait
        # avec un HTTP 201. Voir `guard_static_provider_survives`.
        if key == "metadata_providers" and new_value is not None and not errors:
            errors = guard_static_provider_survives(current_value, new_value)
        if errors or new_value is None:
            log.error(
                "create_pending_section_change: remove_selected refuse: section=%s erreurs=%s",
                key,
                errors,
            )
            return _error_response(errors or ["suppression invalide"])

        change_id = _stage_section_change(conn, section, new_value)
        log.info(
            "create_pending_section_change: remove_selected section=%s supprimes=%d change_id=%d",
            key,
            len(selected),
            change_id,
        )
        return HTMLResponse(
            f'<li class="pending-item">{escape(section.label)} : '
            f"{len(selected)} entrée(s) supprimée(s) en attente (id {change_id})</li>",
            status_code=201,
        )

    if key in ("exporter_classifiers", "interface_classifiers"):
        raw_text = form_dict.get("expressions", "")
        new_value = [line.strip() for line in raw_text.splitlines() if line.strip()]
        errors = section.validator(new_value)
    elif key == "homepage_widgets":
        new_value = widgets if widgets is not None else []
        errors = section.validator(new_value)
    elif key == "schema_columns":
        # Tout décocher est une demande LÉGITIME (revenir au schéma minimal), et
        # un formulaire dont toutes les cases sont décochées n'envoie AUCUN
        # champ `columns`. Sans distinction, ce cas serait soit ignoré, soit
        # confondu avec « ce n'est pas cet écran ». La branche est atteinte parce
        # que la `key` de l'URL vient du catalogue fermé : la liste vide est donc
        # bien un choix explicite de l'utilisateur, pas une absence de données.
        new_value = columns if columns is not None else []
        errors = section.validator(new_value)
    elif key == "visualize_defaults":
        new_value = dict(current_value or {})
        if "limit" in form_dict:
            try:
                new_value["limit"] = int(form_dict["limit"])
            except ValueError:
                new_value["limit"] = form_dict["limit"]  # laisse le validator produire l'erreur
        if "dimensions" in form_dict:
            new_value["dimensions"] = [
                d.strip() for d in form_dict["dimensions"].split(",") if d.strip()
            ]
        errors = section.validator(new_value)
    elif key in _TABLE_HANDLERS:
        action = form_dict.get("action", "")
        handler = _TABLE_HANDLERS[key]
        new_value, errors = handler(current_value, action, form_dict)
        if new_value is not None and not errors:
            errors = section.validator(new_value)
    else:
        # Sections du catalogue sans éditeur dédié construit ici (ex.
        # kafka_retention, mapping libre) : refus explicite plutôt qu'une
        # écriture non maîtrisée.
        log.error("create_pending_section_change: section sans gestionnaire: key=%s", key)
        return _error_response([f"aucun éditeur disponible pour la section {key!r}"])

    if errors or new_value is None:
        log.error(
            "create_pending_section_change: validation echouee: section=%s erreurs=%s",
            key,
            errors,
        )
        return _error_response(errors or ["changement invalide"])

    change_id = _stage_section_change(conn, section, new_value)
    return HTMLResponse(
        f'<li class="pending-item">{escape(section.label)} : changement en attente '
        f"(id {change_id})</li>",
        status_code=201,
    )


@router.delete("/config/sections/pending/{change_id}")
def remove_pending_section_change(conn: DbConnection, change_id: int) -> HTMLResponse:
    """Retire un changement de section de la file d'attente sans l'appliquer."""
    discard_change(conn, change_id)
    log.info("remove_pending_section_change: change_id=%d", change_id)
    return HTMLResponse("")


def _fingerprint_section(config_dir: str, section: ConfigSection) -> str:
    """Empreinte du CONTENU d'une section, pas du fichier qui la porte.

    `compute_file_hash` existe déjà, mais il hache le fichier ENTIER : or
    `outlet.yaml` porte trois sections (plan d'adressage et les deux tables de
    classification). Modifier les classifieurs signalerait alors, à tort, que
    le plan d'adressage a changé — un avertissement qui se déclenche pour rien
    apprend à ignorer les avertissements.

    La valeur est sérialisée avec des clés triées pour que deux lectures d'un
    contenu identique donnent la même empreinte, indépendamment de l'ordre
    d'itération du document YAML.
    """
    raw = _read_current_value(config_dir, section)
    canonical = json.dumps(raw, sort_keys=True, default=str, ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


@router.get("/config/sections/{key}/freshness", response_class=HTMLResponse)
def get_section_freshness(config_dir: ConfigDir, key: str, seen: str = "") -> HTMLResponse:
    """Signale qu'un AUTRE opérateur a modifié cette section depuis l'ouverture.

    POURQUOI une sonde plutôt qu'un rafraîchissement automatique du contenu :
    le panneau d'édition contient 24 champs de saisie et une zone de collage
    CSV. Un `hx-trigger="every 10s"` dessus effacerait un CSV à moitié collé
    ou une sélection de cases en cours — le remède serait pire que le mal.

    Cette route ne rend donc RIEN tant que rien n'a changé, et une bannière
    dès que le fichier diverge de ce que le navigateur a chargé. Recharger
    reste une décision de l'utilisateur : lui seul sait s'il a une saisie en
    cours. C'est le sens de l'usage à plusieurs visé par Okvorado — un
    collègue applique un changement, on doit le SAVOIR sans se le faire
    imposer au milieu d'une saisie.

    `seen` est l'empreinte connue du navigateur. Vide (premier appel), on ne
    signale rien : il n'y a pas encore de référence à comparer.
    """
    section = _get_section_or_none(key)
    if section is None:
        return _section_not_found(key)

    try:
        current = _fingerprint_section(config_dir, section)
    except Exception as exc:  # noqa: BLE001 - une sonde ne doit jamais casser la page
        # Échec de lecture : on rend un état DISTINCT plutôt qu'un « tout va
        # bien » silencieux. Un incident de lecture ne doit pas ressembler à
        # une absence de changement.
        log.error("get_section_freshness: echec lecture section=%s erreur=%s", key, exc)
        return HTMLResponse(
            '<p class="notice notice-warn" data-freshness="unknown">'
            "État de la section indéterminé : impossible de relire le fichier "
            "de configuration. Rechargez pour vérifier.</p>"
        )

    if not seen or seen == current:
        # Rien à signaler. L'empreinte courante voyage en attribut pour que le
        # prochain appel puisse comparer sans état côté serveur.
        return HTMLResponse(f'<span hidden data-fingerprint="{escape(current)}"></span>')

    log.info("get_section_freshness: section=%s modifiee ailleurs (vu=%s)", key, seen[:12])
    return HTMLResponse(
        f'<p class="notice notice-warn" data-fingerprint="{escape(current)}">'
        f"<strong>Cette section a été modifiée ailleurs.</strong> "
        f"Le contenu affiché n'est plus à jour — un autre opérateur a appliqué "
        f"un changement. "
        f'<a class="link-action" href="/config/sections/{escape(key)}">Recharger</a></p>'
    )


@router.get("/config/sections/pending/list", response_class=HTMLResponse)
def get_pending_section_changes_fragment(conn: DbConnection) -> HTMLResponse:
    """Fragment HTMX listant les changements de section en attente."""
    pending = [c for c in list_pending_changes(conn) if c.change_type == _UPDATE_SECTION]
    if not pending:
        return HTMLResponse('<p class="empty">Aucun changement de section en attente.</p>')
    items = "".join(
        f'<li class="pending-item" id="pending-item-{c.id}">'
        f'<span class="pending-item__label">Section '
        f"{escape(str(c.payload.get('section_key', '?')))} modifiée</span>"
        f'<span class="pending-item__meta">par {escape(c.author)} · {escape(c.created_at)}</span>'
        f'<button type="button" class="danger" hx-delete="/config/sections/pending/{c.id}" '
        f'hx-target="#pending-item-{c.id}" hx-swap="outerHTML" '
        f'hx-confirm="Retirer ce changement de la file d\'attente ?">Retirer</button>'
        "</li>"
        for c in pending
    )
    return HTMLResponse(f'<ul class="pending-list">{items}</ul>')


# ---------------------------------------------------------------------------
# Import/export CSV en masse — plan d'adressage (`networks`)
# ---------------------------------------------------------------------------
#
# Deux étapes obligatoires, jamais d'application en aveugle :
#   1. mode="preview" (défaut) : parse + calcule le diff contre l'existant,
#      affiche N ajouts / M mises à jour / P inchangés + erreurs, ne touche
#      rien. Le fragment retourné contient un formulaire de confirmation qui
#      renvoie le MÊME contenu CSV normalisé (jamais recalculé côté client).
#   2. mode="confirm" : reparse le même contenu (jamais de confiance dans un
#      diff pré-calculé côté client), applique fusion/remplacement, met en
#      file d'attente via `stage_change` — jamais d'écriture directe.


def _networks_from_value(value: Any) -> dict[str, str]:
    """Normalise la valeur `networks.networks` courante en `cidr -> nom`.

    Le YAML stocke chaque entrée sous forme `{"name": ..., "role": ..., ...}`
    (voir `_OUTLET_YAML` de test) ; seul `name` intéresse l'import/export CSV.
    """
    if not isinstance(value, dict):
        return {}
    result: dict[str, str] = {}
    for cidr, spec in value.items():
        if isinstance(spec, dict):
            name = spec.get("name")
        else:
            name = spec
        if name:
            result[str(cidr)] = str(name)
    return result


_CSV_FORMATS: dict[str, CsvFormat] = {
    "networks": NETWORKS_CSV_FORMAT,
    "asns": ASNS_CSV_FORMAT,
    "saved_filters": SAVED_FILTERS_CSV_FORMAT,
    "exporter_classifiers": EXPORTER_CLASSIFIERS_CSV_FORMAT,
    "interface_classifiers": INTERFACE_CLASSIFIERS_CSV_FORMAT,
}
"""Sections dotées d'un import/export CSV, et leur format.

Le choix est un ARBITRAGE DE PERTINENCE, pas une omission : les 4 sections
absentes (`visualize_defaults`, `homepage_widgets`, `flow_inputs`,
`kafka_retention`) sont des RÉGLAGES à clés fixes, pas des collections qui
croissent. Volumétrie mesurée en production le 2026-08-06 : 7, 6, 3 et 3
entrées, toutes stables. `homepage_widgets` est en outre une liste FERMÉE de
dimensions connues d'Akvorado — un import libre y ferait entrer des valeurs
que la console rejetterait.

Une section absente d'ici n'affiche simplement pas de bloc CSV : c'est le
`SECTIONS_WITH_CSV` du template qui en découle, jamais l'inverse.
"""


def _pairs_from_value(value: Any, fmt: CsvFormat) -> dict[str, str]:
    """Normalise la valeur courante d'une section en `clé -> valeur` comparable.

    C'est la forme qu'attend `_compute_import_diff`, quel que soit le format
    d'origine. Les trois formes de section y convergent :

    - `mapping` : `{clé: valeur}` ou `{clé: {"name": valeur, ...}}` (le plan
      d'adressage porte aussi `role`/`tenant`, hors CSV).
    - `pairs`   : `[{"description": ..., "content": ...}]` -> description en clé.
    - `lines`   : `["expression", ...]` -> l'expression est sa propre clé, il
      n'y a rien d'autre à comparer.

    Les clés sont ramenées en `str` : le YAML rend les numéros d'AS en `int`,
    et comparer un `int` à la clé `str` issue du CSV ferait apparaître chaque
    AS existant comme un AJOUT — l'import écraserait alors le nom en place en
    croyant créer une entrée.
    """
    if fmt.kind == "lines":
        if not isinstance(value, list):
            return {}
        return {str(item): str(item) for item in value if item}

    if fmt.kind == "pairs":
        if not isinstance(value, list):
            return {}
        key_field, value_field = fmt.pair_fields
        result: dict[str, str] = {}
        for item in value:
            if not isinstance(item, dict):
                continue
            key = item.get(key_field)
            if key:
                result[str(key)] = str(item.get(value_field, ""))
        return result

    return _networks_from_value(value)


@dataclass(frozen=True)
class _ImportDiffEntry:
    cidr: str
    name: str
    previous_name: str | None = None


@dataclass(frozen=True)
class _ImportDiff:
    added: list[_ImportDiffEntry]
    updated: list[_ImportDiffEntry]
    unchanged: list[_ImportDiffEntry]


def _compute_import_diff(
    current: dict[str, str], rows: list[CsvRow], *, replace: bool
) -> tuple[_ImportDiff, list[str]]:
    """Retourne `(diff, removed)`. `removed` n'est peuplé que si `replace=True`
    (liste des CIDR existants absents du CSV, donc perdus par le remplacement)."""
    added: list[_ImportDiffEntry] = []
    updated: list[_ImportDiffEntry] = []
    unchanged: list[_ImportDiffEntry] = []

    for row in rows:
        previous = current.get(row.cidr)
        if previous is None:
            added.append(_ImportDiffEntry(cidr=row.cidr, name=row.name))
        elif previous != row.name:
            updated.append(_ImportDiffEntry(cidr=row.cidr, name=row.name, previous_name=previous))
        else:
            unchanged.append(_ImportDiffEntry(cidr=row.cidr, name=row.name, previous_name=previous))

    if replace:
        imported_cidrs = {row.cidr for row in rows}
        removed = [cidr for cidr in current if cidr not in imported_cidrs]
    else:
        removed = []

    diff = _ImportDiff(added=added, updated=updated, unchanged=unchanged)
    return diff, removed


def _build_new_networks_value(
    current_raw: Any, rows: list[CsvRow], *, replace: bool
) -> dict[str, Any]:
    """Construit la nouvelle valeur `networks.networks` (fusion ou remplacement).

    En fusion (`replace=False`), les entrées existantes non mentionnées dans
    le CSV sont CONSERVÉES telles quelles (y compris leurs éventuels champs
    `role`/`tenant` déjà présents en YAML, non gérés par ce CSV minimal). En
    remplacement, seules les lignes du CSV survivent — mais celles qui
    survivent GARDENT leurs champs annexes.

    Ce dernier point corrige un défaut mesuré (2026-08-06) : `working` partant
    de `{}` en mode remplacement, `working.get(row.cidr)` valait toujours
    `None`, et un réseau POURTANT PRÉSENT dans le CSV était recréé avec le seul
    champ `name`. Ses `role` et `tenant` disparaissaient — alors que `role`
    pilote la classification interne/externe des flux dans Akvorado. La
    prévisualisation classait l'entrée « inchangée » (le nom, lui, ne changeait
    pas), donc rien n'alertait l'utilisateur. Le CSV décrit une désignation,
    jamais une politique de classification : il ne doit pas l'effacer.
    """
    current = dict(current_raw or {})
    working: dict[str, Any] = {} if replace else dict(current)
    for row in rows:
        # En remplacement, on relit l'entrée dans la config COURANTE : c'est le
        # seul endroit où les champs annexes existent encore à ce stade.
        existing = working.get(row.cidr, current.get(row.cidr) if replace else None)
        if isinstance(existing, dict):
            merged = dict(existing)
            merged["name"] = row.name
            working[row.cidr] = merged
        else:
            working[row.cidr] = {"name": row.name}
    return working


def _build_new_section_value(
    current_raw: Any, rows: list[CsvRow], fmt: CsvFormat, *, replace: bool
) -> Any:
    """Construit la nouvelle valeur d'une section, selon la forme de sa donnée.

    Chaque forme a sa règle de fusion, et elles ne sont pas interchangeables :

    - `mapping` : délègue à `_build_new_networks_value`, qui préserve les
      champs annexes (`role`/`tenant`) — voir sa docstring, un défaut mesuré y
      est documenté. Les clés d'AS arrivant du CSV en `str`, on les ramène au
      TYPE d'origine trouvé dans le YAML : réécrire `64501` en `"64501"`
      changerait le type de la clé et Akvorado ne reconnaîtrait plus l'AS.
    - `pairs` : liste ordonnée d'objets. L'ORDRE compte pour Akvorado, donc les
      entrées existantes gardent leur position et les nouvelles sont ajoutées à
      la fin — jamais de tri, qui changerait le comportement produit.
    - `lines` : liste ordonnée d'expressions. Même raison : les classifieurs
      sont appliqués EN SÉQUENCE, réordonner change le résultat.
    """
    if fmt.kind == "mapping":
        built = _build_new_networks_value(current_raw, rows, replace=replace)
        if fmt is NETWORKS_CSV_FORMAT:
            return built
        # Sections `mapping` à valeur scalaire (asns) : le YAML porte
        # `{64501: "ACME"}`, pas `{64501: {"name": ...}}`.
        original_types = {str(k): k for k in (current_raw or {})}
        return {
            original_types.get(str(k), _coerce_mapping_key(k)): (
                v.get("name") if isinstance(v, dict) else v
            )
            for k, v in built.items()
        }

    if fmt.kind == "pairs":
        key_field, value_field = fmt.pair_fields
        existing = list(current_raw or []) if not replace else []
        by_key = {
            str(item.get(key_field)): index
            for index, item in enumerate(existing)
            if isinstance(item, dict)
        }
        working = [dict(item) if isinstance(item, dict) else item for item in existing]
        for row in rows:
            index = by_key.get(row.key)
            if index is None:
                working.append({key_field: row.key, value_field: row.value})
                by_key[row.key] = len(working) - 1
            elif isinstance(working[index], dict):
                merged = dict(working[index])
                merged[value_field] = row.value
                working[index] = merged
        return working

    # `lines` : liste de chaînes, dédoublonnée en conservant l'ordre d'arrivée.
    existing_lines = [str(item) for item in (current_raw or [])] if not replace else []
    seen = set(existing_lines)
    result = list(existing_lines)
    for row in rows:
        if row.value not in seen:
            result.append(row.value)
            seen.add(row.value)
    return result


def _coerce_mapping_key(raw: str) -> Any:
    """Rend une clé de mapping au type attendu par le YAML.

    Un numéro d'AS est un ENTIER dans `akvorado.yaml`. Écrire `"64501"` en
    chaîne produirait un YAML syntaxiquement valide qu'Akvorado ne
    rapprocherait d'aucun AS observé : la table de noms resterait sans effet,
    sans la moindre erreur.
    """
    try:
        return int(raw)
    except (TypeError, ValueError):
        return raw


def _detect_bare_ips(raw_content: str, rows: list[CsvRow]) -> list[str]:
    """Repère, parmi les lignes valides, celles dont le CIDR d'origine était
    une IP nue (aucun `/` dans le champ brut correspondant) — signalé à
    l'utilisateur, jamais silencieux."""
    bare: list[str] = []
    lines = raw_content.splitlines()
    for row in rows:
        if 1 <= row.line <= len(lines):
            raw_line = lines[row.line - 1]
            first_field = raw_line.split(";")[0].split(",")[0].strip()
            if first_field and "/" not in first_field:
                bare.append(row.cidr)
    return bare


def _render_import_errors(errors: list[str], duplicates: list[str]) -> HTMLResponse:
    all_errors = errors + duplicates
    items = "".join(f"<li>{escape(err)}</li>" for err in all_errors)
    return HTMLResponse(
        '<div class="notice notice-crit"><strong>Import refusé — aucune ligne importée</strong>'
        f"<ul>{items}</ul>"
        "<p>Corrigez le fichier et recommencez : un import est tout ou rien.</p></div>",
        status_code=422,
    )


def _render_import_preview(
    diff: _ImportDiff,
    removed: list[str],
    bare_ips: list[str],
    *,
    raw_content: str,
    replace: bool,
    section_key: str = "networks",
) -> HTMLResponse:
    parts: list[str] = ['<div class="notice notice-info" id="csv-import-preview">']
    parts.append("<strong>Prévisualisation de l'import</strong>")
    parts.append(
        f"<p>{len(diff.added)} ajout(s), {len(diff.updated)} mise(s) à jour, "
        f"{len(diff.unchanged)} inchangé(s)"
        + (f", {len(removed)} supprimé(s)" if replace else "")
        + ".</p>"
    )

    if bare_ips:
        bare_list = ", ".join(escape(c) for c in bare_ips)
        parts.append(
            f'<p class="notice notice-warn">IP sans masque normalisée(s) en CIDR hôte : '
            f"{bare_list}.</p>"
        )

    if diff.added:
        items = "".join(f"<li>{escape(e.cidr)} → {escape(e.name)}</li>" for e in diff.added)
        parts.append(f"<p>Ajouts :</p><ul>{items}</ul>")
    if diff.updated:
        items = "".join(
            f"<li>{escape(e.cidr)} : {escape(e.previous_name or '')} → {escape(e.name)}</li>"
            for e in diff.updated
        )
        parts.append(f"<p>Mises à jour :</p><ul>{items}</ul>")
    if replace and removed:
        items = "".join(f"<li>{escape(c)}</li>" for c in removed)
        parts.append(
            f'<p class="notice notice-crit">Supprimés par le remplacement complet :</p>'
            f"<ul>{items}</ul>"
        )

    # `hx-target` vise la file d'attente : c'est le bon endroit pour un SUCCÈS,
    # qui se matérialise par une ligne de plus dans les changements en attente.
    # Un REFUS, lui, doit s'afficher là où la personne REGARDE — la zone
    # d'import — et non dans un panneau situé ailleurs sur la page. Constaté au
    # navigateur le 2026-08-06 : le refus avait bien lieu côté serveur, la
    # preview restait affichée, et rien n'indiquait que la confirmation avait
    # échoué. Le reroutage des réponses d'erreur vers `data-error-target` est
    # fait dans `app/static/htmx-config.js` : l'attribut `hx-target-error`
    # n'existe PAS dans le core htmx (il vient d'une extension non embarquée),
    # il aurait été ignoré en silence.
    # La cible du POST est la SECTION PRÉVISUALISÉE. Codée en dur sur
    # `networks` — ce qu'elle était avant la généralisation — confirmer un
    # import de noms d'AS aurait écrit dans le PLAN D'ADRESSAGE : le contenu
    # d'une section aurait remplacé celui d'une autre, sur une confirmation que
    # l'utilisateur croyait porter sur ce qu'il regardait.
    parts.append(
        f'<form hx-post="/config/sections/{escape(section_key)}/import" '
        'hx-target="#section-pending-panel" '
        'data-error-target="#csv-import-result" '
        'hx-trigger="submit" hx-sync="this:replace" hx-disabled-elt="find button">'
        '<input type="hidden" name="mode" value="confirm">'
        f'<input type="hidden" name="replace" value="{"true" if replace else "false"}">'
        f'<textarea name="csv_text" hidden>{escape(raw_content)}</textarea>'
        '<button type="submit" class="primary">Confirmer l\'import</button>'
        "</form>"
        "</div>"
    )
    return HTMLResponse("".join(parts), status_code=200)


async def _read_csv_upload(csv_file: UploadFile | None) -> tuple[str | None, str | None]:
    """Lit un fichier téléversé en respectant la limite de taille.

    Retourne `(contenu_texte, erreur)`. `contenu_texte` est `None` si aucun
    fichier n'a été fourni ou si la limite est dépassée (erreur non-`None`
    dans ce dernier cas).
    """
    if csv_file is None or not csv_file.filename:
        return None, None
    raw = await csv_file.read()
    if len(raw) > _MAX_CSV_UPLOAD_BYTES:
        return None, (
            f"fichier trop volumineux ({len(raw)} octets, max {_MAX_CSV_UPLOAD_BYTES} octets)"
        )
    try:
        return raw.decode("utf-8"), None
    except UnicodeDecodeError:
        return None, "fichier illisible : encodage attendu UTF-8"


@router.post("/config/sections/{key}/import", response_class=HTMLResponse)
async def import_section_csv(
    conn: DbConnection,
    config_dir: ConfigDir,
    key: str,
    csv_text: Annotated[str, Form()] = "",
    csv_file: UploadFile | None = None,
    mode: Annotated[str, Form()] = "preview",
    replace: Annotated[str, Form()] = "false",
) -> HTMLResponse:
    """Importe en masse une section depuis un CSV, format propre à la section.

    Paramétrée par `key` plutôt que dupliquée par section : le plan
    d'adressage, les noms d'AS, les filtres enregistrés et les deux tables de
    classifieurs partagent le même flux (preview -> confirm, tout ou rien,
    refus si un changement est déjà en file). Cinq copies de cette route
    auraient divergé au premier correctif appliqué à une seule.

    Deux sources possibles (zone de texte collée ou fichier téléversé) : si
    les deux sont fournies, le FICHIER prime. `mode=preview` (défaut) ne
    touche rien et retourne un diff à confirmer ; `mode=confirm` reparse le
    même contenu et met le résultat en file d'attente.
    """
    section = _get_section_or_none(key)
    if section is None:
        return _section_not_found(key)

    csv_format = _CSV_FORMATS.get(key)
    if csv_format is None:
        # Section volontairement dépourvue d'import CSV (réglage à clés fixes).
        # Refus EXPLICITE plutôt qu'un 404 : la route existe, c'est la section
        # qui ne s'y prête pas — et le dire évite qu'on cherche un bug ailleurs.
        log.error("import_section_csv: section sans import CSV: key=%s", key)
        return _error_response(
            [
                f"la section « {section.label} » ne se prête pas à un import CSV : "
                "c'est un réglage à clés fixes, pas une liste d'entrées."
            ]
        )

    file_content, file_error = await _read_csv_upload(csv_file)
    if file_error is not None:
        return _error_response([file_error])

    content = file_content if file_content is not None else csv_text
    if not content or not content.strip():
        return _error_response(["aucun contenu CSV fourni (ni texte collé, ni fichier)"])

    result = parse_csv(content, csv_format)
    if result.errors or result.duplicates:
        log.error(
            "import_section_csv: parsing echoue, aucun import: section=%s erreurs=%s duplicates=%s",
            key,
            result.errors,
            result.duplicates,
        )
        return _render_import_errors(result.errors, result.duplicates)

    replace_all = replace.strip().lower() in ("true", "1", "on", "yes")

    # `section` vient de `key`, jamais d'un `get_section("networks")` en dur :
    # la route étant devenue générique, une section codée en dur ici ferait
    # écrire un import de NOMS D'AS dans le PLAN D'ADRESSAGE — et le YAML
    # écrasé serait celui d'une section que l'utilisateur n'a pas ouverte.
    try:
        current_raw = _read_current_value(config_dir, section)
    except Exception as exc:  # noqa: BLE001 - dégradation visible, jamais de 500 nu
        log.error("import_section_csv: echec lecture section=%s erreur=%s", key, exc, exc_info=True)
        return _error_response([f"impossible de lire la configuration actuelle : {exc}"])

    # Un CSV syntaxiquement valide mais SANS AUCUNE LIGNE DE DONNÉES (que des
    # commentaires, ou une seule ligne d'en-tête) passe le parsing avec
    # `rows=[]` et `errors=[]` : c'est un succès pour le parseur. Combiné à
    # `replace=true`, il produisait un plan d'adressage VIDE, mis en file avec
    # un HTTP 201 et le message « 0 ajout(s), 0 mise(s) à jour » — qui ne
    # mentionne aucune suppression. Chemin réel : exporter, ouvrir dans un
    # tableur, mal enregistrer, réimporter.
    if not result.rows:
        log.error(
            "import_section_csv: CSV sans aucune ligne de donnees, aucun import: section=%s", key
        )
        return _render_import_errors(
            [
                "le CSV ne contient aucune ligne de données "
                "(seulement des commentaires, un en-tête, ou des lignes vides)"
            ],
            [],
        )

    current_names = _pairs_from_value(current_raw, csv_format)
    diff, removed = _compute_import_diff(current_names, result.rows, replace=replace_all)
    # La normalisation d'IP nue en CIDR hôte ne concerne que le plan
    # d'adressage : signaler « IP sans masque normalisée » sur un import de
    # noms d'AS serait un avertissement sans objet, donc du bruit qui apprend
    # à ignorer les avertissements.
    bare_ips = _detect_bare_ips(content, result.rows) if key == "networks" else []

    # Le mode d'écriture est reconnu au sens STRICT. `!= "confirm"` retombait
    # sur preview pour tout le reste, ce qui est le bon défaut — mais après
    # `.strip().lower()`, une valeur comme « CONFIRM » écrivait. Un mode non
    # reconnu doit prévisualiser, jamais écrire.
    if mode != "confirm":
        return _render_import_preview(
            diff,
            removed,
            bare_ips,
            raw_content=content,
            replace=replace_all,
            section_key=key,
        )

    # Un `update_section` déjà en attente sur cette même section serait ÉCRASÉ :
    # `apply_pending_changes` applique « le dernier gagne » par dotted_key, et
    # l'import pousse la valeur ENTIÈRE de la section, calculée depuis le
    # disque — donc sans les changements en file. Un ajout manuel suivi d'un
    # import perdait l'ajout, silencieusement, avec un apply en succès.
    conflicting = _pending_section_change_ids(conn, section)
    if conflicting:
        log.error(
            "import_section_csv: refus, changement deja en attente: section=%s ids=%s",
            key,
            conflicting,
        )
        return _render_import_errors(
            [
                f"un changement de « {section.label} » est déjà en file d'attente "
                f"(id {', '.join(str(i) for i in conflicting)}). Un import écraserait "
                "ce changement sans avertissement : appliquez-le ou annulez-le d'abord."
            ],
            [],
        )

    new_value = _build_new_section_value(current_raw, result.rows, csv_format, replace=replace_all)
    errors = section.validator(new_value)
    if errors:
        log.error(
            "import_section_csv: validation finale echouee: section=%s erreurs=%s", key, errors
        )
        return _error_response(errors)

    change_id = _stage_section_change(conn, section, new_value)
    log.info(
        "import_section_csv: section=%s change_id=%d ajouts=%d maj=%d inchanges=%d "
        "supprimes=%d replace=%s",
        key,
        change_id,
        len(diff.added),
        len(diff.updated),
        len(diff.unchanged),
        len(removed),
        replace_all,
    )
    return HTMLResponse(
        f'<li class="pending-item">Import CSV ({escape(section.label)}) : '
        f"{len(diff.added)} ajout(s), "
        f"{len(diff.updated)} mise(s) à jour en attente (id {change_id})</li>",
        status_code=201,
    )


_EXPORT_FILENAMES: dict[str, str] = {
    "networks": "plan-adressage.csv",
    "asns": "noms-as.csv",
    "saved_filters": "filtres-enregistres.csv",
    "exporter_classifiers": "classification-exportateurs.csv",
    "interface_classifiers": "classification-interfaces.csv",
}
"""Nom du fichier téléchargé par section.

Un nom parlant plutôt que `export.csv` : cinq exports dans un dossier de
téléchargements se distinguent par leur nom, pas par leur ordre d'arrivée.
"""


@router.get("/config/sections/{key}/export")
def export_section_csv_route(config_dir: ConfigDir, key: str) -> Response:
    """Exporte la section courante en CSV téléchargeable.

    Route de NAVIGATION DIRECTE (le bouton est un `<a href download>`, sans
    attribut `hx-*`) : c'est le navigateur qui rend une éventuelle page
    d'erreur, pas HTMX. Cette exemption est vérifiée par un test — voir
    `tests/test_htmx_error_visibility.py`.
    """
    section = _get_section_or_none(key)
    if section is None:
        return _section_not_found(key)

    csv_format = _CSV_FORMATS.get(key)
    if csv_format is None:
        log.error("export_section_csv_route: section sans export CSV: key=%s", key)
        return HTMLResponse(
            f'<div class="notice notice-crit">La section « {escape(section.label)} » '
            "ne se prête pas à un export CSV.</div>",
            status_code=404,
        )

    try:
        current_raw = _read_current_value(config_dir, section)
    except Exception as exc:  # noqa: BLE001 - dégradation visible, jamais de 500 nu
        log.error(
            "export_section_csv_route: echec lecture section=%s erreur=%s",
            key,
            exc,
            exc_info=True,
        )
        message = escape(str(exc))
        return HTMLResponse(
            f'<div class="notice notice-crit">Impossible de générer l\'export : {message}</div>',
            status_code=500,
        )

    # `export_csv` sérialise ce qu'on lui donne : lui passer la valeur BRUTE
    # d'un mapping dont les entrées sont des dicts écrivait la structure
    # entière dans la colonne « désignation »
    # (`{'name': 'lan-maison', 'role': 'lan', ...}`) au lieu du seul nom. Le
    # fichier restait un CSV valide et se retéléchargeait sans erreur — mais
    # réimporté, il aurait remplacé chaque désignation par ce charabia.
    # Attrapé par le test d'aller-retour export -> import, pas par l'export seul.
    exportable = (
        _pairs_from_value(current_raw, csv_format) if csv_format.kind == "mapping" else current_raw
    )
    csv_content = export_csv(exportable, csv_format)
    filename = _EXPORT_FILENAMES.get(key, f"{key}.csv")
    return Response(
        content=csv_content,
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
