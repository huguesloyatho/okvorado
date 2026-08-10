"""Socle générique de lecture/écriture d'une section YAML, à n'importe quel
chemin, dans n'importe lequel des 4 fichiers de configuration d'Akvorado.

Généralise le mécanisme construit dans `akvorado_yaml.py` (lecture/écriture de
`metadata.providers[].exporters`) à une section quelconque désignée par un
chemin pointillé (`dotted_key`), ex. `"networks.networks"`,
`"core.exporter-classifiers"`, `"clickhouse.asns"`, `"database.saved-filters"`.

Garanties REPRISES À L'IDENTIQUE de `akvorado_yaml.py` (lues avant d'écrire ce
module, cf. CONTRACT.md) :
- `ruamel.yaml` round-trip : les commentaires et le formatage survivent, y
  compris les directives custom (`!include`, utilisées par `akvorado.yaml`
  pour inclure `inlet.yaml`/`outlet.yaml` — ruamel les traite comme des tags
  YAML opaques et les préserve tant qu'on ne touche pas au nœud qui les porte).
- Écriture ATOMIQUE : fichier temporaire dans le MÊME répertoire, puis
  `os.replace()`. Jamais d'écriture en place.
- Verrou optimiste par hash sha256 du contenu brut : `ConcurrentModificationError`
  si le fichier a changé depuis la lecture qui a produit `expected_hash`.
- Backup horodaté (`<fichier>.bak-YYYYmmddHHMMSS`) créé avant toute écriture.
- Re-parse de contrôle APRÈS écriture : le fichier réécrit doit être relisible
  et contenir exactement la valeur attendue à `dotted_key`, sinon on lève.
- Modification EN PLACE du document ruamel chargé (jamais de reconstruction
  du document depuis zéro) : c'est ce qui préserve les commentaires attachés
  aux nœuds voisins de celui qu'on modifie.

Robustesse en LECTURE : fichier absent, YAML malformé, section manquante à
n'importe quel niveau du chemin -> dégradation silencieuse vers `None`
(loguée), jamais d'exception. C'est le pendant de `load_declared_exporters`.

Robustesse en ÉCRITURE : l'inverse — toute anomalie DOIT lever une exception
explicite. Un YAML tronqué ou incohérent empêcherait Akvorado de redémarrer.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any

from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError

log = logging.getLogger(__name__)


class ConcurrentModificationError(Exception):
    """Le fichier a été modifié depuis le hash attendu (verrou optimiste).

    Motif (identique à `akvorado_yaml.py`) : quelqu'un a édité le fichier à la
    main (SSH) pendant que l'UI affichait un état devenu périmé. Un `flock` ne
    couvre PAS ce cas — seule une comparaison de hash avant écriture le détecte.
    """


def _split_dotted_key(dotted_key: str) -> list[str]:
    """Découpe un chemin pointillé en segments. Aucune clé de nos sections
    catalogées ne contient de point littéral (vérifié par le catalogue), donc
    un split naïf sur '.' est suffisant et sans ambiguïté.
    """
    return dotted_key.split(".")


def _load_document(path: str, yaml_loader: YAML) -> Any:
    """Charge le document YAML round-trip. Retourne `None` (sans lever) si le
    fichier est absent, illisible ou malformé — c'est la sémantique attendue
    par `read_section`. Les appelants en écriture doivent gérer eux-mêmes ces
    cas car ILS doivent lever, pas dégrader.
    """
    yaml_path = Path(path)
    if not yaml_path.is_file():
        return None
    try:
        with yaml_path.open("r", encoding="utf-8") as handle:
            return yaml_loader.load(handle)
    except YAMLError:
        log.error("yaml malforme (erreur de parsing): path=%s", path, exc_info=True)
        return None
    except OSError:
        log.error("fichier yaml illisible (erreur I/O): path=%s", path, exc_info=True)
        return None


def _navigate(document: Any, segments: list[str]) -> Any:
    """Descend dans un document déjà chargé en suivant `segments`. Retourne
    `None` dès qu'un segment intermédiaire est absent ou que le nœud courant
    n'est pas un mapping — jamais d'exception.
    """
    node = document
    for segment in segments:
        if not isinstance(node, dict) or segment not in node:
            return None
        node = node[segment]
    return node


def _to_plain(value: Any) -> Any:
    """Convertit récursivement les types ruamel (CommentedMap/CommentedSeq,
    scalaires taggés) vers des types Python natifs (dict/list/str/int/bool),
    pour que la valeur retournée à l'appelant soit comparable/sérialisable
    sans dépendance à ruamel.
    """
    if isinstance(value, dict):
        return {key: _to_plain(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_to_plain(item) for item in value]
    return value


def read_section(path: str, dotted_key: str) -> Any:
    """Lit la valeur à `dotted_key` dans le fichier YAML `path`.

    Ne lève jamais : fichier absent, YAML invalide, ou section manquante à
    n'importe quel niveau du chemin -> `None` (loggué avec contexte).
    """
    yaml_loader = YAML(typ="rt")
    document = _load_document(path, yaml_loader)
    if document is None:
        log.error(
            "read_section: document indisponible, retour None: path=%s cle=%s", path, dotted_key
        )
        return None
    if not isinstance(document, dict):
        log.error("read_section: document racine n'est pas un mapping: path=%s", path)
        return None

    segments = _split_dotted_key(dotted_key)
    value = _navigate(document, segments)
    if value is None:
        log.info("read_section: section absente, retour None: path=%s cle=%s", path, dotted_key)
        return None
    return _to_plain(value)


def compute_file_hash(path: str) -> str:
    """Sha256 du contenu actuel du fichier, utilisé comme ETag pour le
    verrouillage optimiste (voir `write_section`)."""
    with Path(path).open("rb") as handle:
        return hashlib.sha256(handle.read()).hexdigest()


def _ensure_path(document: Any, segments: list[str]) -> Any:
    """Descend dans le document round-trip chargé, en CRÉANT les mappings
    intermédiaires manquants (mutation en place — c'est ce qui préserve les
    commentaires des nœuds voisins). Retourne le mapping parent direct de la
    dernière clé du chemin ; lève `ValueError` si un segment intermédiaire
    existe déjà mais n'est pas un mapping (on ne peut pas descendre dedans).
    """
    node = document
    for segment in segments[:-1]:
        if segment not in node:
            node[segment] = {}
        child = node[segment]
        if not isinstance(child, dict):
            raise ValueError(
                f"impossible de descendre dans le chemin '{'.'.join(segments)}': "
                f"le segment '{segment}' n'est pas un mapping (valeur actuelle: {child!r})"
            )
        node = child
    return node


def write_section(path: str, dotted_key: str, value: Any, *, expected_hash: str) -> None:
    """Écrit `value` à `dotted_key` dans le fichier YAML `path`, en toute
    sécurité.

    Séquence stricte (identique à `write_declared_exporters`) :
    1. Vérifie que le fichier existe et que son hash actuel == `expected_hash`
       (verrou optimiste : `ConcurrentModificationError` sinon).
    2. Backup horodaté `<fichier>.bak-YYYYmmddHHMMSS`.
    3. Charge le document ruamel round-trip, modifie EN PLACE le nœud désigné
       par `dotted_key` (création des mappings intermédiaires manquants si la
       section est absente), écrit dans un fichier temporaire du même
       répertoire puis `os.replace()` (atomique).
    4. Re-parse le fichier écrit pour valider qu'il est bien reformé et que
       `dotted_key` contient exactement `value`.

    Ne dégrade JAMAIS silencieusement : toute anomalie lève une exception.
    """
    yaml_path = Path(path)
    if not yaml_path.is_file():
        log.error("ecriture impossible, fichier introuvable: path=%s", path)
        raise FileNotFoundError(f"fichier YAML introuvable: {path}")

    current_hash = compute_file_hash(path)
    if current_hash != expected_hash:
        log.error(
            "verrou optimiste: hash actuel differe du hash attendu, fichier modifie depuis: "
            "path=%s attendu=%s actuel=%s",
            path,
            expected_hash,
            current_hash,
        )
        raise ConcurrentModificationError(
            f"{path} a ete modifie depuis la derniere lecture "
            f"(hash attendu={expected_hash}, actuel={current_hash})"
        )

    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    backup_path = yaml_path.with_name(f"{yaml_path.name}.bak-{timestamp}")
    shutil.copy2(yaml_path, backup_path)
    log.info("backup cree avant ecriture: path=%s", backup_path)

    yaml_rw = YAML(typ="rt")
    yaml_rw.preserve_quotes = True
    try:
        with yaml_path.open("r", encoding="utf-8") as handle:
            document = yaml_rw.load(handle)
    except (YAMLError, OSError) as exc:
        log.error("relecture du fichier impossible avant ecriture: path=%s", path)
        raise ValueError(f"impossible de relire {path} avant ecriture: {exc}") from exc

    if not isinstance(document, dict):
        log.error("ecriture impossible, document racine n'est pas un mapping: path=%s", path)
        raise ValueError(f"document racine invalide (pas un mapping): {path}")

    segments = _split_dotted_key(dotted_key)
    if not segments or any(not segment for segment in segments):
        raise ValueError(f"dotted_key invalide: {dotted_key!r}")

    parent = _ensure_path(document, segments)
    parent[segments[-1]] = value

    tmp_path = yaml_path.with_name(f"{yaml_path.name}.tmp-{timestamp}")
    try:
        with tmp_path.open("w", encoding="utf-8") as handle:
            yaml_rw.dump(document, handle)
        os.replace(tmp_path, yaml_path)
    except OSError:
        log.error(
            "echec de l'ecriture atomique, fichier original preserve: path=%s",
            path,
            exc_info=True,
        )
        if tmp_path.exists():
            tmp_path.unlink()
        raise
    finally:
        if tmp_path.exists():
            tmp_path.unlink()

    reloaded = read_section(path, dotted_key)
    if reloaded != _to_plain(value):
        log.error(
            "validation post-ecriture echouee: attendu=%r obtenu=%r path=%s cle=%s",
            value,
            reloaded,
            path,
            dotted_key,
        )
        raise ValueError(
            f"le fichier ecrit ne contient pas la valeur attendue a '{dotted_key}' "
            f"(attendu={value!r}, obtenu={reloaded!r})"
        )

    log.info("section ecrite avec succes: path=%s cle=%s", path, dotted_key)
