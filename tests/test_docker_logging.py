"""Vérifie la politique de rotation des logs Docker du stack.

Les tests CHARGENT le YAML réel (`stack/docker-compose.yml`) et itèrent sur
les clés RÉELLES de `services:` — jamais une liste de noms écrite en dur ici,
qui deviendrait fausse dès qu'un service est ajouté/retiré (piège vécu à
plusieurs reprises sur ce projet).

Le projet dépend de `ruamel.yaml` (voir `app/clients/akvorado_yaml.py` et
`pyproject.toml`), pas de `pyyaml` : ce test utilise `ruamel.yaml` pour ne
rien ajouter aux dépendances.
"""

from pathlib import Path

from ruamel.yaml import YAML

STACK_DIR = Path(__file__).parent.parent / "stack"
COMPOSE_PATH = STACK_DIR / "docker-compose.yml"
ENV_EXAMPLE_PATH = STACK_DIR / ".env.example"


def _load_compose() -> dict:
    yaml_loader = YAML(typ="safe")
    with COMPOSE_PATH.open(encoding="utf-8") as fh:
        return yaml_loader.load(fh)


def test_tous_les_services_ont_une_politique_de_rotation() -> None:
    """Chaque service du compose déclare une politique `logging:` explicite.

    Vérifie la PRÉSENCE de `max-size`/`max-file` et un format non vide — pas
    la résolution de `${VAR:-default}`, qui est le job de Docker Compose au
    runtime, pas de ce test.
    """
    compose = _load_compose()
    services = compose["services"]
    assert services, "aucun service trouve dans stack/docker-compose.yml"

    for name, service in services.items():
        assert "logging" in service, f"service {name!r}: aucune section logging:"
        logging_cfg = service["logging"]
        assert logging_cfg.get("driver") == "json-file", (
            f"service {name!r}: driver de logging inattendu ({logging_cfg.get('driver')!r})"
        )
        options = logging_cfg.get("options", {})

        max_size = options.get("max-size", "")
        assert max_size, f"service {name!r}: max-size absent ou vide"

        max_file = options.get("max-file", "")
        assert max_file, f"service {name!r}: max-file absent ou vide"


def test_env_example_documente_les_variables_de_rotation() -> None:
    """`DOCKER_LOG_MAX_SIZE` et `DOCKER_LOG_MAX_FILE` sont documentées dans .env.example."""
    content = ENV_EXAMPLE_PATH.read_text(encoding="utf-8")

    assert "DOCKER_LOG_MAX_SIZE" in content
    assert "DOCKER_LOG_MAX_FILE" in content


def test_compose_reste_un_yaml_valide_apres_ajout_du_logging() -> None:
    """Le compose reste parseable en entier (structure `services:` intacte)."""
    compose = _load_compose()

    assert "services" in compose
    assert isinstance(compose["services"], dict)
    assert len(compose["services"]) >= 10
