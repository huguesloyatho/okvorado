"""Tests du catalogue applicatif (`app.services.app_catalog` + routeur).

TDD, avec MORSURE : chaque garantie critique (protection custom/métier,
idempotence, zéro silencieux réseau, règle min(SrcPort, DstPort), import
tout-ou-rien) est prouvée en SABOTANT le comportement attendu et en
vérifiant que le test échoue avant restauration — pas seulement affirmée par
un test qui passerait de toute façon.

Aucun appel réseau réel : `httpx.get` est monkeypatché dans tous les tests
qui touchent `reload_from_iana`.
"""

from __future__ import annotations

import sqlite3
from collections.abc import Generator

import httpx
import pytest
from fastapi.testclient import TestClient

from app.db import SCHEMA
from app.main import app
from app.routers import app_catalog as app_catalog_router
from app.services import app_catalog, portmap
from tests.conftest import authenticated_test_client

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def db() -> Generator[sqlite3.Connection]:
    conn = sqlite3.connect(":memory:", check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    conn.commit()
    try:
        yield conn
    finally:
        conn.close()


@pytest.fixture
def client(db: sqlite3.Connection) -> Generator[TestClient]:
    app.dependency_overrides[app_catalog_router.get_db_connection] = lambda: db
    try:
        yield authenticated_test_client(app)
    finally:
        app.dependency_overrides.pop(app_catalog_router.get_db_connection, None)


_SAMPLE_IANA_CSV = (
    "Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,"
    "Registration Date,Modification Date,Reference,Service Code,"
    "Unauthorized Use Reported,Assignment Notes\n"
    "http,80,tcp,World Wide Web HTTP,,,,,,,,\n"
    "https,443,tcp,HTTP over TLS/SSL,,,,,,,,\n"
    "domain,53,tcp,Domain Name Server,,,,,,,,\n"
    "domain,53,udp,Domain Name Server,,,,,,,,\n"
)


class _FakeResponse:
    def __init__(self, text: str, status_code: int = 200) -> None:
        self.text = text
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("GET", "https://www.iana.org/fake")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("boom", request=request, response=response)


def _fake_httpx_get_ok(*_args: object, **_kwargs: object) -> _FakeResponse:
    return _FakeResponse(_SAMPLE_IANA_CSV)


_SAMPLE_IANA_CSV_WITH_4070 = (
    "Service Name,Port Number,Transport Protocol,Description,Assignee,Contact,"
    "Registration Date,Modification Date,Reference,Service Code,"
    "Unauthorized Use Reported,Assignment Notes\n"
    "http,80,tcp,World Wide Web HTTP,,,,,,,,\n"
    "tripe,4070,tcp,TRIPE,,,,,,,,\n"
)
"""CSV IANA simulé qui CONTIENT 4070/tcp (nom trompeur 'tripe', comme le
registre officiel réel) — nécessaire pour que le test de non-écrasement par
`reload_from_iana` exerce RÉELLEMENT la garde `_PROTECTED_FROM_IANA_RELOAD`
sur cette clé (le CSV `_SAMPLE_IANA_CSV` par défaut ne contient pas 4070 :
un test qui l'utiliserait ne prouverait rien, la clé ne serait jamais
touchée par `_apply_entries` quelle que soit la garde)."""


def _fake_httpx_get_ok_with_4070(*_args: object, **_kwargs: object) -> _FakeResponse:
    return _FakeResponse(_SAMPLE_IANA_CSV_WITH_4070)


def _fake_httpx_get_network_error(*_args: object, **_kwargs: object) -> _FakeResponse:
    raise httpx.ConnectError("connexion refusee (proxy d'entreprise probable)")


# ---------------------------------------------------------------------------
# 1. Un rechargement IANA n'écrase JAMAIS une entrée custom/métier — MORSURE
# ---------------------------------------------------------------------------


def test_reload_iana_never_overwrites_custom_entry(
    db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """80/tcp est présent dans le CSV IANA simulé ('http') : une surcharge
    custom sur ce même port doit survivre au rechargement."""
    portmap.create_mapping(
        db, port=80, proto="tcp", application="Portail interne SFR", source="custom"
    )
    monkeypatch.setattr(httpx, "get", _fake_httpx_get_ok)

    status = app_catalog.reload_from_iana(db)

    assert status.status == "ok"
    mapping = portmap.get_mapping(db, 80, "tcp")
    assert mapping is not None
    assert mapping.application == "Portail interne SFR"
    assert mapping.source == "custom"


def test_reload_iana_never_overwrites_custom_entry_MORSURE(
    db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MORSURE : si `_apply_entries` perdait sa garde `source in ('custom',
    'metier')`, ce test DOIT échouer. On le prouve en appelant directement le
    chemin non protégé (upsert brut, même requête que `seed_iana_defaults`
    SANS la clause WHERE) et en vérifiant que — sans la garde — la valeur
    custom serait bien écrasée. Ceci démontre que la garde produit un effet
    observable, pas qu'elle existe seulement dans le code."""
    portmap.create_mapping(
        db, port=80, proto="tcp", application="Portail interne SFR", source="custom"
    )

    # Sabotage : upsert SANS la clause de protection (reproduit ce qui se
    # passerait si la garde disparaissait de `_apply_entries`).
    db.execute(
        "INSERT INTO port_mappings (port, proto, application, source) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(port, proto) DO UPDATE SET application = excluded.application, "
        "source = excluded.source",
        (80, "tcp", "World Wide Web HTTP", "iana"),
    )
    db.commit()
    sabotaged = portmap.get_mapping(db, 80, "tcp")
    assert sabotaged is not None
    assert sabotaged.source == "iana", "le sabotage doit avoir écrasé la valeur custom"
    assert sabotaged.application == "World Wide Web HTTP"

    # Restauration + preuve que le VRAI chemin (avec garde) ne fait PAS ça.
    portmap.create_mapping(
        db, port=80, proto="tcp", application="Portail interne SFR", source="custom"
    )
    monkeypatch.setattr(httpx, "get", _fake_httpx_get_ok)
    app_catalog.reload_from_iana(db)
    protected = portmap.get_mapping(db, 80, "tcp")
    assert protected is not None
    assert protected.source == "custom"
    assert protected.application == "Portail interne SFR"


def test_reload_iana_never_overwrites_metier_entry(
    db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """443/tcp métier (SCCM HTTPS) doit survivre au rechargement IANA."""
    app_catalog.seed_metier_defaults(db)
    metier_before = portmap.get_mapping(db, 443, "tcp")
    assert metier_before is not None
    assert metier_before.source == "metier"

    monkeypatch.setattr(httpx, "get", _fake_httpx_get_ok)
    app_catalog.reload_from_iana(db)

    metier_after = portmap.get_mapping(db, 443, "tcp")
    assert metier_after is not None
    assert metier_after.source == "metier"
    assert metier_after.application == metier_before.application


# ---------------------------------------------------------------------------
# 2. Idempotence du rechargement
# ---------------------------------------------------------------------------


def test_reload_iana_is_idempotent(db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(httpx, "get", _fake_httpx_get_ok)

    app_catalog.reload_from_iana(db)
    count_after_first = db.execute("SELECT COUNT(*) FROM port_mappings").fetchone()[0]

    app_catalog.reload_from_iana(db)
    count_after_second = db.execute("SELECT COUNT(*) FROM port_mappings").fetchone()[0]

    assert count_after_first == count_after_second
    assert count_after_first == 4  # http, https, domain/tcp, domain/udp


def test_reload_iana_idempotent_MORSURE(
    db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MORSURE : un rechargement qui ferait un INSERT pur (sans ON CONFLICT)
    dupliquerait les lignes. On le prouve en insérant nous-mêmes une ligne
    sans upsert et en montrant que ÇA, ça duplique — donc l'upsert réel de
    `reload_from_iana` (qui ne duplique pas) est bien la garde en jeu, pas un
    hasard de fixture vide."""
    monkeypatch.setattr(httpx, "get", _fake_httpx_get_ok)
    app_catalog.reload_from_iana(db)
    baseline = db.execute("SELECT COUNT(*) FROM port_mappings").fetchone()[0]

    # Sabotage : un INSERT sans clause de conflit, pour prouver qu'un vrai
    # doublon EST détectable dans ce test (la contrainte PK lèverait ici,
    # confirmant que la protection contre les doublons vient bien de la clé
    # primaire (port, proto) + upsert, pas d'un hasard).
    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO port_mappings (port, proto, application, source) "
            "VALUES (80, 'tcp', 'x', 'iana')"
        )

    # Le rechargement réel, lui, ne lève jamais et ne duplique jamais.
    app_catalog.reload_from_iana(db)
    after_second = db.execute("SELECT COUNT(*) FROM port_mappings").fetchone()[0]
    assert after_second == baseline


# ---------------------------------------------------------------------------
# 3. Réseau en échec -> état DISTINCT, jamais un catalogue vide silencieux
# ---------------------------------------------------------------------------


def test_reload_iana_network_failure_falls_back_to_embedded(
    db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Réseau KO -> statut 'offline_fallback' (DISTINCT de 'ok'), catalogue
    non vide grâce au repli embarqué réel du dépôt."""
    monkeypatch.setattr(httpx, "get", _fake_httpx_get_network_error)

    status = app_catalog.reload_from_iana(db)

    assert status.status == "offline_fallback"
    assert status.status != "ok"  # DISTINCTION explicite, pas un succès déguisé
    assert status.entries_iana > 1000  # repli embarqué réel (~11 600 lignes)
    total = db.execute("SELECT COUNT(*) FROM port_mappings").fetchone()[0]
    assert total > 1000, "le catalogue ne doit jamais rester vide après un echec reseau"


def test_reload_iana_network_failure_MORSURE_zero_silencieux(
    db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MORSURE du zéro silencieux : on sabote AUSSI le repli embarqué (chemin
    introuvable) pour forcer le pire cas — ni réseau ni repli. Le statut DOIT
    être 'error', explicitement distinct de 'ok'/'offline_fallback', jamais
    un silence qui laisserait croire à un succès."""
    monkeypatch.setattr(httpx, "get", _fake_httpx_get_network_error)
    monkeypatch.setattr(
        app_catalog, "_EMBEDDED_FALLBACK_PATH", app_catalog.Path("/inexistant/x.csv")
    )

    status = app_catalog.reload_from_iana(db)

    assert status.status == "error"
    assert status.status not in ("ok", "offline_fallback")
    assert status.entries_iana == 0
    assert status.detail  # jamais un message vide sur un échec

    # Restauration implicite : `monkeypatch` annule le patch à la fin du test
    # (fixture pytest), donc le vrai chemin reste intact pour les autres tests.


def test_reload_status_never_run_before_any_reload(db: sqlite3.Connection) -> None:
    """État initial explicite : 'never_run', jamais confondu avec 'ok' (zéro
    résultat) qui laisserait croire qu'un rechargement a eu lieu."""
    status = app_catalog.get_reload_status(db)
    assert status.status == "never_run"


# ---------------------------------------------------------------------------
# 4. Règle min(SrcPort, DstPort) — trois cas
# ---------------------------------------------------------------------------


def test_resolve_flow_service_to_ephemeral(db: sqlite3.Connection) -> None:
    """Retour de connexion : port SERVICE en source, port ÉPHÉMÈRE en
    destination. La règle doit quand même reconnaître le service (443)."""
    portmap.create_mapping(db, port=443, proto="tcp", application="HTTPS", source="iana")
    app = app_catalog.resolve_flow_application(db, src_port=443, dst_port=51234, proto="tcp")
    assert app == "HTTPS"


def test_resolve_flow_ephemeral_to_service(db: sqlite3.Connection) -> None:
    """Sens naïvement 'attendu' : port ÉPHÉMÈRE en source, port SERVICE en
    destination (443)."""
    portmap.create_mapping(db, port=443, proto="tcp", application="HTTPS", source="iana")
    app = app_catalog.resolve_flow_application(db, src_port=51234, dst_port=443, proto="tcp")
    assert app == "HTTPS"


def test_resolve_flow_both_ephemeral_falls_back_to_dst_port(db: sqlite3.Connection) -> None:
    """Deux ports éphémères (ex. pair-à-pair type Tailscale) : aucun n'est un
    port de service, on retombe sur le port DESTINATION."""
    portmap.create_mapping(
        db, port=40000, proto="udp", application="Pair-a-pair X", source="custom"
    )
    app = app_catalog.resolve_flow_application(db, src_port=50000, dst_port=40000, proto="udp")
    assert app == "Pair-a-pair X"


def test_resolve_flow_min_rule_MORSURE(db: sqlite3.Connection) -> None:
    """MORSURE : si la règle utilisait max() au lieu de min(), le cas
    service->éphémère résoudrait FAUX (sur le port éphémère, inconnu). On le
    prouve en calculant le résultat d'une règle max() sabotée et en montrant
    qu'elle diffère du résultat réel (donc que min() est bien ce qui est
    exécuté, pas un hasard de données)."""
    portmap.create_mapping(db, port=22, proto="tcp", application="SSH", source="iana")

    # Comportement RÉEL (min) : reconnaît SSH.
    real = app_catalog.resolve_flow_application(db, src_port=22, dst_port=54321, proto="tcp")
    assert real == "SSH"

    # Comportement SABOTÉ (max), pour montrer qu'il produirait un résultat
    # DIFFÉRENT et FAUX (repli proto/port, 54321 inconnu) — la divergence
    # prouve que la fonction réelle n'est pas équivalente à ce sabotage.
    sabotaged_port = max(22, 54321)
    sabotaged_result = portmap.resolve_application(db, sabotaged_port, "tcp")
    assert sabotaged_result != real
    assert sabotaged_result == "tcp/54321"


# ---------------------------------------------------------------------------
# 5. Import CSV refuse une ligne malformée en le DISANT (tout ou rien)
# ---------------------------------------------------------------------------


def test_parse_catalog_csv_rejects_malformed_line_with_message() -> None:
    content = "port;proto;application\n445;tcp;SMB\nabc;tcp;Casse tout\n"
    result = app_catalog.parse_catalog_csv(content)
    assert result.rows == []
    assert len(result.errors) == 1
    assert "abc" in result.errors[0]
    assert "port non entier" in result.errors[0]


def test_parse_catalog_csv_all_or_nothing_MORSURE() -> None:
    """MORSURE : une ligne valide AVANT une ligne invalide ne doit PAS
    ressortir dans `rows` — sinon l'import appliquerait un sous-ensemble en
    silence. On le prouve en vérifiant explicitement l'ABSENCE de la ligne
    valide dans le résultat malgré sa validité individuelle."""
    content = "445;tcp;SMB\nxxxxx;udp;Invalide\n8530;tcp;WSUS\n"
    result = app_catalog.parse_catalog_csv(content)

    assert result.rows == [], (
        "une ligne invalide doit vider TOUT le résultat, y compris les lignes "
        "valides qui l'entourent (445/tcp et 8530/tcp)"
    )
    assert len(result.errors) == 1
    assert "xxxxx" in result.errors[0]


def test_parse_catalog_csv_accepts_valid_multiline() -> None:
    content = "port;proto;application;port_end\n445;tcp;SMB;\n50000;tcp;FTP passif;51000\n"
    result = app_catalog.parse_catalog_csv(content)
    assert result.errors == []
    assert len(result.rows) == 2
    assert result.rows[0].port == 445
    assert result.rows[0].port_end is None
    assert result.rows[1].port_end == 51000


def test_parse_catalog_csv_rejects_duplicate_with_message() -> None:
    content = "445;tcp;SMB\n445;tcp;SMB encore\n"
    result = app_catalog.parse_catalog_csv(content)
    assert result.rows == []
    assert any("doublon" in err for err in result.errors)


def test_parse_catalog_csv_rejects_invalid_range() -> None:
    content = "50000;tcp;Plage inversee;40000\n"
    result = app_catalog.parse_catalog_csv(content)
    assert result.rows == []
    assert any("inférieure" in err for err in result.errors)


def test_import_router_rejects_malformed_csv_with_explicit_message(client: TestClient) -> None:
    response = client.post(
        "/app-catalog/import",
        data={"content": "445;tcp;SMB\nabc;tcp;Casse tout\n"},
    )
    assert response.status_code == 422
    assert "Import refusé" in response.text
    assert "abc" in response.text


def test_import_router_applies_valid_csv_as_metier(
    client: TestClient, db: sqlite3.Connection
) -> None:
    response = client.post(
        "/app-catalog/import",
        data={"content": "50123;tcp;Application maison SFR\n"},
    )
    assert response.status_code == 200
    mapping = portmap.get_mapping(db, 50123, "tcp")
    assert mapping is not None
    assert mapping.source == "metier"
    assert mapping.application == "Application maison SFR"


def test_import_router_does_not_overwrite_custom(
    client: TestClient, db: sqlite3.Connection
) -> None:
    portmap.create_mapping(db, port=445, proto="tcp", application="SMB exploitant", source="custom")
    response = client.post(
        "/app-catalog/import",
        data={"content": "445;tcp;SMB import ecrase pas\n"},
    )
    assert response.status_code == 200
    mapping = portmap.get_mapping(db, 445, "tcp")
    assert mapping is not None
    assert mapping.source == "custom"
    assert mapping.application == "SMB exploitant"


# ---------------------------------------------------------------------------
# 6. La page est atteignable depuis le menu (garde mécanique déjà dans
#    tests/test_navigation.py — ce test-ci prouve le CONTENU du lien, en plus)
# ---------------------------------------------------------------------------


def test_menu_contains_app_catalog_link() -> None:
    base_html = (
        __import__("pathlib").Path(__file__).parent.parent / "app" / "templates" / "base.html"
    ).read_text(encoding="utf-8")
    # Le lien passe désormais par le filtre Jinja `prefixed` (app servie
    # derrière le proxy Grafana) : la forme source est
    # `href="{{ '/app-catalog' | prefixed }}"`, plus `href="/app-catalog"`.
    assert "'/app-catalog' | prefixed" in base_html or '/app-catalog"' in base_html
    assert "Catalogue applicatif" in base_html


def test_app_catalog_page_reachable_via_http(client: TestClient) -> None:
    response = client.get("/app-catalog")
    assert response.status_code == 200
    assert "Catalogue applicatif" in response.text


# ---------------------------------------------------------------------------
# Compléments — seed métier, pagination/recherche, port_end, non-régression
# des appelants existants de resolve_application
# ---------------------------------------------------------------------------


def test_seed_metier_defaults_covers_sccm_and_tailscale(db: sqlite3.Connection) -> None:
    app_catalog.seed_metier_defaults(db)
    assert portmap.resolve_application(db, 445, "tcp") == "SCCM - SMB (partage de contenu)"
    assert portmap.resolve_application(db, 41641, "udp").startswith("Tailscale")


def test_seed_metier_defaults_does_not_overwrite_custom(db: sqlite3.Connection) -> None:
    portmap.create_mapping(
        db, port=3389, proto="tcp", application="RDP passerelle", source="custom"
    )
    app_catalog.seed_metier_defaults(db)
    mapping = portmap.get_mapping(db, 3389, "tcp")
    assert mapping is not None
    assert mapping.source == "custom"
    assert mapping.application == "RDP passerelle"


def test_seed_metier_defaults_is_idempotent(db: sqlite3.Connection) -> None:
    app_catalog.seed_metier_defaults(db)
    count_first = db.execute("SELECT COUNT(*) FROM port_mappings").fetchone()[0]
    app_catalog.seed_metier_defaults(db)
    count_second = db.execute("SELECT COUNT(*) FROM port_mappings").fetchone()[0]
    assert count_first == count_second


def test_list_catalog_page_search_by_port(db: sqlite3.Connection) -> None:
    app_catalog.seed_metier_defaults(db)
    result = app_catalog.list_catalog_page(db, search="3389")
    assert result.total >= 1
    assert any(item.port == 3389 for item in result.items)


def test_list_catalog_page_search_by_application_name(db: sqlite3.Connection) -> None:
    app_catalog.seed_metier_defaults(db)
    result = app_catalog.list_catalog_page(db, search="Tailscale")
    assert result.total == 1
    assert result.items[0].application.startswith("Tailscale")


def test_list_catalog_page_filter_by_source(db: sqlite3.Connection) -> None:
    app_catalog.seed_metier_defaults(db)
    portmap.create_mapping(db, port=9999, proto="tcp", application="Ajout manuel", source="custom")
    result = app_catalog.list_catalog_page(db, source="custom")
    assert result.total == 1
    assert result.items[0].source == "custom"


def test_list_catalog_page_pagination(db: sqlite3.Connection) -> None:
    for port in range(10000, 10025):
        portmap.create_mapping(
            db, port=port, proto="tcp", application=f"App {port}", source="custom"
        )
    page1 = app_catalog.list_catalog_page(db, page=1, page_size=10)
    page2 = app_catalog.list_catalog_page(db, page=2, page_size=10)
    assert len(page1.items) == 10
    assert len(page2.items) == 10
    assert page1.items[0].port != page2.items[0].port
    assert page1.total == 25
    assert page1.total_pages == 3


def test_port_range_create_and_label(db: sqlite3.Connection) -> None:
    mapping = portmap.create_mapping(
        db, port=50000, proto="tcp", application="FTP passif", source="custom", port_end=51000
    )
    assert mapping.is_range
    assert mapping.port_label == "50000-51000"


def test_port_range_rejects_end_before_start() -> None:
    with pytest.raises(portmap.ValidationError):
        portmap.validate_port_range(50000, 40000)


def test_existing_resolve_application_callers_unaffected(db: sqlite3.Connection) -> None:
    """Non-régression EXPLICITE : `resolve_application(conn, port, proto)`,
    tel qu'utilisé par `app/routers/views.py` et `app/routers/diagnostics.py`,
    continue de fonctionner à l'identique après l'ajout de `port_end`."""
    portmap.create_mapping(db, port=443, proto="tcp", application="HTTPS", source="iana")
    assert portmap.resolve_application(db, 443, "tcp") == "HTTPS"
    assert portmap.resolve_application(db, 9999, "tcp") == "tcp/9999"


def test_export_catalog_csv_roundtrip(db: sqlite3.Connection) -> None:
    portmap.create_mapping(db, port=445, proto="tcp", application="SMB", source="custom")
    csv_text = app_catalog.export_catalog_csv(db)
    assert "445;tcp;SMB;" in csv_text

    reparsed = app_catalog.parse_catalog_csv(csv_text)
    assert reparsed.errors == []
    assert any(row.port == 445 and row.application == "SMB" for row in reparsed.rows)


def test_export_catalog_csv_empty_catalog_is_valid_header_only(db: sqlite3.Connection) -> None:
    csv_text = app_catalog.export_catalog_csv(db)
    assert csv_text.strip() == "port;proto;application;port_end"


def test_get_app_catalog_page_shows_reload_status_distinct_states(
    client: TestClient, db: sqlite3.Connection
) -> None:
    response = client.get("/app-catalog")
    assert response.status_code == 200
    assert 'data-reload-status="never_run"' in response.text


def test_delete_app_catalog_entry_via_http(client: TestClient, db: sqlite3.Connection) -> None:
    portmap.create_mapping(db, port=9998, proto="tcp", application="A supprimer", source="custom")
    response = client.delete("/app-catalog/9998/tcp")
    assert response.status_code == 200
    assert portmap.get_mapping(db, 9998, "tcp") is None


def test_create_app_catalog_entry_via_http_marks_custom(
    client: TestClient, db: sqlite3.Connection
) -> None:
    response = client.post(
        "/app-catalog",
        data={"port": "9997", "proto": "tcp", "application": "Ajout ecran"},
    )
    assert response.status_code == 201
    mapping = portmap.get_mapping(db, 9997, "tcp")
    assert mapping is not None
    assert mapping.source == "custom"


def test_is_ephemeral_port_threshold() -> None:
    assert app_catalog.is_ephemeral_port(32768) is True
    assert app_catalog.is_ephemeral_port(32767) is False
    assert app_catalog.is_ephemeral_port(41641) is True  # Tailscale, mesuré


# ---------------------------------------------------------------------------
# 7. Catalogue GRAND PUBLIC — reproche fondé de l'utilisateur : les 28
#    entrées métier initiales étaient TOUTES des applications système/SCCM.
#    Les 3 exemples "aux antipodes" doivent être reconnus, un nom IANA
#    trompeur doit être remplacé, la source ne doit jamais être écrasée par
#    IANA, et chaque grande famille doit avoir au moins une entrée.
# ---------------------------------------------------------------------------


def test_seed_grand_public_recognizes_bittorrent(db: sqlite3.Connection) -> None:
    app_catalog.seed_grand_public_defaults(db)
    assert "BitTorrent" in portmap.resolve_application(db, 6881, "tcp")
    assert "BitTorrent" in portmap.resolve_application(db, 6969, "tcp")
    assert "BitTorrent" in portmap.resolve_application(db, 51413, "tcp")


def test_seed_grand_public_recognizes_spotify(db: sqlite3.Connection) -> None:
    app_catalog.seed_grand_public_defaults(db)
    assert "Spotify" in portmap.resolve_application(db, 4070, "tcp")
    assert "Spotify" in portmap.resolve_application(db, 57621, "udp")


def test_seed_grand_public_recognizes_appel_wifi(db: sqlite3.Connection) -> None:
    """L'appel WiFi (VoWiFi/IPsec) doit parler à un exploitant : jamais le nom
    IANA brut 'isakmp'/'ipsec-nat-t', mais 'Appel WiFi / VoWiFi' explicite."""
    app_catalog.seed_grand_public_defaults(db)
    label_500 = portmap.resolve_application(db, 500, "udp")
    label_4500 = portmap.resolve_application(db, 4500, "udp")
    assert "VoWiFi" in label_500 or "Appel WiFi" in label_500
    assert "VoWiFi" in label_4500 or "Appel WiFi" in label_4500
    assert label_500 != "isakmp"
    assert label_4500 != "ipsec-nat-t"


def test_seed_grand_public_replaces_misleading_iana_name(db: sqlite3.Connection) -> None:
    """MESURE (cf. tâche) : IANA nomme 4070/tcp 'tripe' (faux, incompréhensible).
    Le catalogue grand public doit REMPLACER ce nom, pas coexister avec lui."""
    portmap.create_mapping(db, port=4070, proto="tcp", application="tripe", source="iana")
    app_catalog.seed_grand_public_defaults(db)
    mapping = portmap.get_mapping(db, 4070, "tcp")
    assert mapping is not None
    assert mapping.application != "tripe"
    assert "Spotify" in mapping.application
    assert mapping.source == "grand_public"


def test_seed_grand_public_replaces_misleading_iana_name_acmsoda(db: sqlite3.Connection) -> None:
    """Même mesure sur 6969/tcp -> IANA 'acmsoda' (faux, tracker BitTorrent
    en réalité)."""
    portmap.create_mapping(db, port=6969, proto="tcp", application="acmsoda", source="iana")
    app_catalog.seed_grand_public_defaults(db)
    mapping = portmap.get_mapping(db, 6969, "tcp")
    assert mapping is not None
    assert mapping.application != "acmsoda"
    assert "BitTorrent" in mapping.application


def test_seed_grand_public_never_overwritten_by_iana_reload(
    db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Une entrée grand_public ne doit JAMAIS être écrasée par un
    rechargement IANA — même contrat que custom/métier. Le CSV IANA simulé
    ici CONTIENT 4070/tcp (nom trompeur 'tripe') : la garde est donc
    RÉELLEMENT exercée sur cette clé, pas contournée par un CSV qui ne la
    toucherait jamais."""
    app_catalog.seed_grand_public_defaults(db)
    before = portmap.get_mapping(db, 4070, "tcp")
    assert before is not None
    assert before.source == "grand_public"

    monkeypatch.setattr(httpx, "get", _fake_httpx_get_ok_with_4070)
    status = app_catalog.reload_from_iana(db)
    assert status.status == "ok"

    after = portmap.get_mapping(db, 4070, "tcp")
    assert after is not None
    assert after.source == "grand_public"
    assert after.application == before.application
    assert after.application != "tripe"


def test_seed_grand_public_never_overwritten_by_iana_reload_MORSURE(
    db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MORSURE : si `_PROTECTED_FROM_IANA_RELOAD` perdait 'grand_public', ce
    test DOIT échouer. On le prouve en rejouant le chemin non protégé (upsert
    brut, sans la clause WHERE) et en montrant qu'IL écraserait bien
    grand_public — donc que la garde réelle produit un effet observable."""
    app_catalog.seed_grand_public_defaults(db)
    before = portmap.get_mapping(db, 4070, "tcp")
    assert before is not None
    assert before.source == "grand_public"

    # Sabotage : upsert SANS la clause de protection.
    db.execute(
        "INSERT INTO port_mappings (port, proto, application, source) VALUES (?, ?, ?, ?) "
        "ON CONFLICT(port, proto) DO UPDATE SET application = excluded.application, "
        "source = excluded.source",
        (4070, "tcp", "tripe", "iana"),
    )
    db.commit()
    sabotaged = portmap.get_mapping(db, 4070, "tcp")
    assert sabotaged is not None
    assert sabotaged.source == "iana", "le sabotage doit avoir écrasé la valeur grand_public"
    assert sabotaged.application == "tripe"

    # Restauration + preuve que le VRAI chemin (avec garde) ne fait PAS ça.
    # CSV avec 4070/tcp inclus ('tripe') : la garde est réellement exercée.
    app_catalog.seed_grand_public_defaults(db)
    monkeypatch.setattr(httpx, "get", _fake_httpx_get_ok_with_4070)
    app_catalog.reload_from_iana(db)
    protected = portmap.get_mapping(db, 4070, "tcp")
    assert protected is not None
    assert protected.source == "grand_public"
    assert "Spotify" in protected.application


def test_seed_grand_public_does_not_overwrite_custom(db: sqlite3.Connection) -> None:
    portmap.create_mapping(
        db, port=4070, proto="tcp", application="Application maison SFR", source="custom"
    )
    app_catalog.seed_grand_public_defaults(db)
    mapping = portmap.get_mapping(db, 4070, "tcp")
    assert mapping is not None
    assert mapping.source == "custom"
    assert mapping.application == "Application maison SFR"


def test_seed_grand_public_is_idempotent(db: sqlite3.Connection) -> None:
    written_first = app_catalog.seed_grand_public_defaults(db)
    count_first = db.execute(
        "SELECT COUNT(*) FROM port_mappings WHERE source = 'grand_public'"
    ).fetchone()[0]

    written_second = app_catalog.seed_grand_public_defaults(db)
    count_second = db.execute(
        "SELECT COUNT(*) FROM port_mappings WHERE source = 'grand_public'"
    ).fetchone()[0]

    assert written_first == written_second
    assert count_first == count_second
    assert count_first > 50  # catalogue substantiel, pas une poignée d'exemples


def test_seed_grand_public_is_idempotent_MORSURE(db: sqlite3.Connection) -> None:
    """MORSURE : si le seed faisait un INSERT pur (sans ON CONFLICT), un
    second appel lèverait une IntegrityError sur la clé primaire (port,
    proto) au lieu de faire un no-op silencieux."""
    app_catalog.seed_grand_public_defaults(db)
    baseline = db.execute(
        "SELECT COUNT(*) FROM port_mappings WHERE source = 'grand_public'"
    ).fetchone()[0]

    with pytest.raises(sqlite3.IntegrityError):
        db.execute(
            "INSERT INTO port_mappings (port, proto, application, source) "
            "VALUES (4070, 'tcp', 'x', 'grand_public')"
        )

    app_catalog.seed_grand_public_defaults(db)
    after_second = db.execute(
        "SELECT COUNT(*) FROM port_mappings WHERE source = 'grand_public'"
    ).fetchone()[0]
    assert after_second == baseline


def test_seed_grand_public_covers_every_family(db: sqlite3.Connection) -> None:
    """Test de COUVERTURE : chaque grande famille annoncée dans la tâche a AU
    MOINS une entrée. C'est ce test qui empêche de retomber dans « je couvre
    l'exemple, pas la famille ». Le catalogue encode la catégorie en préfixe
    `[Catégorie] Nom` dans le champ `application` (pas de colonne dédiée) —
    on cherche donc le préfixe dans les valeurs, jamais dans un commentaire
    ou une docstring (piège vécu : un grep qui mord sur sa propre doc)."""
    app_catalog.seed_grand_public_defaults(db)
    applications = [
        str(row[0])
        for row in db.execute(
            "SELECT application FROM port_mappings WHERE source = 'grand_public'"
        ).fetchall()
    ]
    assert applications, "le catalogue grand public ne doit jamais être vide en base"

    expected_family_prefixes = {
        "P2P": "[P2P]",
        "Streaming": "[Streaming]",
        "Visio": "[Visio]",
        "Messagerie": "[Messagerie]",
        "Jeu": "[Jeu]",
        "VoWiFi": "[VoWiFi]",
        "Cloud": "[Cloud]",
        "VPN": "[VPN]",
        "IoT": "[IoT]",
    }
    for family_name, prefix in expected_family_prefixes.items():
        matches = [app for app in applications if app.startswith(prefix)]
        assert matches, (
            f"famille {family_name!r} (préfixe {prefix!r}) absente du catalogue grand "
            f"public en BASE — au moins une entrée est requise, cf. test de couverture"
        )


def test_seed_grand_public_covers_every_family_MORSURE(db: sqlite3.Connection) -> None:
    """MORSURE du test de couverture lui-même : si on ne charge QUE les 3
    exemples explicites de l'utilisateur (BitTorrent, Spotify, appel WiFi) et
    pas les autres familles (jeux, cloud, VPN, IoT, messagerie...), le test
    de couverture DOIT échouer. On le prouve sur une base delibérément
    limitée aux 3 exemples, sans toucher au vrai catalogue chargé."""
    portmap.create_mapping(
        db, port=6881, proto="tcp", application="[P2P] BitTorrent", source="grand_public"
    )
    portmap.create_mapping(
        db, port=4070, proto="tcp", application="[Streaming] Spotify", source="grand_public"
    )
    portmap.create_mapping(
        db, port=500, proto="udp", application="[VoWiFi] Appel WiFi", source="grand_public"
    )

    applications = [
        str(row[0])
        for row in db.execute(
            "SELECT application FROM port_mappings WHERE source = 'grand_public'"
        ).fetchall()
    ]
    missing_families = [
        prefix
        for prefix in ("[Jeu]", "[Cloud]", "[VPN]", "[IoT]", "[Messagerie]")
        if not any(app.startswith(prefix) for app in applications)
    ]
    assert missing_families, (
        "sur une base limitée aux 3 exemples, plusieurs familles DOIVENT manquer — "
        "si ce n'est pas le cas, le test de couverture ne mord plus"
    )


def test_grand_public_fallback_file_has_no_duplicate_port_proto_keys() -> None:
    """Le fichier de données lui-même ne doit pas contenir de doublon
    (port, proto) — un doublon silencieux masquerait une entrée derrière une
    autre au chargement (le parseur ne garde que la première ou la
    dernière selon l'implémentation, jamais documenté comme comportement
    voulu)."""
    entries = app_catalog._load_grand_public_fallback()
    assert entries is not None
    keys = [(port, proto) for port, proto, _application in entries]
    assert len(keys) == len(set(keys)), "doublons (port, proto) détectés dans le fichier de données"


def test_grand_public_is_in_valid_sources() -> None:
    assert "grand_public" in app_catalog.VALID_SOURCES


def test_grand_public_missing_file_degrades_gracefully_MORSURE(
    db: sqlite3.Connection, monkeypatch: pytest.MonkeyPatch
) -> None:
    """MORSURE zéro silencieux : si le fichier de données est absent, le seed
    ne doit jamais lever, doit retourner 0, et ne doit rien écrire — jamais
    un crash au démarrage, jamais un faux succès."""
    monkeypatch.setattr(
        app_catalog, "_GRAND_PUBLIC_FALLBACK_PATH", app_catalog.Path("/inexistant/grand_public.csv")
    )
    written = app_catalog.seed_grand_public_defaults(db)
    assert written == 0
    count = db.execute(
        "SELECT COUNT(*) FROM port_mappings WHERE source = 'grand_public'"
    ).fetchone()[0]
    assert count == 0
