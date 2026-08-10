"""Service portmap — table port→application éditable (SQLite).

CRUD complet sur `port_mappings`, requêtes paramétrées exclusivement (jamais
de f-string dans le SQL). Le schéma de la table est fourni par le LOT 0
(`app/db.py`) ; ce module n'en est que le consommateur — il ne crée la table
que dans le contexte des tests (fixtures locales), jamais en prod.

Voir CONTRACT.md — section LOT 3.
"""

from __future__ import annotations

import logging
import sqlite3

from app.models import PortMapping

log = logging.getLogger(__name__)

VALID_PROTOS = ("tcp", "udp")
MIN_PORT = 1
MAX_PORT = 65535
MAX_APPLICATION_LENGTH = 128


class ValidationError(ValueError):
    """Levée quand un port_mapping ne respecte pas les bornes métier."""


def validate_port(port: int) -> None:
    if not (MIN_PORT <= port <= MAX_PORT):
        raise ValidationError(f"port hors bornes: {port!r} (attendu: {MIN_PORT}..{MAX_PORT})")


def validate_proto(proto: str) -> None:
    if proto not in VALID_PROTOS:
        raise ValidationError(f"proto invalide: {proto!r} (attendu: {', '.join(VALID_PROTOS)})")


def validate_application(application: str) -> None:
    if not application or not application.strip():
        raise ValidationError("application ne peut pas être vide")
    if len(application) > MAX_APPLICATION_LENGTH:
        raise ValidationError(
            f"application trop longue: {len(application)} caractères (max {MAX_APPLICATION_LENGTH})"
        )


def list_mappings(conn: sqlite3.Connection) -> list[PortMapping]:
    """Retourne tous les port_mappings, triés par port puis proto."""
    rows = conn.execute(
        "SELECT port, proto, application, source, port_end FROM port_mappings ORDER BY port, proto"
    ).fetchall()
    return [
        PortMapping(port=row[0], proto=row[1], application=row[2], source=row[3], port_end=row[4])
        for row in rows
    ]


def get_mapping(conn: sqlite3.Connection, port: int, proto: str) -> PortMapping | None:
    row = conn.execute(
        "SELECT port, proto, application, source, port_end FROM port_mappings "
        "WHERE port = ? AND proto = ?",
        (port, proto),
    ).fetchone()
    if row is None:
        return None
    return PortMapping(
        port=row[0], proto=row[1], application=row[2], source=row[3], port_end=row[4]
    )


def validate_port_range(port: int, port_end: int | None) -> None:
    """Valide `port_end` s'il est fourni : borné et >= `port` (plage non vide)."""
    if port_end is None:
        return
    validate_port(port_end)
    if port_end < port:
        raise ValidationError(
            f"fin de plage invalide: {port_end!r} inférieure au port de début {port!r}"
        )


def create_mapping(
    conn: sqlite3.Connection,
    port: int,
    proto: str,
    application: str,
    source: str = "custom",
    port_end: int | None = None,
) -> PortMapping:
    """Crée ou remplace (upsert) un port_mapping. Requête paramétrée.

    `port_end` (optionnel) déclare une PLAGE de ports plutôt qu'un port
    unique (ex. `50000-51000`) — cas métier réel (FTP passif, plage
    applicative propriétaire). `None` = port unique, le cas dominant.

    Raises:
        ValidationError: si port/proto/application/port_end ne respectent
            pas les bornes.
    """
    validate_port(port)
    validate_proto(proto)
    validate_application(application)
    validate_port_range(port, port_end)

    conn.execute(
        """
        INSERT INTO port_mappings (port, proto, application, source, port_end)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(port, proto) DO UPDATE SET
            application = excluded.application,
            source = excluded.source,
            port_end = excluded.port_end
        """,
        (port, proto, application, source, port_end),
    )
    conn.commit()
    return PortMapping(
        port=port, proto=proto, application=application, source=source, port_end=port_end
    )


def delete_mapping(conn: sqlite3.Connection, port: int, proto: str) -> None:
    """Supprime un port_mapping. Requête paramétrée — pas d'interpolation."""
    conn.execute(
        "DELETE FROM port_mappings WHERE port = ? AND proto = ?",
        (port, proto),
    )
    conn.commit()


def resolve_application(conn: sqlite3.Connection, port: int, proto: str) -> str:
    """Traduit port+proto en nom applicatif.

    Fallback lisible (ex. "tcp/49152") quand le port est inconnu de la table.
    """
    mapping = get_mapping(conn, port, proto)
    if mapping is not None:
        return mapping.application
    return f"{proto}/{port}"


# ---------------------------------------------------------------------------
# Seed IANA — préchargement idempotent
# ---------------------------------------------------------------------------

# Ports IANA courants (source 'iana'). ~40-60 entrées, raisonnablement exhaustif
# sans s'y noyer — voir CONTRACT.md pour la liste minimale attendue.
_IANA_DEFAULTS: tuple[tuple[int, str, str], ...] = (
    (20, "tcp", "FTP-data"),
    (21, "tcp", "FTP"),
    (22, "tcp", "SSH"),
    (23, "tcp", "Telnet"),
    (25, "tcp", "SMTP"),
    (53, "tcp", "DNS"),
    (53, "udp", "DNS"),
    (67, "udp", "DHCP-server"),
    (68, "udp", "DHCP-client"),
    (69, "udp", "TFTP"),
    (80, "tcp", "HTTP"),
    (110, "tcp", "POP3"),
    (111, "tcp", "RPCbind"),
    (119, "tcp", "NNTP"),
    (123, "udp", "NTP"),
    (135, "tcp", "MS-RPC"),
    (137, "udp", "NetBIOS-NS"),
    (138, "udp", "NetBIOS-DGM"),
    (139, "tcp", "NetBIOS-SSN"),
    (143, "tcp", "IMAP"),
    (161, "udp", "SNMP"),
    (162, "udp", "SNMP-trap"),
    (179, "tcp", "BGP"),
    (194, "tcp", "IRC"),
    (389, "tcp", "LDAP"),
    (443, "tcp", "HTTPS"),
    (445, "tcp", "SMB"),
    (465, "tcp", "SMTPS"),
    (500, "udp", "IKE"),
    (514, "udp", "syslog"),
    (515, "tcp", "LPD"),
    (520, "udp", "RIP"),
    (587, "tcp", "SMTP-submission"),
    (631, "tcp", "IPP"),
    (636, "tcp", "LDAPS"),
    (873, "tcp", "rsync"),
    (989, "tcp", "FTPS-data"),
    (990, "tcp", "FTPS"),
    (993, "tcp", "IMAPS"),
    (995, "tcp", "POP3S"),
    (1080, "tcp", "SOCKS"),
    (1194, "udp", "OpenVPN"),
    (1433, "tcp", "MSSQL"),
    (1521, "tcp", "Oracle-DB"),
    (1723, "tcp", "PPTP"),
    (2049, "tcp", "NFS"),
    (2375, "tcp", "Docker-API"),
    (2376, "tcp", "Docker-API-TLS"),
    (3128, "tcp", "Squid-proxy"),
    (3306, "tcp", "MySQL"),
    (3389, "tcp", "RDP"),
    (5060, "udp", "SIP"),
    (5222, "tcp", "XMPP"),
    (5432, "tcp", "PostgreSQL"),
    (5900, "tcp", "VNC"),
    (5984, "tcp", "CouchDB"),
    (6379, "tcp", "Redis"),
    (6443, "tcp", "Kubernetes-API"),
    (8080, "tcp", "HTTP-alt"),
    (8123, "tcp", "ClickHouse-HTTP"),
    (8443, "tcp", "HTTPS-alt"),
    (9000, "tcp", "ClickHouse-native"),
    (9092, "tcp", "Kafka"),
    (9200, "tcp", "Elasticsearch"),
    (11211, "tcp", "Memcached"),
    (27017, "tcp", "MongoDB"),
    (51820, "udp", "WireGuard"),
)

# Surcharges maison connues du homelab (source 'custom'). Les surcharges
# priment sur les entrées IANA en cas de conflit de port+proto.
_CUSTOM_DEFAULTS: tuple[tuple[int, str, str], ...] = (
    (8082, "tcp", "Akvorado"),
    (3100, "tcp", "Gitea"),
    (2055, "udp", "NetFlow v9"),
    (4739, "udp", "IPFIX"),
    (6343, "udp", "sFlow"),
    (10179, "tcp", "Akvorado-outlet"),
)


def seed_iana_defaults(conn: sqlite3.Connection) -> None:
    """Précharge les ports IANA + surcharges maison. Idempotent.

    - Relancer ne duplique pas (upsert sur PRIMARY KEY (port, proto)).
    - N'écrase JAMAIS une surcharge 'custom' déjà présente : seules les
      entrées encore marquées 'iana' (ou absentes) sont (ré)écrites.
    """
    for port, proto, application in _IANA_DEFAULTS:
        existing = get_mapping(conn, port, proto)
        if existing is not None and existing.source == "custom":
            # Une surcharge utilisateur existe déjà sur ce port : on ne touche pas.
            continue
        conn.execute(
            """
            INSERT INTO port_mappings (port, proto, application, source)
            VALUES (?, ?, ?, 'iana')
            ON CONFLICT(port, proto) DO UPDATE SET
                application = excluded.application,
                source = excluded.source
            WHERE port_mappings.source != 'custom'
            """,
            (port, proto, application),
        )

    for port, proto, application in _CUSTOM_DEFAULTS:
        existing = get_mapping(conn, port, proto)
        if existing is not None and existing.source == "custom":
            # Une surcharge custom (potentiellement modifiée par l'utilisateur
            # depuis le seed initial) prime : on ne l'écrase pas non plus.
            continue
        conn.execute(
            """
            INSERT INTO port_mappings (port, proto, application, source)
            VALUES (?, ?, ?, 'custom')
            ON CONFLICT(port, proto) DO UPDATE SET
                application = excluded.application,
                source = excluded.source
            """,
            (port, proto, application),
        )

    conn.commit()
    log.info(
        "portmap: seed IANA/custom effectué (%d iana + %d custom candidats)",
        len(_IANA_DEFAULTS),
        len(_CUSTOM_DEFAULTS),
    )
