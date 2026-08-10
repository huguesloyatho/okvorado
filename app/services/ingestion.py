"""Traduction des compteurs Prometheus de l'outlet en diagnostic actionnable.

Un flux rejeté par Akvorado n'apparaît nulle part dans ClickHouse : ce module
est la seule fenêtre sur ce qui se perd à l'ingestion. Il transforme les
compteurs bruts de `OutletMetrics` en `list[RejectionReason]`, chacune munie
d'une explication en clair et d'une remédiation concrète, triées pour faire
ressortir en premier les exportateurs au taux de rejet critique (cas .18 :
100% de rejet, 0 flux forwarded).

TENDANCE (2026-08-09) — DÉFAUT MESURÉ : les compteurs Prometheus de l'outlet
sont CUMULATIFS depuis le démarrage du conteneur, jamais remis à zéro. Un
incident réseau du matin (Tailscale masquant l'adresse source des
exportateurs) avait laissé deux compteurs figés à un total élevé — la
passerelle Docker et l'adresse LAN de l'hôte, pas de vrais équipements —
affichés à l'écran avec la même urgence visuelle qu'un rejet EN COURS, alors
que 0 nouveau rejet n'était survenu depuis 11 heures. Ce module ajoute
`annotate_trend`, qui compare le compte courant à un point de mesure
antérieur persisté dans `ingestion_rejection_history` (même motif que
`app.routers.db_health._record_history`/`db_health_history` — une ligne par
appel de l'écran/API, pas de scheduler dédié) pour distinguer :
  - "rising" : ça continue de grimper MAINTENANT — action exigée ;
  - "flat"   : cumul figé — séquelle d'un incident passé, pas d'urgence ;
  - "unknown": aucun point de comparaison encore disponible (première mesure,
    ou aucun point assez ancien) — JAMAIS confondu avec "flat" (zéro
    silencieux, CLAUDE.md règle n°2) : un "+0" par défaut affirmerait à tort
    que rien ne bouge.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import dataclass
from typing import Any

from app.clients.prometheus import OutletMetrics
from app.models import RejectionReason, TrendState

log = logging.getLogger(__name__)

TREND_WINDOW_SECONDS = 300
"""Fenêtre de comparaison pour la tendance — 5 minutes : assez court pour
distinguer "ça vient de repartir" d'un cumul historique, assez long pour ne
pas réagir au bruit d'un seul cycle de scrape Prometheus (défaut ~15s)."""

_KNOWN_MOTIFS: dict[str, tuple[str, str]] = {
    "input and output interfaces missing": (
        "Akvorado rejette tout flux dont les interfaces d'entrée et de sortie "
        "sont vides. C'est le comportement de softflowd 1.1.0, qui ne renseigne "
        "pas ces champs en NetFlow v9.",
        "Compiler ou installer softflowd 1.1.1 sur cette machine (les dépôts "
        "Debian/Ubuntu/Alpine ne packagent que la 1.1.0). Sur macOS, forcer "
        "l'ifIndex avec `-i <idx>:<iface>`.",
    ),
    "metadata missing": (
        "Akvorado a reçu ces flux mais n'a pas pu résoudre l'exportateur par "
        "SNMP, et il rejette tout flux dont les métadonnées manquent. MESURÉ "
        "sur une installation neuve (2026-08-09) : le poller SNMP échoue en "
        "« context deadline exceeded », puis l'outlet ouvre son disjoncteur "
        "(« provider breaker open ») et cesse d'interroger cet exportateur "
        "pendant un temps. C'est le motif NORMAL d'un stack qui vient de "
        "démarrer et dont la cible SNMP n'est pas encore joignable — les flux "
        "arrivent bien sur le réseau, mais aucun n'atteindra ClickHouse tant "
        "que SNMP ne répond pas.",
        "Vérifier dans l'ordre : (1) l'agent SNMP écoute-t-il sur l'exportateur "
        "(port 161/udp) ; (2) la communauté configurée dans `outlet.yaml` est "
        "la bonne (variable SNMP_COMMUNITY du .env, jamais en clair dans le "
        "YAML) ; (3) aucun pare-feu ne bloque l'UDP 161 entre le collecteur et "
        "l'exportateur. Le disjoncteur se referme tout seul une fois SNMP "
        "joignable ; aucun redémarrage n'est nécessaire.",
    ),
    "cannot decode BMP header": (
        "Le routage BGP/BMP n'est pas configuré ou mal formé sur cet "
        "exportateur. Cela n'a aucun impact sur la collecte des flux NetFlow "
        "eux-mêmes : seul l'enrichissement par les routes BGP est affecté.",
        "Vérifier la configuration BMP de cet exportateur si l'enrichissement "
        "de routage (AS, préfixes) est nécessaire. Sinon, aucune action requise.",
    ),
}

_UNKNOWN_MOTIF_EXPLANATION = (
    "Motif non répertorié dans la base de connaissance de ce module. "
    "Le compteur brut ci-dessus est fiable (source Prometheus de l'outlet), "
    "mais aucune explication métier n'est disponible pour ce motif précis."
)
_UNKNOWN_MOTIF_REMEDIATION = (
    "Consulter les logs de l'outlet Akvorado pour ce motif avant toute action."
)


def compute_rejection_rate(rejected: int, forwarded: int) -> float:
    """Taux de rejet d'un exportateur : `rejected / (rejected + forwarded)`.

    Division par zéro gérée explicitement (aucun flux du tout) : taux nul,
    jamais d'exception.
    """
    total = rejected + forwarded
    if total <= 0:
        return 0.0
    return rejected / total


def _explain_motif(error: str) -> tuple[str, str]:
    """Explication + remédiation pour un motif de rejet.

    Ne jamais inventer une explication pour un motif inconnu : le fallback
    est honnête et signale explicitement l'absence de connaissance.
    """
    known = _KNOWN_MOTIFS.get(error)
    if known is not None:
        return known
    return _UNKNOWN_MOTIF_EXPLANATION, _UNKNOWN_MOTIF_REMEDIATION


def build_rejection_reasons(metrics: OutletMetrics) -> list[RejectionReason]:
    """Construit la liste des motifs de rejet, triée par criticité décroissante.

    Criticité = (taux de rejet de l'exportateur porteur du motif, count du
    motif) décroissants : un exportateur à 100% de rejet (cas .18) ressort
    systématiquement en tête, quel que soit son volume relatif face à
    d'autres motifs mineurs sur des exportateurs par ailleurs sains.
    """
    reasons: list[RejectionReason] = []

    for exporter, motifs in metrics.rejection_reasons.items():
        for error, count in motifs.items():
            explanation, remediation = _explain_motif(error)
            reasons.append(
                RejectionReason(
                    error=error,
                    exporter=exporter,
                    count=count,
                    explanation=explanation,
                    remediation=remediation,
                )
            )

    exporter_rates = {
        exporter: compute_rejection_rate(
            rejected=metrics.rejected_by_exporter.get(exporter, 0),
            forwarded=metrics.forwarded_by_exporter.get(exporter, 0),
        )
        for exporter in metrics.rejection_reasons
    }

    reasons.sort(
        key=lambda r: (exporter_rates.get(r.exporter, 0.0), r.count),
        reverse=True,
    )

    return reasons


def record_rejection_history(conn: sqlite3.Connection, reasons: list[RejectionReason]) -> None:
    """Persiste le compte courant de chaque (exportateur, motif) — un point de
    mesure pour le calcul de tendance ultérieur.

    Même contrat que `app.routers.db_health._record_history` : un échec
    d'écriture est journalisé mais jamais fatal pour la requête métier qui l'a
    déclenché — un historique de tendance manquant dégrade l'écran (tendance
    "unknown" au lieu de calculée) mais ne doit jamais faire échouer l'affichage
    des compteurs eux-mêmes.
    """
    try:
        conn.executemany(
            "INSERT INTO ingestion_rejection_history (exporter, error, count) VALUES (?, ?, ?)",
            [(r.exporter, r.error, r.count) for r in reasons],
        )
        conn.commit()
    except sqlite3.Error:
        log.error("ingestion: echec ecriture ingestion_rejection_history", exc_info=True)


def _load_comparison_counts(
    conn: sqlite3.Connection, window_seconds: int = TREND_WINDOW_SECONDS
) -> dict[tuple[str, str], int]:
    """Charge, pour chaque (exportateur, motif), le dernier compte connu
    ANTÉRIEUR à `window_seconds` secondes — le point de comparaison de la
    tendance.

    ZÉRO SILENCIEUX : un échec de lecture retourne un dict vide (journalisé) —
    `annotate_trend` traduit alors chaque motif en tendance "unknown", jamais
    en un delta calculé sur une base absente.
    """
    try:
        rows = conn.execute(
            """
            SELECT exporter, error, count
            FROM ingestion_rejection_history
            WHERE checked_at <= datetime('now', ?)
            AND id IN (
                SELECT MAX(id) FROM ingestion_rejection_history
                WHERE checked_at <= datetime('now', ?)
                GROUP BY exporter, error
            )
            """,
            (f"-{window_seconds} seconds", f"-{window_seconds} seconds"),
        ).fetchall()
    except sqlite3.Error:
        log.error("ingestion: echec lecture ingestion_rejection_history", exc_info=True)
        return {}
    return {(row[0], row[1]): row[2] for row in rows}


def annotate_trend(
    conn: sqlite3.Connection,
    reasons: list[RejectionReason],
    window_seconds: int = TREND_WINDOW_SECONDS,
) -> list[RejectionReason]:
    """Complète chaque `RejectionReason` avec sa tendance récente.

    Compare le compte COURANT (cumulatif depuis le démarrage du conteneur
    outlet) au dernier point connu antérieur à `window_seconds` — c'est ce
    delta, pas le cumul brut, qui distingue un incident ACTIF d'une séquelle
    FIGÉE (défaut mesuré 2026-08-09, voir docstring du module).

    N'appelle JAMAIS `record_rejection_history` elle-même : la lecture du
    point de comparaison doit se faire AVANT d'écrire le point courant, sinon
    le point qu'on vient d'écrire se comparerait à lui-même (delta toujours 0).
    L'appelant (le routeur) orchestre l'ordre : `annotate_trend` puis
    `record_rejection_history`.
    """
    comparison = _load_comparison_counts(conn, window_seconds)

    annotated: list[RejectionReason] = []
    for reason in reasons:
        previous_count = comparison.get((reason.exporter, reason.error))
        if previous_count is None:
            trend_state: TrendState = "unknown"
            trend_delta = None
        else:
            trend_delta = reason.count - previous_count
            trend_state = "rising" if trend_delta > 0 else "flat"
        annotated.append(
            reason.model_copy(update={"trend_delta": trend_delta, "trend_state": trend_state})
        )

    return annotated


# ---------------------------------------------------------------------------
# PURGE DES CUMULS FIGÉS (2026-08-10)
#
# DEMANDE : « il faut ajouter un bouton pour purger les metadata missing ».
#
# CE QU'ON NE PEUT PAS FAIRE, et pourquoi : Okvorado ne peut PAS remettre à
# zéro un compteur Prometheus. Ce n'est pas une limitation d'implémentation,
# c'est la définition même d'un compteur Prometheus — il est monotone croissant
# et n'est effacé que par le redémarrage du processus qui l'expose (ici
# l'outlet Akvorado, dont le redémarrage couperait l'ingestion : UDP ne
# retransmet pas, les flux émis pendant la coupure sont perdus pour toujours).
# Une "purge" qui redémarrerait l'outlet pour nettoyer un affichage serait
# disproportionnée — on détruirait de la donnée réelle pour effacer du bruit
# visuel.
#
# CE QU'ON FAIT À LA PLACE : un MASQUAGE côté Okvorado. On mémorise le cumul
# au moment de la purge (`baseline_count`) et l'écran n'affiche ensuite plus
# que ce qui s'ajoute AU-DESSUS de cette ligne. Le compteur Akvorado, lui,
# reste intact et exact — aucune donnée n'est modifiée chez Akvorado. L'écran
# le dit explicitement à l'exploitant (voir `ingestion.html`), qui ne doit
# jamais croire qu'on a effacé une mesure à la source.
#
# LES TROIS GARDE-FOUS ZÉRO SILENCIEUX (CLAUDE.md règle n°2) :
#   1. seul un motif dont la tendance est PROUVÉE figée ("flat") est masquable.
#      "rising" (ça grimpe encore) et "unknown" (aucun point de comparaison,
#      donc aucune preuve) sont REFUSÉS, avec un compte de refus distinct par
#      motif de refus — jamais un échec rendu comme un succès à 0 ;
#   2. un motif masqué qui REPART réapparaît AUTOMATIQUEMENT dès le premier
#      incrément au-dessus de sa ligne de base. Le masque ne peut donc pas
#      cacher une panne qui reprend ;
#   3. un compteur courant INFÉRIEUR à la ligne de base ne peut signifier
#      qu'une chose : l'outlet a redémarré et ses compteurs sont repartis de 0.
#      Le masque est alors PÉRIMÉ — supprimé, motif réaffiché avec son cumul
#      courant intégral. Jamais de delta négatif, jamais de masquage éternel.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PurgeOutcome:
    """Résultat d'une purge — un compte DISTINCT par issue, jamais un booléen.

    ZÉRO SILENCIEUX : « 0 purgé » ne dit pas POURQUOI. Un couple refusé parce
    qu'il grimpe encore (`refused_active`), refusé faute de point de
    comparaison (`refused_unknown`) ou simplement absent de la mesure courante
    (`not_found`) sont trois situations différentes, qui appellent trois
    messages différents à l'écran. Les agréger en un seul « rien fait »
    laisserait l'exploitant sans explication.
    """

    purged: int = 0
    refused_active: int = 0
    refused_unknown: int = 0
    not_found: int = 0
    error: str | None = None

    @property
    def refused_total(self) -> int:
        """Total des refus, tous motifs confondus — pour l'affichage résumé."""
        return self.refused_active + self.refused_unknown

    def as_payload(self) -> dict[str, Any]:
        """Représentation JSON/gabarit. `status` vaut 'error' si la
        persistance a échoué : un échec d'écriture ne doit JAMAIS se présenter
        comme un succès qui n'aurait rien purgé."""
        return {
            "status": "error" if self.error else "ok",
            "purged": self.purged,
            "refused_active": self.refused_active,
            "refused_unknown": self.refused_unknown,
            "not_found": self.not_found,
            "error": self.error,
        }


def _upsert_masks(
    conn: sqlite3.Connection, entries: list[tuple[str, str, int]], actor: str
) -> str | None:
    """Écrit (ou met à jour) les lignes de base. Retourne un message d'erreur
    ou None.

    `ON CONFLICT ... DO UPDATE` : purger deux fois le même couple REMPLACE sa
    ligne de base (le motif avait repris puis s'est re-figé plus haut), jamais
    ne la duplique — la clé primaire (exporter, error) l'interdirait de toute
    façon, mais un simple INSERT lèverait alors une IntegrityError sur un geste
    parfaitement légitime.
    """
    if not entries:
        return None
    try:
        conn.executemany(
            """
            INSERT INTO ingestion_rejection_mask
                (exporter, error, baseline_count, masked_at, masked_by)
            VALUES (?, ?, ?, datetime('now'), ?)
            ON CONFLICT (exporter, error) DO UPDATE SET
                baseline_count = excluded.baseline_count,
                masked_at      = excluded.masked_at,
                masked_by      = excluded.masked_by
            """,
            [(exporter, error, count, actor) for exporter, error, count in entries],
        )
        conn.commit()
    except sqlite3.Error as exc:
        log.error("ingestion: echec ecriture ingestion_rejection_mask", exc_info=True)
        return f"Échec d'enregistrement du masquage : {exc}"
    return None


def _classify_for_purge(reason: RejectionReason) -> str:
    """Décide si un motif est masquable. Retourne 'flat', 'active' ou 'unknown'.

    C'est ICI que se joue la règle du zéro silencieux : la purge nettoie du
    BRUIT HISTORIQUE, elle ne doit jamais faire disparaître une panne en cours.
    Un motif qui grimpe encore n'est pas du bruit ; un motif sans point de
    comparaison n'est pas PROUVÉ figé — dans les deux cas on refuse plutôt que
    de masquer sur une supposition.
    """
    if reason.trend_state == "rising":
        return "active"
    if reason.trend_state == "flat":
        return "flat"
    return "unknown"


def purge_rejection(
    conn: sqlite3.Connection,
    reasons: list[RejectionReason],
    exporter: str,
    error: str,
    actor: str = "anonymous",
) -> PurgeOutcome:
    """Masque UN couple (exportateur, motif), s'il est prouvé figé.

    `reasons` doit être la liste ANNOTÉE (sortie de `annotate_trend`) de la
    mesure courante : c'est elle qui porte à la fois le cumul à mémoriser
    comme ligne de base et la tendance qui autorise — ou refuse — le masquage.
    Purger depuis une liste non annotée classerait tout en "unknown" et
    refuserait tout, ce qui est le comportement sûr par défaut.
    """
    target = next((r for r in reasons if r.exporter == exporter and r.error == error), None)
    if target is None:
        log.info(
            "ingestion: purge refusee, couple absent de la mesure courante",
            extra={"exporter": exporter, "error": error},
        )
        return PurgeOutcome(not_found=1)

    verdict = _classify_for_purge(target)
    if verdict == "active":
        log.info(
            "ingestion: purge refusee, le compteur grimpe encore",
            extra={"exporter": exporter, "error": error, "trend_delta": target.trend_delta},
        )
        return PurgeOutcome(refused_active=1)
    if verdict == "unknown":
        log.info(
            "ingestion: purge refusee, tendance inconnue (aucun point de comparaison)",
            extra={"exporter": exporter, "error": error},
        )
        return PurgeOutcome(refused_unknown=1)

    write_error = _upsert_masks(conn, [(exporter, error, target.count)], actor)
    if write_error:
        return PurgeOutcome(error=write_error)
    return PurgeOutcome(purged=1)


def purge_all_flat_rejections(
    conn: sqlite3.Connection,
    reasons: list[RejectionReason],
    actor: str = "anonymous",
) -> PurgeOutcome:
    """Masque d'un coup TOUS les motifs prouvés figés — le geste qui passe à
    l'échelle (cible produit : 350 routeurs, où purger ligne à ligne ne tient
    pas).

    Reste strictement SÉLECTIF : les motifs "rising" et "unknown" sont
    comptés en refus et laissés VISIBLES. Un « purger tout » qui balaierait
    aussi les problèmes actifs serait précisément la régression que la règle
    du zéro silencieux interdit.
    """
    to_mask: list[tuple[str, str, int]] = []
    refused_active = 0
    refused_unknown = 0

    for reason in reasons:
        verdict = _classify_for_purge(reason)
        if verdict == "flat":
            to_mask.append((reason.exporter, reason.error, reason.count))
        elif verdict == "active":
            refused_active += 1
        else:
            refused_unknown += 1

    write_error = _upsert_masks(conn, to_mask, actor)
    if write_error:
        return PurgeOutcome(
            refused_active=refused_active,
            refused_unknown=refused_unknown,
            error=write_error,
        )

    return PurgeOutcome(
        purged=len(to_mask),
        refused_active=refused_active,
        refused_unknown=refused_unknown,
    )


def _load_masks(conn: sqlite3.Connection) -> dict[tuple[str, str], int] | None:
    """Lignes de base indexées par (exportateur, motif).

    Retourne None — PAS un dict vide — si la lecture échoue. Les deux cas sont
    différents et l'appelant doit pouvoir les distinguer : « aucun masque
    enregistré » (dict vide, on masque donc rien, c'est juste) contre « on ne
    sait pas ce qui est masqué » (échec, on affiche TOUT plutôt que de risquer
    de cacher un problème). Rendre `{}` sur erreur serait un zéro silencieux.
    """
    try:
        rows = conn.execute(
            "SELECT exporter, error, baseline_count FROM ingestion_rejection_mask"
        ).fetchall()
    except sqlite3.Error:
        log.error("ingestion: echec lecture ingestion_rejection_mask", exc_info=True)
        return None
    return {(row[0], row[1]): row[2] for row in rows}


def _drop_masks(conn: sqlite3.Connection, keys: list[tuple[str, str]]) -> None:
    """Supprime des masques devenus PÉRIMÉS (outlet redémarré).

    Échec journalisé, jamais fatal : la ligne concernée est de toute façon
    déjà réaffichée par `apply_rejection_masks` pour l'appel en cours — un
    masque périmé qui survit en base sera simplement re-détecté au prochain
    appel. Faire échouer l'affichage des compteurs pour un ménage de table
    serait disproportionné.
    """
    if not keys:
        return
    try:
        conn.executemany(
            "DELETE FROM ingestion_rejection_mask WHERE exporter = ? AND error = ?", keys
        )
        conn.commit()
    except sqlite3.Error:
        log.error("ingestion: echec suppression masques perimes", exc_info=True)


def apply_rejection_masks(
    conn: sqlite3.Connection, reasons: list[RejectionReason]
) -> tuple[list[RejectionReason], int]:
    """Filtre les motifs masqués. Retourne `(visibles, nombre_masqué)`.

    Les trois cas, pour un motif portant une ligne de base `B` et un cumul
    courant `C` :

    - `C == B` : rien n'a bougé depuis la purge — le motif reste MASQUÉ. C'est
      le cas nominal, celui qui nettoie l'écran des exportateurs fantômes.
    - `C > B`  : le problème a REPRIS. Le motif RÉAPPARAÎT, mais avec `count`
      ramené au DELTA (`C - B`) et `masked_baseline` renseigné pour que
      l'écran puisse dire d'où vient ce chiffre. Le masque est CONSERVÉ : la
      ligne de base reste le référentiel tant que l'exploitant ne re-purge pas.
    - `C < B`  : impossible pour un compteur monotone — sauf redémarrage de
      l'outlet, qui a remis ses compteurs à 0. Le masque est PÉRIMÉ : on le
      supprime et on réaffiche le cumul courant INTÉGRAL. Jamais de delta
      négatif (`C - B` serait négatif), jamais de masquage éternel (sans cette
      règle, le motif resterait invisible jusqu'à ce que le nouveau cumul
      dépasse l'ancien — potentiellement des jours de panne masquée).

    Si la lecture des masques échoue, TOUT est affiché et le compte masqué vaut
    0 : en cas de doute on montre plus, jamais moins.
    """
    masks = _load_masks(conn)
    if masks is None:
        return list(reasons), 0
    if not masks:
        return list(reasons), 0

    visible: list[RejectionReason] = []
    hidden = 0
    stale_keys: list[tuple[str, str]] = []

    for reason in reasons:
        baseline = masks.get((reason.exporter, reason.error))
        if baseline is None:
            visible.append(reason)
            continue

        if reason.count < baseline:
            # Outlet redémarré : la ligne de base ne veut plus rien dire.
            stale_keys.append((reason.exporter, reason.error))
            log.info(
                "ingestion: masque perime (compteur < ligne de base, outlet redemarre)",
                extra={
                    "exporter": reason.exporter,
                    "error": reason.error,
                    "baseline": baseline,
                    "count": reason.count,
                },
            )
            visible.append(reason)
            continue

        if reason.count == baseline:
            hidden += 1
            continue

        visible.append(
            reason.model_copy(
                update={"count": reason.count - baseline, "masked_baseline": baseline}
            )
        )

    _drop_masks(conn, stale_keys)
    return visible, hidden


def list_rejection_masks(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Liste des masques actifs, pour que l'écran dise CE QUI est masqué.

    Un masquage qu'on ne peut pas inspecter serait lui-même un zéro silencieux :
    l'exploitant doit pouvoir voir quelles lignes rouges ont été escamotées,
    par qui et depuis quand, et les rétablir.

    Échec de lecture : liste vide + log. L'écran affiche par ailleurs le
    compte réel de lignes masquées calculé par `apply_rejection_masks`, qui
    reste la mesure de référence.
    """
    try:
        rows = conn.execute(
            """
            SELECT exporter, error, baseline_count, masked_at, masked_by
            FROM ingestion_rejection_mask
            ORDER BY masked_at DESC, exporter
            """
        ).fetchall()
    except sqlite3.Error:
        log.error("ingestion: echec lecture liste des masques", exc_info=True)
        return []
    return [
        {
            "exporter": row[0],
            "error": row[1],
            "baseline_count": row[2],
            "masked_at": row[3],
            "masked_by": row[4],
        }
        for row in rows
    ]


def unmask_all_rejections(conn: sqlite3.Connection) -> int:
    """Annule TOUS les masquages. Retourne le nombre de lignes rétablies.

    RÉVERSIBILITÉ : après cet appel, chaque motif retrouve son cumul BRUT à
    l'écran (aucune ligne de base ne subsiste pour en soustraire quoi que ce
    soit). Une purge irréversible serait inacceptable — l'exploitant doit
    toujours pouvoir revenir à la vue non filtrée de ce que rapporte Akvorado.
    """
    try:
        cursor = conn.execute("DELETE FROM ingestion_rejection_mask")
        conn.commit()
    except sqlite3.Error:
        log.error("ingestion: echec annulation des masques", exc_info=True)
        return 0
    return int(cursor.rowcount or 0)


def unmask_one_rejection(conn: sqlite3.Connection, exporter: str, error: str) -> int:
    """Annule le masquage d'UN couple. Retourne le nombre de lignes rétablies
    (0 si ce couple n'était pas masqué — pas une erreur, juste un no-op)."""
    try:
        cursor = conn.execute(
            "DELETE FROM ingestion_rejection_mask WHERE exporter = ? AND error = ?",
            (exporter, error),
        )
        conn.commit()
    except sqlite3.Error:
        log.error("ingestion: echec annulation d'un masque", exc_info=True)
        return 0
    return int(cursor.rowcount or 0)
