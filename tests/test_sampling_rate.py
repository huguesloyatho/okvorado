"""Garde-fou : tout volume agrégé doit être multiplié par `SamplingRate`.

DÉFAUT MESURÉ (2026-08-07), et INVISIBLE dans le homelab — c'est ce qui le rend
dangereux.

NetFlow échantillonné ne transporte qu'une FRACTION des flux : un routeur en
1:1000 n'émet qu'un flux sur mille, et la colonne `SamplingRate` porte le
facteur à réappliquer. Sommer `Bytes` sans le multiplier sous-estime le volume
d'autant.

Pourquoi personne ne l'aurait vu ici : les exportateurs logiciels du homelab
(softflowd) émettent TOUS les flux, donc `SamplingRate = 1` — mesuré le
2026-08-07 sur 510 898 flux, tous à 1. `Bytes * 1 == Bytes` : le calcul faux
et le calcul juste donnent le MÊME résultat.

L'utilisateur déploie ce stack en entreprise, sur des équipements qui
échantillonnent. Là, l'écart serait d'un facteur 1000 — sans erreur, sans
avertissement, avec des graphes parfaitement cohérents entre eux et tous faux.

Aucun test fonctionnel ne peut attraper ça : il faudrait des données
échantillonnées, que le homelab ne produit pas. D'où un contrôle sur le SQL
lui-même.
"""

from __future__ import annotations

import re
from pathlib import Path

APP_DIR = Path(__file__).resolve().parent.parent / "app"

# Colonnes de MESURE : leur somme représente un volume réel, donc doit être
# ramenée à l'échelle par le taux d'échantillonnage.
COLONNES_A_ECHELLE = ("Bytes", "Packets")

# `count()` compte des FLUX OBSERVÉS, pas un volume : le multiplier n'aurait
# aucun sens. C'est une mesure du travail du collecteur, pas du trafic.


def _fichiers_sql() -> list[Path]:
    """Modules portant du SQL d'agrégation."""
    return sorted(
        p
        for p in (*(APP_DIR / "routers").glob("*.py"), *(APP_DIR / "clients").glob("*.py"))
        if "sum(" in p.read_text(encoding="utf-8")
    )


def _sans_commentaires(source: str) -> str:
    """Retire DOCSTRINGS et commentaires, en préservant le SQL.

    Un test qui lit le fichier BRUT prend pour du SQL la mention `sum(Bytes)`
    d'une docstring qui décrit la vue. C'est arrivé ici même — et trois fois
    ailleurs dans ce projet (couleurs en dur, variables CSS, gestionnaires
    inline) : le garde-fou échoue sur la documentation du défaut qu'il protège.

    ⚠️ Retirer TOUTE chaîne triple effacerait aussi le SQL, qui vit lui-même
    dans des `\"\"\"...\"\"\"` — le premier essai comptait « 0 agrégation » sur
    un fichier qui en contient dix. On ne retire donc que les chaînes triples
    en POSITION de docstring : premières de module, ou suivant un `def`/`class`.
    Le SQL, lui, est toujours affecté à une variable ou retourné.
    """
    nettoye = re.sub(r"^\s*(?:r|f|rf|fr)?\"\"\".*?\"\"\"", "", source, flags=re.DOTALL)
    nettoye = re.sub(
        r"(\n(?:async\s+)?(?:def|class)\s+[^\n]*:\n\s*)(?:r|f|rf|fr)?\"\"\".*?\"\"\"",
        r"\1",
        nettoye,
        flags=re.DOTALL,
    )
    return re.sub(r"#[^\n]*", "", nettoye)


def test_le_homelab_ne_peut_pas_reveler_ce_defaut() -> None:
    """La prémisse, énoncée pour que le test se comprenne seul.

    Ce test ne mesure rien : il DOCUMENTE pourquoi les six autres existent.
    Avec `SamplingRate = 1`, la multiplication est neutre et aucun écart
    n'apparaît à l'écran. Le contrôle doit donc porter sur le SQL.
    """
    assert 1 * 1000 == 1000, "avec un taux de 1, le facteur est neutre — d'où l'angle mort"


def test_toute_somme_de_volume_applique_le_taux_d_echantillonnage() -> None:
    """`sum(Bytes)` nu est un volume faux dès que l'exportateur échantillonne."""
    offenders: list[str] = []

    for fichier in _fichiers_sql():
        contenu = _sans_commentaires(fichier.read_text(encoding="utf-8"))
        for colonne in COLONNES_A_ECHELLE:
            # `sum(Bytes)` ou `sum( Bytes )` — sans multiplication.
            for match in re.finditer(rf"sum\(\s*{colonne}\s*\)", contenu):
                ligne = contenu[: match.start()].count("\n") + 1
                offenders.append(f"{fichier.name}:{ligne} -> {match.group(0)}")

    assert not offenders, (
        "Ces agrégations somment une colonne de volume SANS la multiplier par "
        "`SamplingRate` — le volume affiché serait divisé par le taux "
        "d'échantillonnage de l'exportateur, silencieusement :\n  "
        + "\n  ".join(offenders)
        + "\nÉcris `sum(Bytes * SamplingRate)`."
    )


def test_les_agregations_existantes_appliquent_bien_le_taux() -> None:
    """Miroir du précédent : la forme correcte doit être présente.

    Sans cette assertion, supprimer purement et simplement toutes les
    agrégations ferait passer le test au vert.
    """
    total = sum(
        len(
            re.findall(
                r"sum\(\s*\w+\s*\*\s*SamplingRate\s*\)",
                _sans_commentaires(f.read_text(encoding="utf-8")),
            )
        )
        for f in _fichiers_sql()
    )
    assert total >= 8, (
        f"seulement {total} agrégation(s) appliquent le taux d'échantillonnage — "
        "l'inventaire du 2026-08-07 en comptait 10 (9 dans views.py, 1 dans "
        "clickhouse.py). Une disparition signale une régression."
    )


def test_le_comptage_de_flux_n_est_pas_mis_a_l_echelle() -> None:
    """`count()` compte des flux OBSERVÉS, pas du trafic.

    Le multiplier serait le défaut symétrique : on annoncerait avoir vu mille
    fois plus de flux qu'on n'en a réellement reçus. Le nombre de flux mesure
    le travail du collecteur ; le volume mesure le trafic. Deux grandeurs
    différentes, deux traitements différents.
    """
    for fichier in _fichiers_sql():
        contenu = _sans_commentaires(fichier.read_text(encoding="utf-8"))
        assert not re.search(r"count\(\)\s*\*\s*SamplingRate", contenu), (
            f"{fichier.name}: le nombre de flux ne doit PAS être mis à l'échelle"
        )
