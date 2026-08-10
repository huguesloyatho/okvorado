"""Garde-fou : un encart `.notice` ne doit pas hacher ses propres phrases.

DÉFAUT MESURÉ À L'ÉCRAN (2026-08-07), et invisible partout ailleurs.

La règle `.notice strong { display: block }` servait à détacher le TITRE d'un
encart (« Ce que révèle ce classement : »). Écrite sans restriction, elle
s'appliquait à TOUS les `<strong>` descendants — y compris ceux qui mettent un
mot en valeur AU MILIEU d'une phrase.

Rendu réel sur la vue Convergence : le paragraphe explicatif, cinq `<strong>`
dans une phrase continue, s'affichait haché sur neuf lignes :

    Le tableau classe par nombre de
    sources internes distinctes
    , décroissant, et ne retient que les
    destinations internes

Pourquoi aucun test ne pouvait l'attraper : le HTML est PARFAITEMENT correct.
Un test qui lit le DOM voit une phrase bien formée. Le défaut ne vit que dans la
mise en forme — il faut regarder l'écran. C'est le même angle mort que les
gestionnaires bloqués par la CSP et l'ordre de chargement d'htmx : le gabarit
est juste, le rendu est faux.

D'où un contrôle sur la RÈGLE CSS elle-même, seule trace testable du défaut.
"""

from __future__ import annotations

import re
from pathlib import Path

STYLE_CSS = Path(__file__).resolve().parent.parent / "app" / "static" / "style.css"


def _regles_notice_strong() -> list[str]:
    """Sélecteurs de `style.css` qui mettent un `<strong>` d'encart en bloc."""
    contenu = STYLE_CSS.read_text(encoding="utf-8")
    # On retire les commentaires : ce fichier DOCUMENTE le défaut, et un test qui
    # lit le fichier brut échouerait sur sa propre explication. Piège déjà vécu
    # quatre fois dans ce projet (couleurs en dur, variables CSS, SamplingRate).
    sans_commentaires = re.sub(r"/\*.*?\*/", "", contenu, flags=re.DOTALL)

    regles: list[str] = []
    for selecteur, corps in re.findall(r"([^{}]+)\{([^}]*)\}", sans_commentaires):
        if "notice" in selecteur and "strong" in selecteur and "display" in corps:
            if re.search(r"display\s*:\s*block", corps):
                regles.append(selecteur.strip())
    return regles


def test_le_titre_d_encart_en_bloc_ne_touche_que_le_premier_strong() -> None:
    """Une emphase en cours de phrase doit rester DANS la phrase."""
    trop_larges = [
        regle
        for regle in _regles_notice_strong()
        if "first-child" not in regle and "first-of-type" not in regle
    ]

    assert not trop_larges, (
        "Ces règles mettent en bloc TOUT `<strong>` d'un encart, pas seulement "
        f"son titre : {trop_larges}. Une phrase contenant de l'emphase se rendra "
        "hachée sur autant de lignes qu'elle a de `<strong>` — le HTML restera "
        "correct, donc aucun test de DOM ne le verra. Restreins au premier "
        "enfant (`.notice > strong:first-child`)."
    )


def test_la_regle_de_titre_existe_toujours() -> None:
    """Miroir : supprimer la règle ferait passer le test précédent au vert.

    Le titre d'un encart DOIT rester détaché — c'est ce qui le distingue du
    corps du texte. Le test précédent borne la règle ; celui-ci la protège.
    """
    assert _regles_notice_strong(), (
        "plus aucune règle ne détache le titre d'un encart : les encarts "
        "perdraient la distinction visuelle titre/corps"
    )
