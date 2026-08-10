"""Garde-fou : aucun gestionnaire d'événement inline, la CSP les bloque.

DEUX DÉFAUTS MESURÉS AU NAVIGATEUR (2026-08-06), invisibles autrement.

L'application sert `script-src 'self'` SANS `unsafe-inline` : un attribut
`onchange=` / `onclick=` posé dans un template est BLOQUÉ par le navigateur,
sans erreur visible à l'écran. Le contrôle ne « casse » pas — il ne fait rien.

1. Formulaire « Déclarer une interface » : un `onchange=` réécrivait `hx-post`
   selon l'exportateur choisi. Mesuré sur les 12 exportateurs de production —
   on choisit le sixième, la cible reste sur le troisième. **L'interface aurait
   été déclarée sur une machine que l'utilisateur n'a pas choisie**, avec un
   « changement mis en attente » affiché en succès.

2. Sélecteur de fenêtre des vues métier : `onchange="this.form.submit()"`.
   Changer la fenêtre de 1h à 6h ne soumettait rien, l'URL restait identique,
   et aucun bouton ne permettait de valider.

Les deux ont le même profil que le reste de cette session : la logique était
juste, l'utilisateur ne voyait rien.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "app" / "templates"
MAIN_PY = Path(__file__).resolve().parent.parent / "app" / "main.py"

# Attributs de gestionnaire d'événement HTML. `hx-on::` est EXCLU : c'est htmx
# qui l'évalue, pas le navigateur, donc la CSP ne s'y applique pas.
INLINE_HANDLER_RE = re.compile(r'\bon[a-z]+\s*=\s*["\']', re.IGNORECASE)


def _strip_jinja_comments(html: str) -> str:
    """Retire les commentaires Jinja avant analyse.

    Ces commentaires CITENT volontairement `onchange=` pour documenter le
    piège. Un test lisant le fichier brut échouerait sur la documentation du
    défaut qu'il protège — faux positif déjà rencontré deux fois dans ce
    projet (couleurs en dur, variables CSS).
    """
    return re.sub(r"\{#.*?#\}", "", html, flags=re.DOTALL)


def test_la_csp_interdit_bien_les_scripts_inline() -> None:
    """La prémisse du défaut, vérifiée plutôt que supposée."""
    source = MAIN_PY.read_text(encoding="utf-8")
    csp = re.search(r'"Content-Security-Policy"\]\s*=\s*\((.*?)\)', source, re.DOTALL)

    assert csp, "en-tête Content-Security-Policy introuvable"
    directive = csp.group(1)
    assert "script-src 'self'" in directive
    assert "unsafe-inline" not in directive.split("style-src")[0], (
        "si script-src autorisait unsafe-inline, ce garde-fou serait sans objet"
    )


@pytest.mark.parametrize(
    "template_name",
    sorted(p.name for p in TEMPLATES_DIR.glob("*.html")),
)
def test_aucun_gestionnaire_inline_dans_les_templates(template_name: str) -> None:
    """Un `onchange=` est ignoré en SILENCE : le contrôle change d'apparence
    sans produire aucun effet."""
    html = _strip_jinja_comments((TEMPLATES_DIR / template_name).read_text(encoding="utf-8"))

    offenders = []
    for match in INLINE_HANDLER_RE.finditer(html):
        fragment = html[max(0, match.start() - 60) : match.end() + 20]
        # `hx-on::after-request` est évalué par htmx lui-même, pas par le
        # navigateur : la CSP ne s'y applique pas.
        if "hx-on" in fragment:
            continue
        line = html[: match.start()].count("\n") + 1
        offenders.append(f"{template_name}:{line} -> {match.group(0)!r}")

    assert not offenders, (
        "Gestionnaires d'événement inline détectés — la CSP de l'application "
        "les BLOQUE, le contrôle sera inerte sans le moindre avertissement :\n  "
        + "\n  ".join(offenders)
        + "\nDéplace le câblage dans un fichier de app/static/, comme "
        "form-targets.js."
    )


def test_le_selecteur_de_fenetre_a_un_bouton_de_repli() -> None:
    """Sans JS, la fenêtre doit rester changeable à la souris.

    Un `<select>` qui se soumet automatiquement N'A AUCUN moyen de validation
    quand le script ne s'exécute pas — c'était le cas mesuré. Le bouton est
    donc rendu par le serveur et MASQUÉ par le script, jamais l'inverse :
    posé masqué, il resterait invisible le seul jour où il sert.
    """
    html = (TEMPLATES_DIR / "views.html").read_text(encoding="utf-8")

    assert "data-autosubmit" in html, "le formulaire de fenêtre n'est pas déclaré auto-soumis"
    assert "autosubmit-fallback" in html, (
        "aucun bouton de repli : sans JS, la fenêtre serait impossible à changer"
    )


def test_le_formulaire_d_interface_declare_sa_cible_en_donnees() -> None:
    """La cible du POST doit être décrite en `data-*`, pas en JS inline."""
    html = (TEMPLATES_DIR / "config.html").read_text(encoding="utf-8")

    assert "data-target-template=" in html, (
        "la cible dynamique n'est plus câblée : le formulaire posterait "
        "toujours vers le premier exportateur, quel que soit le choix"
    )
    assert "data-target-source=" in html


def test_le_cablage_vit_dans_un_fichier_statique_et_est_charge() -> None:
    """Le script doit exister ET être réellement chargé.

    Vérifié sur la BALISE `<script src=...>` et non sur une simple occurrence
    du nom de fichier : mes propres commentaires le mentionnent, et un premier
    contrôle les avait pris pour un chargement effectif — le script n'était en
    réalité chargé nulle part.
    """
    script = TEMPLATES_DIR.parent / "static" / "form-targets.js"
    assert script.exists(), "app/static/form-targets.js absent"

    # Reconnaît la forme brute `src="/static/form-targets.js` ET la forme
    # passée au filtre Jinja `prefixed` (app servie derrière le proxy
    # Grafana) `src="{{ '/static/form-targets.js?v=' | prefixed }}`.
    balise = re.compile(
        r"""<script[^>]+src="(?:/static/form-targets\.js|\{\{\s*'/static/form-targets\.js)"""
    )
    for nom in ("config.html", "views.html"):
        html = (TEMPLATES_DIR / nom).read_text(encoding="utf-8")
        assert balise.search(html), (
            f"{nom} ne charge pas form-targets.js par une vraie balise <script> "
            "(une mention en commentaire ne charge rien)"
        )
