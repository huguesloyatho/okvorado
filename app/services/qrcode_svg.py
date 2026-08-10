"""Rendu d'un QR code en SVG inline, généré LOCALEMENT — aucun appel réseau.

CONTRAINTE DE PROJET (CLAUDE.md) : CSP `script-src 'self'` sans `unsafe-inline`
ni `unsafe-eval`, aucun script depuis un CDN. Un QR code affiché depuis un
service tiers (`api.qrserver.com` et consorts, le réflexe le plus courant)
violerait cette CSP (`img-src` n'autorise que `'self' data:`) ET introduirait
une dépendance réseau pour une app qui doit fonctionner sur une machine
d'entreprise sans sortie Internet garantie.

DÉPENDANCE `qrcode` (pyproject.toml) : seule addition du lot d'authentification
au-delà de la stdlib + `cryptography` déjà présente. Encoder un QR code
correctement (correction d'erreur Reed-Solomon, placement de la matrice,
sélection du masque optimal) à la main serait un projet en soi et une source
de bugs silencieux (un QR mal formé ne se lit simplement pas — pire cas
possible ici : verrouillage de l'exploitant hors de son propre compte).
`qrcode` est pure Python, ne dépend pas de PIL quand on utilise
`SvgPathImage` (vérifié : aucun import d'image bitmap dans ce chemin), et son
usage ici se limite à ENCODER une chaîne locale — zéro risque réseau/CDN.
"""

from __future__ import annotations

import io

import qrcode
import qrcode.image.svg


def render_qr_svg(data: str) -> str:
    """Encode `data` (l'URI `otpauth://...`) en SVG, prêt à insérer inline.

    `SvgPathImage` produit un unique `<path>` (pas de grille de `<rect>`) :
    plus compact, et surtout AUCUNE dépendance à PIL/Pillow (qui serait
    nécessaire pour les factories image bitmap de la même bibliothèque).
    """
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage)
    buffer = io.BytesIO()
    img.save(buffer)
    return buffer.getvalue().decode("utf-8")
