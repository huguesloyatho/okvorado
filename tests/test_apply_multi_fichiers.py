"""Garde-fou : « Appliquer » doit atteindre les QUATRE fichiers Akvorado.

DÉFAUT MESURÉ (2026-08-07), et il rendait la partie management inopérante sans
la moindre erreur.

La route `/config/apply` passait à `apply_pending_changes` le seul chemin
d'`outlet.yaml`. Cette fonction accepte `str | dict` : un `str` active son
raccourci historique, interprété comme `{"outlet.yaml": <path>}` SEUL.

Conséquence : un changement visant une section d'un AUTRE fichier n'avait aucune
cible. Constaté en activant la colonne QoS depuis l'écran — changement mis en
file, bouton « Appliquer » cliqué, rapport affiché… et `akvorado.yaml` INCHANGÉ
(hash identique à la baseline), orchestrateur jamais redémarré. Un succès
apparent qui n'écrivait rien.

NEUF sections sur onze vivent hors d'`outlet.yaml` : elles étaient toutes
concernées.
"""

from __future__ import annotations

from app.services.config_sections import SECTIONS

# Nom logique -> fichier, tel que le catalogue le déclare.
FICHIERS_ATTENDUS = {"outlet.yaml", "akvorado.yaml", "console.yaml", "inlet.yaml"}


def test_la_map_couvre_tous_les_fichiers_du_catalogue() -> None:
    """Aucune section ne doit viser un fichier absent de la map.

    Le contrôle part du CATALOGUE — la source réelle — et non d'une liste
    tenue à la main qui dériverait à la première section ajoutée.
    """
    from app.routers.config import get_config_files

    fichiers_du_catalogue = {section.file for section in SECTIONS.values()}
    map_fournie = get_config_files("/config/outlet.yaml")

    manquants = sorted(fichiers_du_catalogue - set(map_fournie))
    assert not manquants, (
        f"Ces fichiers sont visés par une section mais absents de la map "
        f"passée à « Appliquer » : {manquants}. Les changements les ciblant "
        "seraient mis en file, rapportés en succès, et JAMAIS écrits."
    )


def test_les_chemins_derivent_du_repertoire_d_outlet() -> None:
    """Les 4 fichiers sont voisins sur disque, comme le catalogue le suppose."""
    from app.routers.config import get_config_files

    map_fournie = get_config_files("/data/akvorado/config/outlet.yaml")

    assert map_fournie["outlet.yaml"] == "/data/akvorado/config/outlet.yaml"
    assert map_fournie["akvorado.yaml"] == "/data/akvorado/config/akvorado.yaml"
    assert map_fournie["console.yaml"] == "/data/akvorado/config/console.yaml"
    assert map_fournie["inlet.yaml"] == "/data/akvorado/config/inlet.yaml"


def test_la_route_apply_consomme_la_map_pas_un_chemin_seul() -> None:
    """Un `str` réactiverait le raccourci historique, donc le défaut.

    Le contrôle porte sur la SIGNATURE : c'est le type du paramètre qui décide
    si `apply_pending_changes` voit un fichier ou quatre.
    """
    import inspect

    from app.routers.config import apply_config_changes

    signature = inspect.signature(apply_config_changes)
    parametres = signature.parameters

    assert "config_files" in parametres, (
        "la route doit recevoir la MAP des 4 fichiers ; un `config_path` seul "
        "n'atteindrait qu'outlet.yaml"
    )
    assert "config_path" not in parametres, (
        "un `config_path` réactiverait le raccourci historique de "
        "`apply_pending_changes`, donc le défaut du 2026-08-07"
    )
    # `from __future__ import annotations` rend les annotations sous forme de
    # CHAÎNES : comparer à l'objet `ConfigFiles` échouerait toujours. On
    # compare donc le nom, qui est ce que le fichier déclare réellement.
    assert parametres["config_files"].annotation == "ConfigFiles"


def test_le_compte_de_sections_hors_outlet_est_bien_majoritaire() -> None:
    """Mesure de l'enjeu, pour que le test se comprenne seul.

    Si un jour toutes les sections revenaient dans `outlet.yaml`, ce test
    échouerait — et ce serait le signal qu'il faut relire cette famille de
    garde-fous, pas les supprimer.
    """
    hors_outlet = [k for k, s in SECTIONS.items() if s.file != "outlet.yaml"]

    assert len(hors_outlet) >= 5, (
        f"seulement {len(hors_outlet)} section(s) hors outlet.yaml : "
        "l'inventaire du 2026-08-07 en comptait 6 sur 11"
    )
