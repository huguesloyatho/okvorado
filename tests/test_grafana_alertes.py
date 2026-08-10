"""Garde-fous des alertes Grafana provisionnées (`stack/grafana/provisioning/alerting/`).

CE QUE CE LOT RÉSOUT (voir prompt de la tâche) : le stack n'avait AUCUNE
alerte — le widget « Recent Alarms » de NetFlow Analyzer (capture
`reference/manageengine/01-dashboard-traffic-summary.png`) n'avait aucun
équivalent, et un log de Grafana montrait explicitement qu'il cherchait un
répertoire `provisioning/alerting` introuvable :
    logger=provisioning.alerting level=error msg="can't read alerting
    provisioning files from directory"

Trois règles livrées, chacune en `.yaml.template` (jamais en `.yaml` versionné
en dur) : Grafana ne résout AUCUNE substitution `${VAR}` dans son propre
provisioning — mesuré 2026-08-08 sur ce projet (`defaults.ini` ne porte aucun
réglage `expand_env`, `docker exec stack-grafana-1 printenv` ne montre que les
`GF_*` explicitement passées par le compose). Le service `config-generator`
(déjà responsable de `outlet.yaml`) résout ces gabarits par `sed` au
démarrage, AVANT que Grafana ne lise son dossier de provisioning — voir
`stack/config-generator/generate-config.sh` et
`stack/grafana/provisioning/alerting/README.md`.

Ces tests ne rejouent PAS les requêtes contre un vrai ClickHouse (aucune base
disponible en CI) — les trois requêtes candidates ont été exécutées et
validées à la main contre le VRAI ClickHouse de qualification (2026-08-08,
stack-clickhouse-1, 192.0.2.7) avant d'être commises ici. Ils vérifient le
GABARIT tel qu'il sera résolu, à la manière de `tests/test_grafana_dashboards.py`
et `tests/test_stack_portable.py` pour les autres YAML de ce projet.

⚠️ Piège vécu 10 fois sur ce projet (rappelé dans le prompt de cette tâche) :
un test qui grep un motif interdit échoue sur sa PROPRE documentation. Les
recherches de motifs interdits retirent donc les commentaires (`#` YAML) et
opèrent sur le SQL extrait, jamais sur le texte brut du fichier — même
précaution que `_sans_commentaires_sql` / `_sans_commentaires_yaml` ailleurs
dans ce projet.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import pytest
import yaml

ALERTING_DIR = (
    Path(__file__).resolve().parent.parent / "stack" / "grafana" / "provisioning" / "alerting"
)
GENERATOR_SCRIPT = (
    Path(__file__).resolve().parent.parent / "stack" / "config-generator" / "generate-config.sh"
)
COMPOSE_FILE = Path(__file__).resolve().parent.parent / "stack" / "docker-compose.yml"

# Valeurs de substitution FICTIVES utilisées uniquement pour PARSER les
# gabarits en YAML valide dans ces tests — jamais les vraies valeurs par
# défaut du projet (qui vivent dans generate-config.sh / .env.example et
# sont vérifiées séparément par test_seuils_par_defaut_coherents_avec_env_example).
VALEURS_FICTIVES = {
    "ALERTE_EXPORTATEUR_MUET_MINUTES": "15",
    "ALERTE_SATURATION_INTERFACE_SEUIL_PCT": "80",
    "ALERTE_CHUTE_TRAFIC_SEUIL_PCT": "50",
    "ALERTE_NOTIFICATION_WEBHOOK_URL": "http://localhost:9999/aucune-cible-configuree",
    # LOT db_health : seuil de parts actives ClickHouse (signal précoce,
    # bien avant les seuils serveur parts_to_delay_insert/parts_to_throw_insert).
    "ALERTE_DB_HEALTH_PARTS_ACTIVES_SEUIL": "500",
}


def _fichiers_templates() -> list[Path]:
    fichiers = sorted(ALERTING_DIR.glob("*.yaml.template"))
    assert fichiers, f"aucun gabarit *.yaml.template trouvé sous {ALERTING_DIR}"
    return fichiers


def _resoudre_template(chemin: Path) -> str:
    """Reproduit la substitution faite par `generate-config.sh` (sed sur
    chaque ${VAR} connue), avec des valeurs FICTIVES — assez pour parser le
    YAML résultant et vérifier sa structure, jamais pour tester les vraies
    valeurs par défaut (test séparé, voir plus bas)."""
    texte = chemin.read_text(encoding="utf-8")
    for cle, valeur in VALEURS_FICTIVES.items():
        texte = texte.replace(f"${{{cle}}}", valeur)
    return texte


def _charger_template(chemin: Path) -> dict[str, Any]:
    contenu: dict[str, Any] = yaml.safe_load(_resoudre_template(chemin))
    return contenu


def _sans_commentaires_yaml(texte: str) -> str:
    """Retire les commentaires `#` avant tout grep — même précaution que
    `tests/test_stack_portable.py::_sans_commentaires_yaml` : un commentaire
    qui EXPLIQUE pourquoi un motif est interdit contient lui-même ce motif,
    et ferait échouer le garde-fou sur sa propre documentation."""
    lignes = texte.splitlines()
    nettoyees = []
    for ligne in lignes:
        # Ne coupe pas un '#' à l'intérieur d'une chaîne entre guillemets
        # (peu probable ici, mais évite un faux positif sur une future
        # description de règle qui citerait un motif littéral).
        if '"' in ligne or "'" in ligne:
            nettoyees.append(ligne)
            continue
        nettoyees.append(re.sub(r"#.*$", "", ligne))
    return "\n".join(nettoyees)


def _toutes_les_requetes_sql(gabarit: dict[str, Any]) -> list[str]:
    """Extrait tout `rawSql` des `data[]` de chaque règle d'alerte, tous
    groupes confondus."""
    requetes: list[str] = []
    for groupe in gabarit.get("groups", []) or []:
        for regle in groupe.get("rules", []) or []:
            for donnee in regle.get("data", []) or []:
                modele = donnee.get("model", {}) or {}
                sql = modele.get("rawSql")
                if isinstance(sql, str) and sql.strip():
                    requetes.append(sql)
    return requetes


def _toutes_les_regles(gabarit: dict[str, Any]) -> list[dict[str, Any]]:
    regles: list[dict[str, Any]] = []
    for groupe in gabarit.get("groups", []) or []:
        regles.extend(groupe.get("rules", []) or [])
    return regles


# ---------------------------------------------------------------------------
# 0. Présence et parsing réel des fichiers
# ---------------------------------------------------------------------------


class TestFichiersPresents:
    def test_le_dossier_alerting_existe_et_contient_des_gabarits(self) -> None:
        assert ALERTING_DIR.is_dir(), f"{ALERTING_DIR} n'existe pas"
        assert list(ALERTING_DIR.glob("*.yaml.template")), (
            f"aucun *.yaml.template sous {ALERTING_DIR} — le dossier de "
            "provisioning resterait vide au démarrage de Grafana"
        )

    @pytest.mark.parametrize("chemin", _fichiers_templates())
    def test_chaque_gabarit_resolu_est_un_yaml_valide(self, chemin: Path) -> None:
        contenu = _charger_template(chemin)
        assert isinstance(contenu, dict), f"{chemin.name} ne parse pas comme un objet YAML"
        assert contenu.get("apiVersion") == 1, f"{chemin.name}: apiVersion attendu = 1"

    def test_aucun_yaml_resolu_nest_versionne_en_dur(self) -> None:
        """Seuls les *.yaml.template sont versionnés — un *.yaml résolu et
        commité figerait les seuils, contredisant l'exigence de
        paramétrage par variable d'environnement."""
        fichiers_yaml_bruts = list(ALERTING_DIR.glob("*.yaml")) + list(ALERTING_DIR.glob("*.yml"))
        assert not fichiers_yaml_bruts, (
            f"fichier(s) YAML résolu(s) versionné(s) trouvé(s) : {fichiers_yaml_bruts} — "
            "seuls les .yaml.template doivent être commités"
        )


# ---------------------------------------------------------------------------
# 1. Les 3 règles métier attendues existent, avec sévérité et description
#    « quoi faire »
# ---------------------------------------------------------------------------


class TestLesTroisReglesAttendues:
    def _tous_les_titres(self) -> list[str]:
        titres: list[str] = []
        for chemin in _fichiers_templates():
            gabarit = _charger_template(chemin)
            titres.extend(r.get("title", "") for r in _toutes_les_regles(gabarit))
        return titres

    def test_regle_exportateur_muet_existe(self) -> None:
        titres = self._tous_les_titres()
        assert any("muet" in t.lower() for t in titres), (
            f"aucune règle 'exportateur muet' trouvée (titres : {titres})"
        )

    def test_regle_saturation_interface_existe(self) -> None:
        titres = self._tous_les_titres()
        assert any("saturation" in t.lower() for t in titres), (
            f"aucune règle de saturation d'interface trouvée (titres : {titres})"
        )

    def test_regle_chute_de_trafic_existe(self) -> None:
        titres = self._tous_les_titres()
        assert any("chute" in t.lower() for t in titres), (
            f"aucune règle de chute de trafic trouvée (titres : {titres})"
        )

    def test_toutes_les_regles_portent_une_severite(self) -> None:
        for chemin in _fichiers_templates():
            gabarit = _charger_template(chemin)
            for regle in _toutes_les_regles(gabarit):
                labels = regle.get("labels", {}) or {}
                assert labels.get("severite"), (
                    f"{chemin.name} / {regle.get('title')}: aucun label 'severite'"
                )

    def test_toutes_les_regles_decrivent_quoi_faire_pas_seulement_le_symptome(self) -> None:
        """Exigence du prompt : « une description qui dit QUOI FAIRE quand
        elle se déclenche (pas seulement ce qui ne va pas) ». Contrôle
        faible mais réel : la description doit dépasser une simple
        redite du résumé et contenir au moins un verbe d'action attendu."""
        verbes_action = ("ouvrir", "vérifier", "identifier", "contrôler", "escalader", "arbitrer")
        for chemin in _fichiers_templates():
            gabarit = _charger_template(chemin)
            for regle in _toutes_les_regles(gabarit):
                description = (regle.get("annotations", {}) or {}).get("description", "").lower()
                assert len(description) > 80, (
                    f"{chemin.name} / {regle.get('title')}: description trop courte "
                    "pour expliquer une procédure"
                )
                assert any(verbe in description for verbe in verbes_action), (
                    f"{chemin.name} / {regle.get('title')}: description sans verbe "
                    f"d'action ({verbes_action}) — ne dit pas quoi FAIRE"
                )

    def test_toutes_les_regles_ont_des_titres_et_libelles_en_francais(self) -> None:
        mots_francais = ("exportateur", "interface", "trafic", "flux", "chute", "saturation")
        texte_complet = " ".join(self._tous_les_titres()).lower()
        trouves = [m for m in mots_francais if m in texte_complet]
        assert len(trouves) >= 3, f"trop peu de vocabulaire français dans les titres : {trouves}"


# ---------------------------------------------------------------------------
# 2. GARDE-FOU CRITIQUE — SamplingRate appliqué, count() jamais mis à
#    l'échelle (même esprit que test_sampling_rate.py / test_grafana_dashboards.py)
# ---------------------------------------------------------------------------


class TestSamplingRateDansLesAlertes:
    COLONNES_A_ECHELLE = ("Bytes", "Packets")

    def test_aucune_somme_de_volume_sans_taux_dechantillonnage(self) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_templates():
            gabarit = _charger_template(chemin)
            for requete in _toutes_les_requetes_sql(gabarit):
                nettoyee = _sans_commentaires_yaml(requete)
                for colonne in self.COLONNES_A_ECHELLE:
                    for match in re.finditer(rf"sum\(\s*{colonne}\s*\)", nettoyee):
                        offenders.append(f"{chemin.name}: {match.group(0)}")
        assert not offenders, (
            "sommes de volume SANS '* SamplingRate' dans une requête d'alerte — "
            "le seuil comparé serait faux d'un facteur égal au taux "
            "d'échantillonnage réel de l'exportateur :\n  " + "\n  ".join(offenders)
        )

    def test_au_moins_une_agregation_par_gabarit_qui_calcule_un_volume_applique_bien_le_taux(
        self,
    ) -> None:
        """Miroir du précédent : au moins une requête (saturation, chute)
        doit sommer un volume avec le taux appliqué — sinon supprimer
        toute agrégation ferait aussi passer le garde ci-dessus au vert."""
        total = 0
        for chemin in _fichiers_templates():
            gabarit = _charger_template(chemin)
            for requete in _toutes_les_requetes_sql(gabarit):
                total += len(
                    re.findall(
                        r"sum\(\s*\w+\s*\*\s*SamplingRate\s*\)",
                        _sans_commentaires_yaml(requete),
                    )
                )
                # Les agrégations conditionnelles (sumIf) comptent aussi.
                total += len(
                    re.findall(
                        r"sumIf\(\s*\w+\s*\*\s*SamplingRate",
                        _sans_commentaires_yaml(requete),
                    )
                )
        assert total >= 2, (
            f"seulement {total} agrégation(s) 'sum(... * SamplingRate)' ou "
            "'sumIf(... * SamplingRate...)' trouvée(s) dans les alertes — "
            "attendu au moins 2 (saturation interface + chute de trafic)"
        )

    def test_le_comptage_de_flux_nest_jamais_mis_a_lechelle(self) -> None:
        for chemin in _fichiers_templates():
            gabarit = _charger_template(chemin)
            for requete in _toutes_les_requetes_sql(gabarit):
                nettoyee = _sans_commentaires_yaml(requete)
                assert not re.search(r"count\(\)\s*\*\s*SamplingRate", nettoyee), (
                    f"{chemin.name}: count() ne doit PAS être mis à l'échelle"
                )

    def test_le_garde_fou_mord_sur_un_sum_bytes_nu_sabote(self) -> None:
        """Sabotage : injecte un sum(Bytes) nu en mémoire (jamais le fichier
        réel) et prouve que le motif resterait détectable, puis restaure
        (rien à restaurer : la mutation ne touche jamais le disque)."""
        sql_sabote = "SELECT sum(Bytes) AS total FROM flows"
        nettoyee = _sans_commentaires_yaml(sql_sabote)
        assert re.search(r"sum\(\s*Bytes\s*\)", nettoyee), (
            "le motif de sabotage aurait dû rester détectable — sinon le "
            "garde-fou ci-dessus ne prouve rien"
        )


# ---------------------------------------------------------------------------
# 3. GARDE-FOU CRITIQUE — DSCP via bitShiftRight, jamais l'opérateur >>
# ---------------------------------------------------------------------------


class TestPasDoperateurDecalageBinaire:
    def test_aucun_operateur_gtgt_dans_le_sql_des_alertes(self) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_templates():
            gabarit = _charger_template(chemin)
            for requete in _toutes_les_requetes_sql(gabarit):
                if ">>" in _sans_commentaires_yaml(requete):
                    offenders.append(chemin.name)
        assert not offenders, (
            f"'>>' trouvé dans le SQL d'alerte de : {offenders} — ClickHouse le "
            "refuse (Code: 62 SYNTAX_ERROR, mesuré). Utiliser bitShiftRight(x, n)."
        )

    def test_le_garde_fou_mord_sur_un_gtgt_sabote(self) -> None:
        sql_sabote = "SELECT IPTos >> 2 AS dscp FROM flows"
        assert ">>" in _sans_commentaires_yaml(sql_sabote), (
            "le sabotage aurait dû rester détectable"
        )


# ---------------------------------------------------------------------------
# 4. GARDE-FOU CRITIQUE — aucune macro Grafana inexistante dans le plugin
#    ClickHouse ($__unixEpochFrom, $__unixEpochTo, $__timeInterval_ms,
#    $__dateTimeFilter). Les alertes doivent utiliser une fenêtre LITTÉRALE
#    (pas de fenêtre de dashboard à ce niveau) ou $__timeFilter / $__toTime /
#    $__fromTime / $__interval_s, les seules macros vérifiées supportées.
# ---------------------------------------------------------------------------

MACROS_INEXISTANTES = (
    "$__unixEpochFrom",
    "$__unixEpochTo",
    "$__timeInterval_ms",
    "$__dateTimeFilter",
)


class TestAucuneMacroInexistante:
    def test_aucune_requete_dalerte_nutilise_une_macro_absente_du_plugin(self) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_templates():
            gabarit = _charger_template(chemin)
            for requete in _toutes_les_requetes_sql(gabarit):
                for macro in MACROS_INEXISTANTES:
                    if macro in requete:
                        offenders.append(f"{chemin.name}: {macro}")
        assert not offenders, (
            f"macro(s) absente(s) du plugin ClickHouse trouvée(s) : {offenders} — "
            "elles partiraient telles quelles dans le SQL (Code: 46 UNKNOWN_FUNCTION). "
            "Macros supportées : $__timeFilter, $__timeInterval, $__fromTime, "
            "$__toTime, $__interval_s."
        )

    def test_le_garde_fou_macro_mord_sur_une_macro_sabotee(self) -> None:
        sql_sabote = "SELECT toUnixTimestamp($__toTime) - $__unixEpochFrom() AS duree"
        assert "$__unixEpochFrom" in sql_sabote, "le sabotage aurait dû rester détectable"


# ---------------------------------------------------------------------------
# 5. Aucun seuil en dur qui devrait être paramétrable — les 3 seuils
#    métier (silence, saturation, chute) doivent passer par ${VAR}, jamais
#    une constante numérique figée dans le gabarit.
# ---------------------------------------------------------------------------


class TestSeuilsParametrables:
    """Exigence du prompt : « des seuils paramétrables par variable
    d'environnement avec des valeurs par défaut raisonnables ». Contrôlé sur
    le texte BRUT du gabarit (avant résolution) — après résolution, le
    ${VAR} a disparu et ce garde-fou ne pourrait plus rien prouver."""

    def test_le_gabarit_exportateur_muet_reference_bien_la_variable_de_seuil(self) -> None:
        chemin = ALERTING_DIR / "alerte-exportateur-muet.yaml.template"
        assert chemin.exists(), f"{chemin} manquant"
        texte = chemin.read_text(encoding="utf-8")
        assert "${ALERTE_EXPORTATEUR_MUET_MINUTES}" in texte, (
            "le seuil de silence (minutes) doit être paramétrable par variable "
            "d'environnement, pas figé en dur dans le gabarit"
        )

    def test_le_gabarit_saturation_reference_bien_la_variable_de_seuil(self) -> None:
        chemin = ALERTING_DIR / "alerte-saturation-interface.yaml.template"
        assert chemin.exists(), f"{chemin} manquant"
        texte = chemin.read_text(encoding="utf-8")
        assert "${ALERTE_SATURATION_INTERFACE_SEUIL_PCT}" in texte, (
            "le seuil de saturation (%) doit être paramétrable par variable "
            "d'environnement, pas figé en dur dans le gabarit"
        )

    def test_le_gabarit_chute_trafic_reference_bien_la_variable_de_seuil(self) -> None:
        chemin = ALERTING_DIR / "alerte-chute-trafic.yaml.template"
        assert chemin.exists(), f"{chemin} manquant"
        texte = chemin.read_text(encoding="utf-8")
        assert "${ALERTE_CHUTE_TRAFIC_SEUIL_PCT}" in texte, (
            "le seuil de chute (%) doit être paramétrable par variable "
            "d'environnement, pas figé en dur dans le gabarit"
        )

    def test_le_contact_point_reference_bien_la_variable_de_cible(self) -> None:
        chemin = ALERTING_DIR / "contact-points.yaml.template"
        assert chemin.exists(), f"{chemin} manquant"
        texte = chemin.read_text(encoding="utf-8")
        assert "${ALERTE_NOTIFICATION_WEBHOOK_URL}" in texte, (
            "la cible du contact point doit être paramétrable par variable "
            "d'environnement, pas figée en dur dans le gabarit"
        )

    def test_le_garde_fou_mord_si_un_seuil_est_sabote_en_dur(self) -> None:
        """Sabotage : simule un gabarit où le seuil serait figé en dur
        (HAVING silence_s > 900, sans ${VAR}) et prouve que le motif de
        paramétrage attendu serait bien absent — donc détectable."""
        gabarit_sabote = "HAVING silence_s > (900)"  # 900 = 15*60 en dur, sans ${VAR}
        assert "${ALERTE_EXPORTATEUR_MUET_MINUTES}" not in gabarit_sabote, (
            "le sabotage aurait dû faire disparaître la variable attendue"
        )


# ---------------------------------------------------------------------------
# 6. Le canal de notification (contact point) et la politique de
#    notification sont bien déclarés
# ---------------------------------------------------------------------------


class TestCanalDeNotification:
    def test_le_contact_point_est_declare(self) -> None:
        chemin = ALERTING_DIR / "contact-points.yaml.template"
        gabarit = _charger_template(chemin)
        points = gabarit.get("contactPoints", []) or []
        assert points, f"{chemin.name}: aucun contactPoint déclaré"
        noms = [p.get("name") for p in points]
        assert "okvorado-notifications" in noms, (
            f"contact point 'okvorado-notifications' introuvable (trouvés : {noms})"
        )

    def test_le_contact_point_porte_un_recepteur_avec_url(self) -> None:
        chemin = ALERTING_DIR / "contact-points.yaml.template"
        gabarit = _charger_template(chemin)
        points = gabarit.get("contactPoints", []) or []
        recepteurs = [r for p in points for r in (p.get("receivers") or [])]
        assert recepteurs, "aucun récepteur déclaré dans le contact point"
        for recepteur in recepteurs:
            settings = recepteur.get("settings", {}) or {}
            assert settings.get("url"), f"récepteur {recepteur.get('uid')} sans URL cible"

    def test_la_politique_de_notification_route_vers_le_contact_point(self) -> None:
        chemin = ALERTING_DIR / "notification-policies.yaml.template"
        gabarit = _charger_template(chemin)
        politiques = gabarit.get("policies", []) or []
        assert politiques, f"{chemin.name}: aucune politique déclarée"
        assert any(p.get("receiver") == "okvorado-notifications" for p in politiques), (
            "aucune politique ne route vers 'okvorado-notifications'"
        )

    def test_la_cible_par_defaut_est_inoffensive(self) -> None:
        """Exigence du prompt : « une valeur par défaut inoffensive ». Le
        défaut vit dans docker-compose.yml (fallback ${VAR:-défaut} de
        ALERTE_NOTIFICATION_WEBHOOK_URL) — generate-config.sh ne fait que
        relayer la valeur reçue, il ne porte aucun défaut lui-même. Le
        défaut ne doit JAMAIS pointer une cible réelle (Slack/Teams/PagerDuty
        publics) — seulement une URL locale non routée."""
        compose = COMPOSE_FILE.read_text(encoding="utf-8")
        match = re.search(
            r"ALERTE_NOTIFICATION_WEBHOOK_URL:\s*\$\{ALERTE_NOTIFICATION_WEBHOOK_URL:-([^}]+)\}",
            compose,
        )
        assert match, (
            "aucun défaut ${ALERTE_NOTIFICATION_WEBHOOK_URL:-...} trouvé dans "
            "docker-compose.yml — le stack démarrerait sans cible de repli"
        )
        defaut = match.group(1)
        assert "localhost" in defaut or "127.0.0.1" in defaut, (
            f"la valeur par défaut du webhook de notification ({defaut!r}) n'a pas "
            "l'air d'être une URL locale inoffensive"
        )
        for motif_interdit in ("hooks.slack.com", "webhook.office.com", "events.pagerduty.com"):
            assert motif_interdit not in defaut, (
                f"cible de notification réelle en dur trouvée par défaut : {motif_interdit}"
            )

    def test_le_garde_fou_canal_mord_si_le_contact_point_disparait(self) -> None:
        gabarit_sabote: dict[str, Any] = {"apiVersion": 1, "contactPoints": []}
        points = gabarit_sabote.get("contactPoints", [])
        assert not points, "le sabotage aurait dû produire une liste de contact points vide"


# ---------------------------------------------------------------------------
# 7. Le widget « Alarmes récentes » (alertlist) est bien sur l'accueil
# ---------------------------------------------------------------------------

ACCUEIL_DASHBOARD = (
    Path(__file__).resolve().parent.parent
    / "stack"
    / "grafana"
    / "dashboards"
    / "00-accueil-traffic-summary.json"
)


class TestWidgetAlarmesRecentes:
    def test_le_dashboard_accueil_porte_un_panneau_alertlist(self) -> None:
        import json

        dashboard = json.loads(ACCUEIL_DASHBOARD.read_text(encoding="utf-8"))
        types = [p.get("type") for p in dashboard.get("panels", [])]
        assert "alertlist" in types, (
            f"aucun panneau 'alertlist' trouvé sur le dashboard d'accueil "
            f"(types présents : {types}) — équivalent du widget 'Recent Alarms' "
            "de NetFlow Analyzer absent"
        )

    def test_le_panneau_alertlist_est_titre_alarmes_recentes(self) -> None:
        import json

        dashboard = json.loads(ACCUEIL_DASHBOARD.read_text(encoding="utf-8"))
        panneaux_alertlist = [
            p for p in dashboard.get("panels", []) if p.get("type") == "alertlist"
        ]
        assert panneaux_alertlist, "aucun panneau alertlist à vérifier"
        titres = [p.get("title", "").lower() for p in panneaux_alertlist]
        assert any("alarme" in t for t in titres), (
            f"le panneau alertlist ne porte pas de titre évoquant les alarmes : {titres}"
        )

    def test_aucun_chevauchement_de_gridpos_sur_le_dashboard_accueil(self) -> None:
        """Garde-fou de non-régression pour l'insertion du panneau
        alertlist : vérifie que deux panneaux ne se chevauchent jamais sur
        la grille (12 colonnes standard Grafana), en excluant les 'row'
        (hauteur 1, purement des séparateurs visuels sans contenu propre)."""
        import json

        dashboard = json.loads(ACCUEIL_DASHBOARD.read_text(encoding="utf-8"))
        rects = []
        for panel in dashboard.get("panels", []):
            if panel.get("type") == "row":
                continue
            gp = panel.get("gridPos", {})
            x0, y0 = gp.get("x", 0), gp.get("y", 0)
            x1, y1 = x0 + gp.get("w", 0), y0 + gp.get("h", 0)
            rects.append((panel.get("id"), x0, y0, x1, y1))

        offenders: list[str] = []
        for i, (id_a, ax0, ay0, ax1, ay1) in enumerate(rects):
            for id_b, bx0, by0, bx1, by1 in rects[i + 1 :]:
                chevauche_x = ax0 < bx1 and bx0 < ax1
                chevauche_y = ay0 < by1 and by0 < ay1
                if chevauche_x and chevauche_y:
                    offenders.append(f"panel {id_a} chevauche panel {id_b}")
        assert not offenders, f"chevauchements de gridPos détectés : {offenders}"


# ---------------------------------------------------------------------------
# 8. Le générateur résout bien les gabarits d'alerte (config-generator)
# ---------------------------------------------------------------------------


class TestGenerateurConfig:
    def test_le_script_generateur_traite_les_gabarits_dalerte(self) -> None:
        script = GENERATOR_SCRIPT.read_text(encoding="utf-8")
        assert "grafana-alerting-templates" in script or "yaml.template" in script, (
            "generate-config.sh ne semble pas traiter les gabarits d'alerte Grafana"
        )
        for variable in VALEURS_FICTIVES:
            assert variable in script, f"generate-config.sh ne substitue pas la variable {variable}"

    def test_le_compose_monte_le_dossier_de_gabarits_dans_config_generator(self) -> None:
        compose = COMPOSE_FILE.read_text(encoding="utf-8")
        assert "grafana-alerting-templates" in compose, (
            "docker-compose.yml ne monte pas les gabarits d'alerte dans config-generator"
        )

    def test_le_compose_monte_le_volume_genere_dans_grafana(self) -> None:
        """La sortie du générateur d'alertes doit atterrir dans le dossier de
        provisioning de Grafana.

        Ce qui compte est la CIBLE du montage, pas la forme de la source :
        depuis le 2026-08-08 la persistance est passée des volumes Docker
        nommés (`grafana-alerting-generated`) à des bind mounts du projet
        (`./data/grafana-alerting`), sur exigence utilisateur — « stockage et
        persistence dans des dossiers à la racine du projet ». Le test
        vérifiait auparavant l'ancien NOM de volume et cassait sur ce
        changement, alors que le comportement protégé était intact.
        """
        compose = COMPOSE_FILE.read_text(encoding="utf-8")
        assert ":/etc/grafana/provisioning/alerting" in compose, (
            "docker-compose.yml ne monte rien dans le dossier de "
            "provisioning alerting de Grafana : les alertes générées ne "
            "seraient jamais chargées (écran d'alertes vide, sans erreur)"
        )

    def test_grafana_attend_la_fin_de_config_generator(self) -> None:
        """Sans cette dépendance, Grafana pourrait démarrer avant que le
        volume grafana-alerting-generated ne soit rempli, provisionnant un
        dossier vide au premier démarrage."""
        compose = COMPOSE_FILE.read_text(encoding="utf-8")
        # Cherche le bloc du service grafana et vérifie qu'il dépend de
        # config-generator avec condition service_completed_successfully.
        match = re.search(r"\n  grafana:\n(?:.*\n)*?(?=\n  \w|\Z)", compose)
        assert match, "service 'grafana' introuvable dans docker-compose.yml"
        bloc_grafana = match.group(0)
        assert "config-generator" in bloc_grafana, (
            "le service grafana ne déclare pas de dépendance sur config-generator"
        )
        assert "service_completed_successfully" in bloc_grafana, (
            "la dépendance grafana -> config-generator n'attend pas sa complétion réussie"
        )


# ---------------------------------------------------------------------------
# 9. La datasource ClickHouse porte un UID EXPLICITE et STABLE — condition
#    nécessaire pour que les règles d'alerte (qui référencent 'ClickHouse'
#    comme datasourceUid) fonctionnent sur un déploiement neuf.
# ---------------------------------------------------------------------------

DATASOURCE_FILE = (
    Path(__file__).resolve().parent.parent
    / "stack"
    / "grafana"
    / "provisioning"
    / "datasources"
    / "clickhouse.yml"
)


class TestDatasourceUidStable:
    """DÉFAUT MESURÉ (2026-08-08) : sans `uid:` explicite dans le
    provisioning datasource, Grafana attribue un UID ALÉATOIRE à chaque
    provisioning à froid (mesuré : 'PDEE91DDB90597936'). Les règles d'alerte
    de ce lot référencent `datasourceUid: ClickHouse` — sans cet UID fixé,
    `POST /api/ds/query` avec `uid: "ClickHouse"` répond
    `{"message":"Data source not found"}` (reproduit contre ce ClickHouse
    réel), et Grafana refuse même de démarrer une fois des règles
    provisionnées le référencent (mesuré : crash-loop
    'Datasource provisioning error: data source not found' après ajout
    d'un uid explicite en désaccord avec l'état déjà persisté — la cause
    räcine était bien l'ABSENCE de cet uid au tout premier provisioning)."""

    def test_la_datasource_clickhouse_porte_un_uid_explicite(self) -> None:
        contenu = yaml.safe_load(DATASOURCE_FILE.read_text(encoding="utf-8"))
        datasources = contenu.get("datasources", []) or []
        assert datasources, "aucune datasource déclarée"
        ds_clickhouse = next((d for d in datasources if d.get("name") == "ClickHouse"), None)
        assert ds_clickhouse is not None, "datasource 'ClickHouse' introuvable"
        assert ds_clickhouse.get("uid") == "ClickHouse", (
            f"uid explicite attendu 'ClickHouse', trouvé : {ds_clickhouse.get('uid')!r} — "
            "sans cet uid fixé, les règles d'alerte qui référencent "
            "datasourceUid: ClickHouse ne trouveraient pas la datasource"
        )

    def test_toutes_les_regles_dalerte_referencent_luid_clickhouse_stable(self) -> None:
        offenders: list[str] = []
        for chemin in _fichiers_templates():
            gabarit = _charger_template(chemin)
            for regle in _toutes_les_regles(gabarit):
                for donnee in regle.get("data", []) or []:
                    uid = donnee.get("datasourceUid")
                    if uid in (None, "__expr__"):
                        continue  # étages d'expression (reduce/threshold), pas une requête SQL
                    if uid != "ClickHouse":
                        offenders.append(f"{chemin.name} / {regle.get('title')}: uid={uid!r}")
        assert not offenders, (
            f"règle(s) d'alerte référençant un datasourceUid autre que "
            f"'ClickHouse' (stable) : {offenders}"
        )

    def test_le_garde_fou_uid_mord_si_luid_disparait(self) -> None:
        ds_sabotee = {"name": "ClickHouse", "type": "grafana-clickhouse-datasource"}
        assert ds_sabotee.get("uid") != "ClickHouse", (
            "le sabotage (absence d'uid) aurait dû être détectable — "
            "ds_sabotee.get('uid') vaut None, pas 'ClickHouse'"
        )
