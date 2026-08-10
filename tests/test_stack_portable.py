"""Garde-fous du stack `stack/` — clé en main, sans dépendance homelab.

CE QUE CE STACK RÉSOUT (voir CLAUDE.md racine, section « L'objectif ») :
construire un stack Docker qui remplace NetFlow en entreprise sur 350 routeurs
SFR, sur le modèle de l'auto-découverte NetFlow classique — on pointe les
routeurs vers le collecteur, ils apparaissent seuls, SNMP complète les
métadonnées, rien à déclarer nominativement.

POINT DE RUPTURE MESURÉ (2026-08-07) que ces tests interdisent de réintroduire :
`outlet.yaml` en production porte 13 adresses en dur pour 11 exportateurs
(~18 lignes par exportateur). Ce modèle ne tient pas à 350 routeurs. Le stack
livré ici doit fonctionner par AUTO-DÉCOUVERTE SNMP, sans aucune IP de routeur
déclarée à la main.

DEUX PIÈGES MESURÉS, dont ces tests prouvent la présence dans la config livrée :

1. Zéro silencieux à l'échelle du parc : la doc Akvorado dit explicitement que
   les flux sans information d'interface sont JETÉS. Sans repli, un routeur
   dont SNMP ne répond pas (pare-feu, mauvaise communauté) perd sa visibilité
   sans aucune alerte.
2. Ordre CONTRE-INTUITIF de la cascade `metadata.providers` : `static` doit
   être EN PREMIER (avec `skip-missing-interfaces: true`), sinon il ne
   laisserait rien passer et `snmp` ne serait jamais interrogé — un `static`
   avec `default:` avale TOUT. Documenté dans `outlet.yaml`.

⚠️ Piège vécu 7 fois sur ce projet : un test qui fige un MOYEN (chaîne exacte,
ligne précise) casse au premier refactor légitime et ne prouve rien. Ces tests
visent le COMPORTEMENT observable — YAML parsé, structure, présence/absence de
motifs — jamais une ligne figée.

⚠️ Autre piège vécu : un test qui grep un motif interdit échoue sur sa PROPRE
documentation (un commentaire qui explique pourquoi `100.64.` est interdit
contient... `100.64.`). Les recherches de motifs interdits retirent donc les
lignes de commentaire avant de chercher.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest
import yaml


class _LoaderTolerantIncludes(yaml.SafeLoader):
    """`yaml.SafeLoader` qui sait ignorer le tag `!include` d'Akvorado.

    `akvorado.yaml` inclut `inlet.yaml`/`outlet.yaml` via `!include "..."`,
    une directive CUSTOM propre au binaire Akvorado (voir
    `app/clients/yaml_editor.py`, qui utilise `ruamel.yaml` pour la même
    raison). Un `yaml.safe_load` nu échoue sur ce tag inconnu. Ces tests ne
    valident QUE la structure de chaque fichier séparément (jamais la
    résolution des inclusions) : le nom du fichier inclus suffit.
    """


def _construire_include(loader: yaml.SafeLoader, node: yaml.Node) -> str:
    return str(loader.construct_scalar(node))  # type: ignore[arg-type]


_LoaderTolerantIncludes.add_constructor("!include", _construire_include)


def _charger_yaml(chemin: Path) -> Any:
    return yaml.load(chemin.read_text(encoding="utf-8"), Loader=_LoaderTolerantIncludes)


STACK_DIR = Path(__file__).resolve().parent.parent / "stack"
COMPOSE_FILE = STACK_DIR / "docker-compose.yml"
ENV_EXAMPLE = STACK_DIR / ".env.example"
CONFIG_DIR = STACK_DIR / "config"
README = STACK_DIR / "README.md"

CONFIG_FILES = {
    "akvorado": CONFIG_DIR / "akvorado.yaml",
    "inlet": CONFIG_DIR / "inlet.yaml",
    # outlet.yaml n'est PAS versionné : il est GÉNÉRÉ au démarrage (service
    # `config-generator` du compose) depuis ce gabarit, en résolvant
    # ${SNMP_COMMUNITY} — le seul secret du lot. Le gabarit porte la même
    # structure YAML que le fichier généré (seule la communauté SNMP change),
    # donc tous les tests structurels ci-dessous restent valides dessus.
    "outlet": CONFIG_DIR / "outlet.yaml.template",
    "console": CONFIG_DIR / "console.yaml",
}

# `outlet.yaml.template` : le gabarit versionné, source de `outlet.yaml`.
OUTLET_TEMPLATE = CONFIG_DIR / "outlet.yaml.template"

# Les 4 fichiers RÉELLEMENT lus par Akvorado à l'exécution (après génération
# de outlet.yaml depuis son gabarit). Utilisé par le garde-fou anti-${...}
# ci-dessous : ce sont eux qui doivent être ZÉRO substitution non résolue.
FICHIERS_LUS_PAR_AKVORADO = {
    "akvorado": CONFIG_DIR / "akvorado.yaml",
    "inlet": CONFIG_DIR / "inlet.yaml",
    "console": CONFIG_DIR / "console.yaml",
}

# Motifs qui signent une adhérence au homelab de qualification. Aucun ne doit
# apparaître dans le code EXÉCUTABLE (hors commentaires) du stack livré : ce
# stack doit démarrer sur une machine nue, en entreprise, sans rien de ceci.
# Motifs signant une ADHÉRENCE au homelab de développement. Le paquet livrable
# ne doit en contenir AUCUN : il s'installe sur une machine nue en entreprise.
#
# ⚠️ Ces chaînes sont VOLONTAIREMENT les noms réels du homelab, y compris le
# domaine. Elles ont été ré-écrites par erreur le 2026-08-10 lors de
# l'anonymisation du dépôt pour publication : la liste s'est alors mise à
# chercher les noms GÉNÉRIQUES de remplacement, donc à mordre sur du code sain
# tout en devenant aveugle à ce qu'elle doit détecter. Un garde-fou dont on
# anonymise les motifs ne garde plus rien.
MOTIFS_HOMELAB = (
    "tailscale",
    "100.64.",
    "authelia",
    "bunkerweb",
    "masenam",
)

# Motifs signant un registre d'image privé du homelab (à ne jamais retrouver
# comme préfixe d'image : le stack doit tirer des images PUBLIQUES).
MOTIFS_REGISTRE_PRIVE = ("registry.masenam", "harbor.masenam", "gitea.masenam")


def _sans_commentaires_yaml(texte: str) -> str:
    """Retire les commentaires `# ...` d'un texte YAML, ligne par ligne.

    Un test qui grep un motif interdit sur le fichier BRUT échoue sur sa PROPRE
    documentation : le commentaire qui explique « ne jamais utiliser une IP
    Tailscale ici » contient lui-même `100.64.` ou le mot `tailscale`. On ne
    retire pas les `#` à l'intérieur d'une valeur entre guillemets (rare ici,
    mais on reste simple et prudent : on ne coupe qu'à partir d'un `#` précédé
    d'un espace ou en tout début de ligne, ce qui couvre la totalité des
    commentaires réellement écrits dans ces fichiers).
    """
    lignes = []
    for ligne in texte.splitlines():
        sans_commentaire = re.sub(r"(^|\s)#.*$", "", ligne)
        lignes.append(sans_commentaire)
    return "\n".join(lignes)


def _sans_commentaires_compose(texte: str) -> str:
    """Même traitement pour docker-compose.yml (aussi du YAML)."""
    return _sans_commentaires_yaml(texte)


# ---------------------------------------------------------------------------
# 0. Présence et parsing réel des fichiers
# ---------------------------------------------------------------------------


class TestFichiersPresents:
    def test_les_fichiers_attendus_existent(self) -> None:
        manquants = [
            str(f)
            for f in (COMPOSE_FILE, ENV_EXAMPLE, README, *CONFIG_FILES.values())
            if not f.exists()
        ]
        assert not manquants, f"fichiers absents du stack : {manquants}"

    @pytest.mark.parametrize("nom", sorted(CONFIG_FILES))
    def test_chaque_yaml_de_config_parse_reellement(self, nom: str) -> None:
        """Parsing RÉEL (pas une regex) : un YAML syntaxiquement invalide
        empêcherait Akvorado de démarrer, silencieusement pour quiconque ne
        lance pas le service pour vérifier."""
        chemin = CONFIG_FILES[nom]
        contenu = _charger_yaml(chemin)
        assert isinstance(contenu, dict), f"{chemin.name} ne parse pas comme un mapping YAML"

    def test_le_compose_parse_reellement(self) -> None:
        contenu = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        assert isinstance(contenu, dict)
        assert "services" in contenu


# ---------------------------------------------------------------------------
# 1. Zéro adhérence au homelab de qualification
# ---------------------------------------------------------------------------


class TestZeroAdherenceHomelab:
    @pytest.mark.parametrize("motif", MOTIFS_HOMELAB)
    def test_aucun_motif_homelab_dans_le_compose(self, motif: str) -> None:
        contenu = _sans_commentaires_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
        assert motif not in contenu.lower(), (
            f"'{motif}' trouvé hors commentaire dans docker-compose.yml — "
            "adhérence au homelab de qualification, interdite pour un stack "
            "cle en main installable sur une machine nue en entreprise."
        )

    @pytest.mark.parametrize("motif", MOTIFS_HOMELAB)
    @pytest.mark.parametrize("nom", sorted(CONFIG_FILES))
    def test_aucun_motif_homelab_dans_les_configs(self, nom: str, motif: str) -> None:
        chemin = CONFIG_FILES[nom]
        contenu = _sans_commentaires_yaml(chemin.read_text(encoding="utf-8"))
        assert motif not in contenu.lower(), (
            f"'{motif}' trouvé hors commentaire dans {chemin.name} — "
            "adhérence au homelab de qualification."
        )

    def test_aucun_registre_prive_dans_le_compose(self) -> None:
        contenu = _sans_commentaires_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
        for motif in MOTIFS_REGISTRE_PRIVE:
            assert motif not in contenu.lower(), (
                f"'{motif}' trouvé dans docker-compose.yml : les images doivent "
                "venir d'un registre PUBLIC (quay.io, docker.io, ghcr.io...), "
                "pas d'un registre privé du homelab."
            )

    def test_aucun_reseau_docker_externe_preexistant(self) -> None:
        """`external: true` sur un réseau supposerait qu'il existe déjà sur
        l'hôte — faux sur une machine nue. Le stack doit créer son propre
        réseau, comme n'importe quel compose autonome."""
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        for reseau in (compose.get("networks") or {}).values():
            if isinstance(reseau, dict):
                assert reseau.get("external") is not True, (
                    "un reseau 'external: true' suppose une infra preexistante "
                    "sur l'hote — incompatible avec une machine nue"
                )

    def test_ce_fichier_de_test_documente_bien_les_motifs_sans_faux_positif(self) -> None:
        """Prémisse du nettoyage de commentaires : elle doit RETIRER le motif,
        pas juste ne pas planter. Sans ce test, `_sans_commentaires_yaml` qui
        ne fait rien laisserait passer silencieusement toutes les assertions
        ci-dessus si le motif n'apparaissait QUE dans des commentaires."""
        texte = "clef: valeur\n# ceci mentionne tailscale et 192.0.2.6 en commentaire\nautre: 1\n"
        nettoye = _sans_commentaires_yaml(texte)
        assert "tailscale" not in nettoye
        assert "100.64." not in nettoye
        assert "clef: valeur" in nettoye
        assert "autre: 1" in nettoye


# ---------------------------------------------------------------------------
# 1bis. GARDE-FOU — Akvorado ne résout AUCUN ${...} dans ses YAML
# ---------------------------------------------------------------------------


# Motif d'une substitution shell/compose non résolue : `${VAR}` ou
# `${VAR:-defaut}`. Un YAML qui en contient encore au moment où Akvorado le
# lit produit une erreur `strconv.Parse*` ou `invalid duration` — jamais une
# erreur YAML (le fichier PARSE très bien, `${...}` est une simple chaîne de
# caractères valide) : `docker compose config` et un `yaml.safe_load` passent
# tous les deux, et le défaut ne se révèle qu'au VRAI démarrage du conteneur.
_SUBSTITUTION_NON_RESOLUE_RE = re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*(?::-[^}]*)?\}")


class TestZeroSubstitutionDollarDansLesYamlLusParAkvorado:
    """DÉFAUT MESURÉ (2026-08-07) en montant le stack pour de vrai sur une
    machine qui ne l'avait jamais vu : ClickHouse, Kafka, Redis et Grafana
    démarrent, mais `akvorado-orchestrator` boucle en `Restarting` avec, mot
    pour mot :

        Error: unable to parse configuration: decoding failed due to the
        following error(s):
        'ClickHouse.ASNs[${LOCAL_ASN:-64500}]' cannot parse value as
        'uint32': strconv.ParseUint: invalid syntax
        'Kafka.TopicConfiguration.NumPartitions' cannot parse value as
        'int32': strconv.ParseInt: invalid syntax
        'Inlet[0].Flow.Inputs[0].Config.Workers' cannot parse value as
        'int': strconv.ParseInt: invalid syntax

    CE QUE CE DÉFAUT PROUVE, et pourquoi aucun garde-fou existant ne
    l'attrapait avant cette session : `docker compose config` VALIDE (les
    `${VAR}` sont un problème pour Akvorado, pas pour Compose — ce n'est même
    pas leur syntaxe qui pose problème ici), CHAQUE YAML PARSE tout seul
    (`${LOCAL_ASN:-64500}` est une chaîne de caractères parfaitement licite
    comme clé ou valeur YAML), et les 1194 tests de cette suite passaient
    tous. Seul le fait de monter le stack pour de vrai — Akvorado LUI-MÊME
    tentant de convertir cette chaîne en `uint32`/`int32`/`time.Duration` —
    révèle le défaut. Cause : Akvorado ne substitue JAMAIS les `${VAR}` dans
    les YAML qu'il lit (`akvorado.yaml`, `inlet.yaml`, `outlet.yaml`,
    `console.yaml`) ; seul Docker Compose le fait, et seulement dans
    `docker-compose.yml`.

    Portée : les 4 fichiers RÉELLEMENT lus par Akvorado au runtime
    (`FICHIERS_LUS_PAR_AKVORADO`) doivent être à zéro substitution non
    résolue — `outlet.yaml` en fait partie mais n'est pas versionné (il est
    généré depuis `outlet.yaml.template`, qui lui EST autorisé à contenir
    `${SNMP_COMMUNITY}` : c'est le seul secret du lot, résolu par le service
    `config-generator` du compose avant que l'orchestrateur ne démarre).
    """

    @pytest.mark.parametrize("nom", sorted(FICHIERS_LUS_PAR_AKVORADO))
    def test_aucune_substitution_dollar_dans_les_yaml_reellement_lus(self, nom: str) -> None:
        chemin = FICHIERS_LUS_PAR_AKVORADO[nom]
        contenu = _sans_commentaires_yaml(chemin.read_text(encoding="utf-8"))
        trouvees = _SUBSTITUTION_NON_RESOLUE_RE.findall(contenu)
        assert not trouvees, (
            f"{chemin.name} contient encore des substitutions non résolues "
            f"{trouvees!r} — Akvorado ne les résout PAS lui-même (seul Docker "
            "Compose le fait, uniquement dans docker-compose.yml). Au "
            "démarrage réel, ceci produit : \"'Kafka.TopicConfiguration."
            "NumPartitions' cannot parse value as 'int32': strconv.ParseInt: "
            "invalid syntax\" (ou l'équivalent uint32/duration selon le "
            "champ) — l'orchestrateur boucle en Restarting. Remplace par une "
            "valeur LITTÉRALE (réglable ensuite depuis l'écran Okvorado), ou "
            "si c'est un secret, résous-le via le gabarit "
            "outlet.yaml.template + le service config-generator."
        )

    def test_le_gabarit_outlet_porte_bien_la_reference_snmp_community(self) -> None:
        """Vérifie l'AUTRE moitié du garde-fou : `${SNMP_COMMUNITY}` doit
        rester présent dans le gabarit (sinon le secret serait en clair, ou
        le mécanisme de génération serait cassé/inutile)."""
        contenu = OUTLET_TEMPLATE.read_text(encoding="utf-8")
        assert "${SNMP_COMMUNITY}" in contenu, (
            "le gabarit outlet.yaml.template doit porter ${SNMP_COMMUNITY} "
            "— sans lui, rien ne distingue plus ce fichier d'un YAML final, "
            "et le service config-generator n'a plus rien à résoudre"
        )

    def test_le_fichier_outlet_yaml_genere_nest_pas_verse_au_depot(self) -> None:
        """`outlet.yaml` (généré) ne doit JAMAIS être commité : seul le
        `.template` l'est. S'il traîne dans le répertoire de travail (généré
        localement pendant un test manuel), le `.gitignore` doit l'exclure —
        sinon un `git add -A` étourdi verserait un fichier contenant la vraie
        communauté SNMP en clair."""
        gitignore = (STACK_DIR.parent / ".gitignore").read_text(encoding="utf-8")
        assert "stack/config/outlet.yaml" in gitignore, (
            "stack/config/outlet.yaml (le fichier GÉNÉRÉ, pas le .template) "
            "doit être listé dans .gitignore — sinon le secret SNMP généré "
            "localement peut finir versionné par erreur"
        )

    def test_le_garde_fou_mord_sur_le_cas_reellement_vecu(self, tmp_path: Path) -> None:
        """PREUVE QUE LE GARDE-FOU MORD : sabotage d'une copie temporaire avec
        exactement les 3 substitutions citées dans l'erreur Akvorado
        observée, vérification de la détection, puis restauration automatique
        (`tmp_path`, jamais le fichier réel)."""
        saboté = tmp_path / "akvorado.yaml"
        contenu_original = FICHIERS_LUS_PAR_AKVORADO["akvorado"].read_text(encoding="utf-8")
        contenu_saboté = contenu_original.replace(
            "num-partitions: 8", "num-partitions: ${KAFKA_NUM_PARTITIONS:-8}"
        ).replace("64500: Reseau local", "${LOCAL_ASN:-64500}: ${LOCAL_AS_NAME:-Reseau local}")
        assert contenu_saboté != contenu_original, "le sabotage n'a rien remplacé — test invalide"
        saboté.write_text(contenu_saboté, encoding="utf-8")

        contenu_nettoye = _sans_commentaires_yaml(saboté.read_text(encoding="utf-8"))
        trouvees = _SUBSTITUTION_NON_RESOLUE_RE.findall(contenu_nettoye)
        assert trouvees, (
            "le sabotage aurait dû introduire des substitutions ${...} "
            "détectables par le garde-fou — s'il n'en trouve aucune, le "
            "garde-fou ne mord pas et laisserait passer la régression "
            "réellement vécue le 2026-08-07"
        )
        assert any("KAFKA_NUM_PARTITIONS" in t for t in trouvees)
        assert any("LOCAL_ASN" in t for t in trouvees)

    def test_le_garde_fou_ne_mord_pas_sur_sa_propre_documentation(self) -> None:
        """PIÈGE VÉCU 8 FOIS sur ce projet (cf. docstring de module) : un test
        qui grep un motif interdit échoue sur sa PROPRE documentation. Les
        commentaires de ce fichier de test ET des YAML citent `${LOCAL_ASN`
        et consorts comme EXEMPLE d'erreur passée — retirer les commentaires
        avant de chercher est ce qui évite le faux positif."""
        texte = (
            "num-partitions: 8\n"
            "# DÉFAUT MESURÉ : num-partitions: ${KAFKA_NUM_PARTITIONS:-8} "
            "provoquait une erreur de parsing\n"
        )
        nettoye = _sans_commentaires_yaml(texte)
        assert not _SUBSTITUTION_NON_RESOLUE_RE.search(nettoye), (
            "le commentaire documentant l'ancienne erreur a fait échouer le "
            "garde-fou sur lui-même — la définition du motif interdit doit "
            "être cherchée APRÈS retrait des commentaires"
        )


# ---------------------------------------------------------------------------
# 2. LE test central — aucun exportateur déclaré nominativement
# ---------------------------------------------------------------------------


# Un motif d'IP/CIDR en dur.
_IP_CIDR_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?\b")

# Adresses/plages GÉNÉRIQUES légitimes : soit elles couvrent TOUT le parc
# (0.0.0.0/0), soit ce sont les trois plages RFC1918 standard utilisées pour
# étiqueter un RÔLE réseau (interne/externe) dans `networks.networks` — pas
# des exportateurs. La signature du point de rupture mesuré le 2026-08-07 est
# une adresse d'HÔTE (typiquement `/32`, ou sans masque) : un `/8`, `/12` ou
# `/16` correspondant PILE à une des trois plages RFC1918 canoniques ne
# déclare aucune machine précise, il couvre des millions d'adresses.
_ADRESSES_GENERIQUES = {
    "0.0.0.0/0",
    "0.0.0.0",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
}


def _adresses_ipv4_hors_commentaires(chemin: Path) -> list[str]:
    contenu = _sans_commentaires_yaml(chemin.read_text(encoding="utf-8"))
    return [m for m in _IP_CIDR_RE.findall(contenu) if m not in _ADRESSES_GENERIQUES]


class TestAucunExportateurNominatif:
    """LE test central du lot : c'est le point de rupture mesuré le 2026-08-07
    (outlet.yaml en prod : 13 adresses en dur pour 11 exportateurs, ~18 lignes
    chacun) que ce stack doit supprimer. Une IP de routeur en dur ici serait
    une régression exacte de ce défaut, à l'échelle de 350 routeurs cette fois.
    """

    def test_aucune_adresse_ipv4_nominative_dans_outlet(self) -> None:
        adresses = _adresses_ipv4_hors_commentaires(CONFIG_FILES["outlet"])
        assert not adresses, (
            f"adresse(s) IPv4 en dur trouvées dans outlet.yaml : {adresses} — "
            "c'est exactement le point de rupture mesure le 2026-08-07 "
            "(13 adresses pour 11 exportateurs). Le mode auto-decouverte SNMP "
            "ne doit declarer AUCUN exportateur nominativement."
        )

    def test_aucune_adresse_ipv4_nominative_dans_aucune_config(self) -> None:
        for nom, chemin in CONFIG_FILES.items():
            adresses = _adresses_ipv4_hors_commentaires(chemin)
            assert not adresses, f"{nom}.yaml porte des IP en dur : {adresses}"

    def test_le_provider_static_ne_declare_aucun_exportateur_nomme(self) -> None:
        """Le fournisseur `static` doit se limiter à un `default` générique
        (`::/0` ou `0.0.0.0/0`) — jamais une clé d'exportateur nominative.
        C'est la vérification structurelle, complémentaire du grep d'IP :
        elle attraperait aussi une clé nominative qui ne serait pas une IPv4
        pure (ex: un nom DNS)."""
        outlet = _charger_yaml(CONFIG_FILES["outlet"])
        providers = outlet["metadata"]["providers"]
        static = next(p for p in providers if p.get("type") == "static")
        exporters = static.get("exporters", {})
        cles_non_generiques = [k for k in exporters if k not in ("::/0", "0.0.0.0/0")]
        assert not cles_non_generiques, (
            f"le fournisseur 'static' declare des exportateurs nominatifs : "
            f"{cles_non_generiques} — regression du point de rupture (config "
            "qui croit lineairement avec le parc, ~18 lignes par exportateur)."
        )


# ---------------------------------------------------------------------------
# 3. Le provider SNMP est présent, en `::/0`, et bien ORDONNÉ après static
# ---------------------------------------------------------------------------


def _providers(outlet: dict[str, Any]) -> list[dict[str, Any]]:
    return outlet["metadata"]["providers"]


class TestAutoDecouverteSnmp:
    def test_le_provider_snmp_est_present(self) -> None:
        outlet = _charger_yaml(CONFIG_FILES["outlet"])
        types = [p.get("type") for p in _providers(outlet)]
        assert "snmp" in types, (
            "aucun fournisseur 'snmp' dans outlet.yaml : sans lui, aucune "
            "auto-decouverte, on retombe sur la declaration nominative que "
            "ce stack doit precisement supprimer."
        )

    def test_le_snmp_couvre_tout_le_parc_en_slash_zero(self) -> None:
        """`::/0` (IPv6, englobe aussi les IPv4-mapped) couvre TOUT le parc
        sans qu'aucun routeur n'ait à être déclaré."""
        outlet = _charger_yaml(CONFIG_FILES["outlet"])
        snmp = next(p for p in _providers(outlet) if p.get("type") == "snmp")
        credentials = snmp.get("credentials", {})
        assert "::/0" in credentials, (
            "le fournisseur snmp doit couvrir '::/0' pour interroger "
            "automatiquement TOUT exportateur, sans avoir a le declarer."
        )

    def test_lordre_de_la_cascade_est_snmp_puis_static(self) -> None:
        """SNMP D'ABORD, sinon il n'est JAMAIS interrogé.

        Ce test exigeait l'ordre INVERSE, sur deux affirmations que
        l'expérience a démenties le 2026-08-08 :

          « le rafraîchissement du cache re-interroge tous les providers » —
          FAUX. `refreshCacheEntry` rejoue `queryProviders` À L'IDENTIQUE : la
          cascade repart du début et s'arrête au même provider. `static` en
          tête gagne éternellement.

          « SNMP en premier ferait jeter les flux (timeout = vraie erreur) » —
          FAUX. Mesuré : avec SNMP en tête, 7154 nouveaux flux ont bien été
          enregistrés. Aucun flux perdu.

        Le défaut réel, mesuré sur un VRAI agent SNMP (`snmpd`, sysName
        `routeur-test-01`) : son compteur `snmpInPkts` n'a pas bougé d'UNE
        requête pendant que l'outlet traitait 370 000 flux. `static` avec
        `"::/0"` accepte toutes les adresses, la cascade s'arrête sur lui.

        Le cache a été écarté comme cause : après un `down -v` (tous volumes
        détruits, stack neuf), l'agent restait non interrogé.

        Symptôme trompeur : aucun log, aucune erreur — seulement un nom de
        repli qu'on peut prendre pour un nom légitime. Zéro silencieux.
        """
        outlet = _charger_yaml(CONFIG_FILES["outlet"])
        types = [p.get("type") for p in _providers(outlet)]
        assert "static" in types and "snmp" in types
        assert types.index("snmp") < types.index("static"), (
            f"cascade dans le mauvais ordre : {types} — 'snmp' doit précéder "
            "'static'. Portant « ::/0 », `static` accepte toutes les adresses "
            "et la cascade s'arrête sur lui : SNMP ne serait jamais interrogé "
            "et les exportateurs garderaient le nom de repli pour toujours."
        )

    def test_le_static_ne_porte_pas_skip_missing_interfaces(self) -> None:
        """CAUSE MESUREE (2026-08-07, .7) : `default:` et
        `skip-missing-interfaces: true` sont MUTUELLEMENT EXCLUSIFS dans
        Akvorado — la validation officielle le déclare
        (`outlet/metadata/provider/static/config.go`, tag de validation
        `omitempty,excluded_with=SkipMissingInterfaces` sur le champ Default).
        Preuve par le code source (`outlet/metadata/provider/static/root.go`,
        fonction `Query`) : avec `SkipMissingInterfaces` a `true`, la fonction
        retourne `ErrSkipProvider` DES qu'un ifIndex est absent de
        `IfIndexes` — AVANT meme de regarder si `Default` est renseigne.
        Aucun ifIndex n'etant jamais declare ici, `static` saute TOUJOURS,
        `snmp` timeoute sur un exportateur sans agent actif (vraie erreur),
        et la cascade s'arrete sans jamais consulter `default:`. Mesure :
        100% des flux recus marques 'metadata missing'
        (`akvorado_outlet_core_flows_errors_total`), zero ligne inseree en
        ClickHouse. Le retrait de ce flag est ce qui rend `default:` reel."""
        outlet = _charger_yaml(CONFIG_FILES["outlet"])
        static = next(p for p in _providers(outlet) if p.get("type") == "static")
        exporters = static.get("exporters", {})
        cle_generique = next((k for k in exporters if k in ("::/0", "0.0.0.0/0")), None)
        assert cle_generique is not None, (
            "le static doit porter une entree generique ::/0 ou 0.0.0.0/0"
        )
        assert "skip-missing-interfaces" not in exporters[cle_generique], (
            "'skip-missing-interfaces' est present alors qu'il est "
            "MUTUELLEMENT EXCLUSIF avec 'default:' cote Akvorado — avec les "
            "deux ensemble, 'default:' n'est JAMAIS consulte (ErrSkipProvider "
            "est retourne avant), et un exportateur sans agent SNMP actif "
            "voit 100% de ses flux jetes des le premier ('metadata missing')."
        )

    def test_le_pourquoi_du_retrait_de_skip_missing_interfaces_est_documente(self) -> None:
        """Le piège doit être documenté LÀ où il s'applique, pas seulement
        dans un commentaire de tête — y compris pourquoi le flag a été
        retiré (sinon un futur exploitant pourrait le rajouter en pensant
        bien faire, réintroduisant le zéro silencieux mesuré)."""
        contenu = CONFIG_FILES["outlet"].read_text(encoding="utf-8")
        idx = contenu.find("metadata:")
        assert idx != -1, "section metadata absente d'outlet.yaml"
        bloc = contenu[idx : idx + 4000]
        assert re.search(r"skip-missing-interfaces", bloc), (
            "le piege 'skip-missing-interfaces incompatible avec default' "
            "doit rester documente au voisinage de metadata.providers, meme "
            "apres son retrait — sinon un futur exploitant pourrait le "
            "rajouter en pensant reproduire le comportement documente par "
            "la doc Akvorado generique"
        )
        assert re.search(r"(?i)cacherefresh|rafraich", bloc), (
            "le mecanisme qui compense le retrait du skip (rafraichissement "
            "periodique du cache, qui re-interroge snmp meme apres un hit "
            "'default:') doit etre documente au voisinage de "
            "metadata.providers"
        )


# ---------------------------------------------------------------------------
# 4. Zéro silencieux — repli qui empêche les flux d'être jetés
# ---------------------------------------------------------------------------


class TestRepliAntiFluxJetes:
    """La doc Akvorado : « Flows missing any interface information are
    discarded. » Sans repli, un routeur dont SNMP ne répond pas (pare-feu,
    mauvaise communauté) perd purement et simplement sa visibilite — sans la
    moindre alerte, à l'échelle de 350 routeurs. Le repli retenu : un
    `default:` GÉNÉRIQUE sur le fournisseur `static`, qui garantit qu'AUCUN
    exportateur ne se retrouve totalement sans résolution d'interface, même
    si SNMP échoue pour lui."""

    def test_le_static_porte_un_default_generique(self) -> None:
        outlet = _charger_yaml(CONFIG_FILES["outlet"])
        static = next(p for p in _providers(outlet) if p.get("type") == "static")
        exporters = static.get("exporters", {})
        cle_generique = next((k for k in exporters if k in ("::/0", "0.0.0.0/0")), None)
        assert cle_generique is not None
        assert "default" in exporters[cle_generique], (
            "sans 'default:' generique sur le static, un exportateur dont "
            "SNMP echoue (pare-feu, mauvaise communaute) voit TOUS ses flux "
            "jetes silencieusement (doc Akvorado : 'discarded')."
        )

    def test_le_risque_de_perte_de_flux_est_documente(self) -> None:
        """Le piège doit être écrit en clair : c'est un choix de conception,
        pas un détail — un lecteur qui n'a pas suivi cette session doit
        comprendre pourquoi ce repli existe."""
        contenu = CONFIG_FILES["outlet"].read_text(encoding="utf-8")
        assert re.search(r"(?i)jet[ée]|discard|perdu|silenc", contenu), (
            "le risque de perte silencieuse de flux (zero silencieux) doit "
            "etre documente dans outlet.yaml, au voisinage du repli qui "
            "l'empeche."
        )

    def test_le_name_de_lexportateur_est_pose_au_niveau_exporter_pas_dans_default(
        self,
    ) -> None:
        """CAUSE MESUREE (2026-08-07, .7, troisième défaut de la même chaîne) :
        `static.Query()` répondait bien `Found:true` via `default:` (les deux
        fix précédents avaient fonctionné), mais 100% des flux restaient
        marqués 'metadata missing'. Preuve par le code source Akvorado :

        - `ExporterConfiguration` (outlet/metadata/provider/static/config.go)
          inclut `provider.Exporter` en SQUASH — son champ `Name` (marqué
          `validate:"required"` dans `provider.Exporter`,
          outlet/metadata/provider/root.go) doit être posé au MÊME niveau que
          `default:`/`ifIndexes:`, PAS dedans. `default:` est un
          `provider.Interface` — un type DIFFÉRENT, qui ne porte que les
          attributs d'INTERFACE réseau (name/description/speed/boundary),
          jamais les attributs d'EXPORTATEUR.
        - `enricher.go` (`enrichFlow`) : `flowExporterName =
          answer.Exporter.Name` (PAS `answer.Interface.Name`) — puis
          `if flowExporterName == "" { ... "metadata missing" }`.

        Le piège n'est pas visible en YAML brut : les deux `name:` (celui de
        l'exportateur et celui de l'interface `default:`) ont la même syntaxe
        et la même clé, seule leur POSITION dans l'arbre YAML détermine à
        quel type Go ils sont mappés. Un `name:` posé au mauvais niveau
        produit un YAML parfaitement valide, une config acceptée par
        l'orchestrateur, et un `Found:true` — mais zéro ligne en ClickHouse.
        """
        outlet = _charger_yaml(CONFIG_FILES["outlet"])
        static = next(p for p in _providers(outlet) if p.get("type") == "static")
        exporters = static.get("exporters", {})
        cle_generique = next((k for k in exporters if k in ("::/0", "0.0.0.0/0")), None)
        assert cle_generique is not None
        exporter_config = exporters[cle_generique]
        assert exporter_config.get("name"), (
            "'name:' absent (ou vide) au niveau EXPORTATEUR (directement "
            "sous la clé generique, a cote de 'default:') — Akvorado exige "
            'Exporter.Name (validate:"required"). Sans lui, '
            "flowExporterName reste vide meme quand static repond Found:true "
            "via default:, et enrichFlow marque TOUS les flux "
            "'metadata missing' — zero ligne en ClickHouse malgre un repli "
            "'default:' apparemment correct."
        )
        # Le default: (attributs d'INTERFACE) ne doit pas etre confondu avec
        # le name de l'exportateur : les deux existent, a des niveaux
        # differents, avec des roles differents.
        assert exporter_config.get("default", {}).get("name"), (
            "'default.name' absent : sans lui, l'INTERFACE resolue par le "
            "repli n'a pas de nom lisible (distinct du nom d'exportateur)."
        )

    def test_le_garde_fou_mord_sur_le_defaut_de_placement_du_name(self, tmp_path: Path) -> None:
        """PREUVE QUE LE GARDE-FOU MORD : sabotage d'une copie temporaire qui
        reproduit exactement le défaut réel (`name:` posé UNIQUEMENT dans
        `default:`, absent au niveau exportateur), vérification de l'échec,
        puis restauration automatique (`tmp_path`, jamais le fichier réel)."""
        outlet_yaml = _charger_yaml(CONFIG_FILES["outlet"])
        static = next(p for p in _providers(outlet_yaml) if p.get("type") == "static")
        exporters = static.get("exporters", {})
        cle_generique = next(k for k in exporters if k in ("::/0", "0.0.0.0/0"))
        # Sabotage : retire le name du niveau exportateur (garde celui de
        # default:, exactement l'état réellement mesuré le 2026-08-07).
        assert exporters[cle_generique].pop("name", None), "rien a saboter — test invalide"

        saboté = tmp_path / "outlet.yaml"
        saboté.write_text(yaml.safe_dump(outlet_yaml), encoding="utf-8")

        outlet_saboté = _charger_yaml(saboté)
        static_saboté = next(p for p in _providers(outlet_saboté) if p.get("type") == "static")
        exporter_config = static_saboté["exporters"][cle_generique]
        assert not exporter_config.get("name"), (
            "le sabotage aurait du retirer 'name:' du niveau exportateur — "
            "s'il est encore present, le garde-fou ne mord pas et "
            "laisserait passer la regression reellement vecue le 2026-08-07 "
            "(100% des flux marques 'metadata missing' malgre un "
            "default: apparemment complet)"
        )
        # Le fichier reel du depot, lui, doit toujours porter le name.
        contenu_reel = _charger_yaml(CONFIG_FILES["outlet"])
        static_reel = next(p for p in _providers(contenu_reel) if p.get("type") == "static")
        assert static_reel["exporters"][cle_generique].get("name"), (
            "le fichier reel du depot a ete altere par ce test — le "
            "sabotage doit rester cantonne a tmp_path"
        )


# ---------------------------------------------------------------------------
# 5. Classification GÉNÉRIQUE, pas par IP
# ---------------------------------------------------------------------------


class TestClassificationGenerique:
    def test_aucune_regle_de_classification_ne_cible_une_ip(self) -> None:
        """`core.exporter-classifiers` / `interface-classifiers` doivent
        rester des règles GÉNÉRIQUES (regex sur nom, ASN, etc.) — jamais une
        IP en dur, qui reproduirait la déclaration nominative au niveau de
        la classification plutôt que des exportateurs."""
        outlet = _charger_yaml(CONFIG_FILES["outlet"])
        core = outlet.get("core", {})
        regles = list(core.get("exporter-classifiers", [])) + list(
            core.get("interface-classifiers", [])
        )
        for regle in regles:
            assert not _IP_CIDR_RE.search(str(regle)), (
                f"regle de classification avec IP en dur : {regle!r}"
            )


# ---------------------------------------------------------------------------
# 6. Rétention : brute courte, agrégats longs
# ---------------------------------------------------------------------------


class TestRetention:
    def test_un_reglage_de_retention_brute_est_expose_en_variable_env(self) -> None:
        """La rétention doit se régler AU DÉPLOIEMENT (`.env`), pas être
        figée dans un YAML versionné — le volume dépend du parc réel."""
        env_contenu = ENV_EXAMPLE.read_text(encoding="utf-8")
        assert re.search(r"RETENTION", env_contenu, re.IGNORECASE), (
            ".env.example doit exposer au moins un reglage de retention"
        )


# ---------------------------------------------------------------------------
# 7. Aucun secret en clair — la communauté SNMP est une référence d'env
# ---------------------------------------------------------------------------


class TestAucunSecretEnClair:
    def test_la_communaute_snmp_est_une_reference_environnement(self) -> None:
        outlet = _charger_yaml(CONFIG_FILES["outlet"])
        snmp = next(p for p in _providers(outlet) if p.get("type") == "snmp")
        communities = snmp["credentials"]["::/0"]["communities"]
        for communaute in communities:
            assert re.fullmatch(r"\$\{[A-Z_][A-Z0-9_]*\}", str(communaute)), (
                f"la communaute SNMP {communaute!r} n'est pas une reference "
                "d'environnement (${VAR}) — un secret ne doit JAMAIS etre "
                "ecrit en clair dans un YAML versionne."
            )

    def test_aucune_valeur_de_type_mot_de_passe_en_clair_dans_le_compose(self) -> None:
        """Tout `PASSWORD`/`TOKEN`/`SECRET`/`COMMUNITY` doit être résolu via
        `${VAR}` (interpolation compose), jamais une valeur littérale."""
        compose_texte = _sans_commentaires_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
        for ligne in compose_texte.splitlines():
            if re.search(r"(PASSWORD|_TOKEN|_SECRET|COMMUNITY)\s*[:=]", ligne, re.IGNORECASE):
                assert "${" in ligne or ligne.strip().endswith(":"), (
                    f"valeur potentiellement en clair dans le compose : {ligne!r}"
                )

    def test_env_example_ne_contient_aucun_secret_reel(self) -> None:
        """Un `.env.example` versionné ne doit porter QUE des placeholders /
        valeurs vides pour tout ce qui ressemble à un secret."""
        contenu = ENV_EXAMPLE.read_text(encoding="utf-8")
        for ligne in contenu.splitlines():
            if ligne.strip().startswith("#") or "=" not in ligne:
                continue
            cle, _, valeur = ligne.partition("=")
            if re.search(r"(PASSWORD|_TOKEN|_SECRET|COMMUNITY)$", cle.strip(), re.IGNORECASE):
                valeur = valeur.strip()
                assert valeur == "" or re.fullmatch(r"[a-z_\-]+", valeur), (
                    f"{cle.strip()} porte une valeur qui ressemble a un secret "
                    f"reel dans .env.example : {valeur!r} (attendu : vide ou "
                    "placeholder generique)"
                )


# ---------------------------------------------------------------------------
# 8. Le compose déclare bien le service grafana (conteneur d'un autre agent)
# ---------------------------------------------------------------------------


class TestServiceGrafanaDeclare:
    """Un autre agent construit les dashboards en parallèle : ce lot déclare
    SEULEMENT le conteneur dans le compose, sans écrire dans stack/grafana/."""

    def test_le_service_grafana_existe(self) -> None:
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        assert "grafana" in compose["services"], "aucun service 'grafana' declare dans le compose"

    def test_grafana_utilise_une_image_publique(self) -> None:
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        image = compose["services"]["grafana"].get("image", "")
        assert image.startswith("grafana/grafana"), f"image grafana inattendue : {image!r}"

    def test_grafana_monte_les_volumes_de_provisioning_et_dashboards(self) -> None:
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        volumes = compose["services"]["grafana"].get("volumes", [])
        volumes_texte = " ".join(str(v) for v in volumes)
        assert "grafana/provisioning" in volumes_texte, "volume de provisioning grafana absent"
        assert "grafana/dashboards" in volumes_texte, "volume de dashboards grafana absent"

    def test_les_dashboards_grafana_sont_livres_avec_le_stack(self) -> None:
        """Un Grafana sans dashboard ne remplit pas la promesse « clé en main ».

        Ce test a d'abord exigé l'INVERSE — que `stack/grafana/` soit VIDE —
        pour cloisonner deux lots construits en parallèle. C'était figer une
        frontière d'organisation interne, sans valeur pour l'exploitant : le
        test cassait au moment précis où le travail devenait complet.

        Ce qui compte réellement : l'utilisateur démarre le stack et trouve ses
        dashboards. Sans provisionnement, Grafana s'ouvre sur une page vide et
        il faut tout construire à la main — exactement le geste que ce projet
        supprime.
        """
        grafana_dir = STACK_DIR / "grafana"
        assert grafana_dir.is_dir(), "stack/grafana/ doit exister : Grafana est provisionné"

        dashboards = list((grafana_dir / "dashboards").glob("*.json"))
        assert dashboards, (
            "aucun dashboard sous stack/grafana/dashboards/ : Grafana démarrerait "
            "vide et l'exploitant devrait tout construire lui-même"
        )

        provisioning = grafana_dir / "provisioning"
        assert (provisioning / "datasources").is_dir(), (
            "la source de données ClickHouse doit être provisionnée : sans elle, "
            "les dashboards s'affichent en erreur"
        )
        assert (provisioning / "dashboards").is_dir(), (
            "le chargement automatique des dashboards doit être provisionné"
        )


# ---------------------------------------------------------------------------
# 9. Ports NetFlow/IPFIX/sFlow exposés en UDP + healthchecks + volumes nommés
# ---------------------------------------------------------------------------


class TestExpositionEtResilience:
    def test_les_ports_de_collecte_sont_exposes_en_udp(self) -> None:
        compose_texte = COMPOSE_FILE.read_text(encoding="utf-8")
        compose = yaml.safe_load(compose_texte)
        inlet = compose["services"].get("akvorado-inlet") or compose["services"].get("inlet")
        assert inlet is not None, "aucun service inlet trouve dans le compose"
        ports = " ".join(str(p) for p in inlet.get("ports", []))
        assert "udp" in ports.lower(), (
            "les ports de collecte NetFlow/IPFIX/sFlow doivent etre en UDP"
        )

    def test_la_persistance_va_dans_des_dossiers_du_projet(self) -> None:
        """Chaque service qui STOCKE des données persiste sous `./data/`.

        EXIGENCE UTILISATEUR (2026-08-08), qui REMPLACE la règle antérieure
        « volumes nommés » : « stockage et persistence dans des dossiers à la
        racine du projet ». Motif : un volume nommé vit dans les entrailles de
        Docker (`/var/lib/docker/volumes/...`), invisible à l'exploitant —
        sauvegarder, inspecter ou déplacer les données demande de connaître
        Docker. Un dossier `stack/data/clickhouse` se voit, se sauvegarde avec
        un `tar`, et se comprend sans documentation.

        Ce test remplace `test_clickhouse_et_grafana_ont_des_volumes_nommes`,
        qui imposait exactement l'inverse : ce n'est pas un garde-fou retiré,
        c'est la même protection retournée vers la nouvelle cible. Sans lui,
        rien n'empêcherait un retour silencieux aux volumes nommés.
        """
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))

        # Services qui écrivent des données devant survivre à un redémarrage.
        for service_nom, cible_attendue in (
            ("clickhouse", "/var/lib/clickhouse"),
            ("grafana", "/var/lib/grafana"),
            ("kafka", "/var/lib/kafka/data"),
            ("okvorado", "/data"),
        ):
            service = compose["services"].get(service_nom)
            assert service is not None, f"service {service_nom} absent du compose"

            montages = [v for v in service.get("volumes", []) if isinstance(v, str)]
            correspondants = [
                m for m in montages if m.split(":")[1:2] == [cible_attendue]
            ]
            assert correspondants, (
                f"{service_nom} ne monte rien sur {cible_attendue} : "
                "ses données ne survivraient pas à un `docker compose down`"
            )

            source = correspondants[0].split(":")[0]
            assert source.startswith("./data/"), (
                f"{service_nom} persiste sur '{source}' au lieu d'un dossier "
                "`./data/...` du projet. Exigence utilisateur : le stockage "
                "doit être visible et sauvegardable sans connaître Docker."
            )

    # Images dont l'ENTRYPOINT démarre nativement en uid 0 (root) et gère
    # LUI-MÊME le `chown`/la bascule d'utilisateur avant de lancer le vrai
    # process (ou reste root faute de `USER` déclaré dans son Dockerfile) —
    # vérifié par `docker image inspect <image> --format '{{.Config.User}}'`
    # (chaîne vide ou "0" = root), PAS supposé.
    #   - clickhouse/clickhouse-server : entrypoint root, chown natif vers
    #     l'uid `clickhouse` (101) avant de basculer dessus (voir commentaire
    #     de tête de ce fichier compose, section PERMISSIONS).
    #   - valkey/valkey (service `redis`) : idem, entrypoint officiel root.
    #   - quay.io/akvorado/akvorado : MESURÉ le 2026-08-09 —
    #     `docker image inspect quay.io/akvorado/akvorado:main --format
    #     '{{.Config.User}}'` renvoie `0`. Les 3 services akvorado-console/
    #     inlet/outlet qui montent `./data/okvorado` sur `/run/akvorado`
    #     héritent de cette image : indifférents à l'appartenance du dossier.
    #   - docker.io/library/alpine : MESURÉ le 2026-08-09 — `docker image
    #     inspect alpine:3.20 --format '{{.Config.User}}'` renvoie une
    #     chaîne VIDE (= root, aucun `USER` dans son Dockerfile amont).
    #     Utilisée par `config-generator` (monte `./data/grafana-alerting`)
    #     et par `okvorado-data-init` lui-même — les deux tournent donc déjà
    #     en root SANS qu'un `user: root` explicite soit nécessaire.
    # Cette liste n'exempte QUE l'écriture sur bind mount root:root — elle ne
    # dispense d'aucun autre garde-fou de ce fichier.
    _IMAGES_DEMARRANT_NATIVEMENT_EN_ROOT = (
        "clickhouse/clickhouse-server",
        "valkey/valkey",
        "quay.io/akvorado/akvorado",
        "docker.io/library/alpine",
    )

    @staticmethod
    def _image_par_defaut(image_brute: str) -> str:
        """Résout la valeur PAR DÉFAUT d'une image compose `${VAR:-defaut}`
        vers son nom sans tag — celle qui s'applique sans `.env` sur mesure.
        Même mécanisme que `test_toute_image_non_publique_est_construite_par_le_compose`
        (section 'Toute image non publique...' plus haut dans ce fichier) :
        comparer la chaîne BRUTE `${AKVORADO_IMAGE:-quay.io/...}` à
        `quay.io/akvorado/akvorado` ne matche jamais, l'interpolation compose
        doit être résolue en amont."""
        defaut = re.sub(r"\$\{[A-Z_]+:-([^}]*)\}", r"\1", image_brute)
        return defaut.split(":")[0]

    @classmethod
    def _services_sans_couverture_ecriture(cls, compose: dict[str, Any]) -> list[str]:
        """Cœur du garde-fou, FACTORISÉ pour être appelable à la fois sur le
        compose réel du dépôt et sur une copie SABOTÉE en mémoire (preuve que
        le garde-fou mord, voir le test `_le_garde_fou_mord_...` ci-dessous) :
        aucune duplication de logique entre « ça doit passer » et « ça doit
        échouer », qui serait elle-même une source de divergence silencieuse.

        Retourne la liste des noms de services montant un bind mount
        `./data/...` sans AUCUN des 3 mécanismes de couverture reconnus.
        """
        services = compose["services"]

        # Étape 1 — pour chaque service d'INIT (`restart: "no"` + `command`
        # qui invoque `chown`), les SOURCES hôte (`./data/...`) qu'il chowne
        # réellement — en croisant ses propres bind mounts avec les chemins
        # CONTENEUR passés en argument à `chown` dans sa commande (ex:
        # `okvorado-data-init` chowne `/data`, monté depuis `./data/okvorado`).
        # Résultat : {nom_du_service_init: {sources hôte couvertes}}.
        init_vers_sources_couvertes: dict[str, set[str]] = {}
        for nom, service in services.items():
            if service.get("restart") != "no":
                continue
            commande = service.get("command")
            arguments = commande if isinstance(commande, list) else str(commande or "").split()
            if not any(str(a) == "chown" for a in arguments):
                continue
            chemins_conteneur = {a for a in arguments if isinstance(a, str) and a.startswith("/")}
            sources = {
                source
                for source, cible in cls._cible_bind_mounts(service)
                if cible in chemins_conteneur
            }
            if sources:
                init_vers_sources_couvertes[nom] = sources

        def _depend_dun_init_qui_couvre(service: dict[str, Any], sources: set[str]) -> bool:
            """Le service DÉPEND-il (depends_on + service_completed_successfully,
            seule garantie d'ORDRE — sans elle rien n'empêche le conteneur de
            démarrer AVANT le chown) d'un service d'init qui chowne au moins
            une des sources hôte que `service` monte ?"""
            depends_on = service.get("depends_on") or {}
            if not isinstance(depends_on, dict):
                return False
            for nom_init, sources_couvertes in init_vers_sources_couvertes.items():
                condition = depends_on.get(nom_init, {}).get("condition")
                if condition == "service_completed_successfully" and sources & sources_couvertes:
                    return True
            return False

        # Étape 2 — DÉCOUVERTE AUTOMATIQUE : chaque service (hors services
        # d'init eux-mêmes) qui monte au moins un bind mount `./data/...`
        # doit être couvert par l'un des 3 mécanismes.
        non_couverts: list[str] = []
        for nom, service in services.items():
            if nom in init_vers_sources_couvertes:
                continue  # un service d'init n'a pas besoin d'écrire ailleurs

            paires = cls._cible_bind_mounts(service)
            if not paires:
                continue  # ne monte aucun bind mount `./data/...`

            if str(service.get("user", "")) == "root":
                continue  # mécanisme 1 : tourne en root

            image = str(service.get("image", ""))
            image_defaut = cls._image_par_defaut(image)
            image_native_root = image_defaut in cls._IMAGES_DEMARRANT_NATIVEMENT_EN_ROOT
            if "build" not in service and image_native_root:
                continue  # mécanisme 2 : image connue, démarre nativement en root (mesuré)

            sources = {source for source, _cible in paires}
            if _depend_dun_init_qui_couvre(service, sources):
                continue  # mécanisme 3 : dépend d'un service d'init qui chowne cette source

            non_couverts.append(nom)

        return non_couverts

    @staticmethod
    def _cible_bind_mounts(service: dict[str, Any]) -> list[tuple[str, str]]:
        """Liste des (source, cible) pour chaque bind mount `./data/...` d'un
        service — la SOURCE (pas seulement la cible) sert à faire correspondre
        un service d'init qui prépare le MÊME dossier hôte, potentiellement
        monté sur une cible différente (ex: `/data` pour okvorado vs
        `/run/akvorado` pour les 3 services akvorado-*)."""
        paires = []
        for v in service.get("volumes", []):
            if not isinstance(v, str) or not v.startswith("./data/"):
                continue
            morceaux = v.split(":")
            if len(morceaux) >= 2:
                paires.append((morceaux[0], morceaux[1]))
        return paires

    def test_les_services_qui_ecrivent_sur_bind_mount_peuvent_le_faire(self) -> None:
        """GARDE-FOU MÉCANIQUE — motif corrigé 3 fois (règle CLAUDE.md
        « un motif corrigé ≥3 fois n'est plus un bug, c'est un défaut de
        conception »), donc plus question de coder une liste de services en
        dur : ce test DÉCOUVRE AUTOMATIQUEMENT tous les services montant un
        bind mount `./data/...` et vérifie que CHACUN a un mécanisme pour y
        écrire. Une 4ᵉ occurrence future — un nouveau service ajouté à ce
        compose avec un bind mount et un uid non privilégié — DOIT échouer
        ici, sans que quiconque ait pensé à l'ajouter à une liste.

        LES TROIS OCCURRENCES RÉELLEMENT VÉCUES DU MÊME DÉFAUT, toutes issues
        du même mécanisme (Docker crée `./data/...` en `root:root` 0755 au
        premier `up`, un entrypoint qui démarre directement en uid non
        privilégié ne peut pas y écrire) :

          1. kafka (2026-08-08) : image démarre en uid 1000 (`appuser`),
             AUCUN chown natif —
                 java.nio.file.AccessDeniedException:
                 /var/lib/kafka/data/bootstrap.checkpoint.tmp
             → conteneur `unhealthy`, TOUT le stack bloqué en cascade
               (« dependency failed to start »).
             CORRIGÉ PAR : `user: root` (l'image gère alors ses droits seule,
             comme clickhouse/valkey le font nativement).

          2. grafana (2026-08-08) : image démarre en uid 472, doit CRÉER un
             sous-répertoire (`plugins/`) —
                 mkdir: can't create directory '/var/lib/grafana/plugins':
                 Permission denied
             → `Restarting` en boucle, interface d'analyse totalement
               indisponible.
             CORRIGÉ PAR : `user: root`, même parade que kafka.

          3. okvorado (2026-08-09, ce chantier) : image construite par ce
             dépôt (Dockerfile racine, `useradd --uid 10001 okvorado`,
             `USER okvorado`) —
                 sqlite3.OperationalError: unable to open database file
             → HTTP 500 à l'écran, sur la page de connexion (premier geste
               de tout exploitant). Les 1650 tests existants étaient VERTS :
               ce défaut n'apparaît qu'à l'écran, jamais dans un test
               statique — exactement pourquoi ce garde-fou doit rester
               MÉCANIQUE et AUTOMATIQUE plutôt que reposer sur la vigilance.
             CORRIGÉ PAR : PAS `user: root` (annulerait le durcissement
             délibéré du Dockerfile pour une appli qui accepte des entrées
             utilisateur, voir CLAUDE.md racine section Sécurité) — un
             service d'init dédié `okvorado-data-init` qui `chown -R
             10001:10001 /data` avant qu'`okvorado` ne démarre
             (`depends_on: condition: service_completed_successfully`,
             même motif que `config-generator`).

        POURQUOI CE TEST EXISTE (méthode) : une vérification isolée avait
        conclu à tort que Grafana passait — elle testait l'écriture d'un
        fichier, pas la CRÉATION d'un sous-répertoire, le geste réel du
        conteneur au démarrage. Aucun test statique ne remplace un `up -d`
        réel (voir section 3 de ce rapport pour la preuve sur machine nue),
        mais celui-ci empêche au moins la régression SILENCIEUSE : retirer la
        protection d'un service casserait le démarrage sur toute machine
        neuve, sans qu'aucun des 1650+ tests existants ne le détecte s'il
        n'était pas là.
        """
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        non_couverts = self._services_sans_couverture_ecriture(compose)

        assert not non_couverts, (
            f"Ces services montent un bind mount `./data/...` sans AUCUN "
            f"mécanisme leur permettant d'y écrire : {non_couverts}. Docker "
            "crée toujours le dossier hôte cible d'un bind mount en "
            "`root:root` 0755 au premier `up` — un entrypoint qui démarre "
            "en uid non privilégié (sans chown natif) échoue à y écrire. "
            "Symptômes réellement mesurés selon le service concerné : "
            "kafka -> `java.nio.file.AccessDeniedException` (conteneur "
            "unhealthy, stack bloqué en cascade) ; grafana -> `mkdir: "
            "can't create directory ... Permission denied` (Restarting en "
            "boucle) ; okvorado -> `sqlite3.OperationalError: unable to "
            "open database file` (HTTP 500 à l'écran, sur la page de "
            "connexion). Parade : soit `user: root` si l'image n'a pas de "
            "raison de rester non privilégiée, soit (préférable si "
            "l'image durcit délibérément son utilisateur, ex: Dockerfile "
            "avec `USER <non-root>`) un service d'init dédié qui `chown` "
            "le dossier vers le bon uid AVANT le démarrage, référencé via "
            "`depends_on: <service>: condition: service_completed_successfully`."
        )

    def test_le_garde_fou_mord_sur_le_cas_okvorado_reellement_vecu(self) -> None:
        """PREUVE QUE LE GARDE-FOU MORD (motif déjà suivi par ce fichier,
        ex: `test_le_garde_fou_mord_sur_le_cas_reellement_vecu` plus haut) :
        sabotage EN MÉMOIRE du compose réel (retrait de la dépendance
        `okvorado -> okvorado-data-init`, exactement l'état du dépôt AVANT ce
        chantier — le service d'init existait alors même pas), vérification
        que la découverte automatique détecte bien `okvorado` comme
        non-couvert. Aucune écriture disque : `yaml.safe_load` est rejoué sur
        le texte réel, jamais le fichier du dépôt n'est modifié."""
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))

        # État AVANT correction : okvorado ne dépend pas encore de
        # okvorado-data-init (le service d'init lui-même peut rester déclaré
        # ou non, seule la DÉPENDANCE compte pour la garantie d'ordre).
        okvorado = compose["services"]["okvorado"]
        depends_on_avant = dict(okvorado.get("depends_on") or {})
        assert "okvorado-data-init" in depends_on_avant, (
            "précondition invalide : le compose réel du dépôt ne dépend déjà "
            "plus de okvorado-data-init — rien à saboter, ce test ne prouve "
            "plus rien"
        )
        okvorado["depends_on"] = {
            k: v for k, v in depends_on_avant.items() if k != "okvorado-data-init"
        }
        assert okvorado["depends_on"] != depends_on_avant, (
            "le sabotage n'a rien retiré — test invalide"
        )

        non_couverts = self._services_sans_couverture_ecriture(compose)
        assert "okvorado" in non_couverts, (
            "le sabotage aurait dû faire réapparaître 'okvorado' dans la "
            "liste des services non couverts — s'il n'y est pas, le "
            "garde-fou ne mord pas et laisserait passer la régression "
            "réellement vécue le 2026-08-09 (sqlite3.OperationalError: "
            "unable to open database file -> HTTP 500 sur la page de "
            "connexion, alors que les 1650 tests existants restaient verts)"
        )

        # Le fichier réel du dépôt, lui, doit toujours porter la dépendance :
        # preuve que le sabotage a opéré sur une copie en mémoire, pas
        # l'original.
        compose_reel = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        depends_on_reel = compose_reel["services"]["okvorado"].get("depends_on") or {}
        assert "okvorado-data-init" in depends_on_reel, (
            "le fichier réel du dépôt a été altéré par ce test — régression "
            "de méthode, le sabotage doit rester cantonné à une copie en mémoire"
        )
        assert not self._services_sans_couverture_ecriture(compose_reel), (
            "le compose RÉEL du dépôt échoue le garde-fou — corrige "
            "docker-compose.yml avant de considérer ce chantier terminé"
        )

    def test_le_garde_fou_mord_si_un_service_futur_tourne_en_uid_non_privilegie_sans_protection(
        self,
    ) -> None:
        """PREUVE QUE LA DÉCOUVERTE EST AUTOMATIQUE, pas une liste figée : un
        service HYPOTHÉTIQUE, jamais vu par ce fichier de test auparavant,
        montant un bind mount `./data/...` sans `user: root` ni dépendance
        d'init ni appartenance à `_IMAGES_DEMARRANT_NATIVEMENT_EN_ROOT`, DOIT
        être détecté — exactement le scénario qui a laissé passer okvorado
        (un service nouveau, non anticipé par une liste en dur `('kafka',
        'grafana')`, comme l'ancienne version de ce test le faisait)."""
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        compose["services"]["futur-service-non-protege"] = {
            "image": "example.org/un-service-jamais-vu:1.0",
            "volumes": ["./data/futur-service:/var/lib/futur-service"],
        }
        non_couverts = self._services_sans_couverture_ecriture(compose)
        assert "futur-service-non-protege" in non_couverts, (
            "un service totalement inconnu de ce fichier de test, montant un "
            "bind mount `./data/...` sans aucune protection, n'a PAS été "
            "détecté — la découverte n'est plus automatique, régression du "
            "défaut de conception que ce garde-fou corrige (liste en dur "
            "kafka/grafana qui a laissé passer okvorado)"
        )

    def test_aucun_volume_nomme_ne_subsiste(self) -> None:
        """Aucun volume Docker nommé ne doit rester déclaré.

        Corollaire du test précédent, et défaut RÉELLEMENT VÉCU pendant la
        conversion (2026-08-08) : la section `volumes:` de haut niveau avait
        été supprimée alors que 5 services y référaient encore leurs
        montages — `docker compose config` échouait avec « refers to undefined
        volume okvorado-data ». Un compose invalide ne démarre pas du tout,
        et l'erreur n'apparaît qu'au `up`, jamais à la lecture du fichier.
        """
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        declares = set(compose.get("volumes", {}) or {})
        assert not declares, (
            f"volumes nommés encore déclarés : {sorted(declares)} — la "
            "persistance doit passer exclusivement par `./data/...`"
        )

        # Et surtout : aucun service ne doit référencer un volume nommé,
        # sinon le compose est invalide (cas mesuré ci-dessus).
        for service_nom, service in compose["services"].items():
            for montage in service.get("volumes", []):
                if not isinstance(montage, str):
                    continue
                source = montage.split(":")[0]
                est_un_chemin = source.startswith((".", "/", "~"))
                assert est_un_chemin, (
                    f"{service_nom} référence le volume nommé '{source}', "
                    "qui n'est plus déclaré : `docker compose config` "
                    "échouerait avec « refers to undefined volume »"
                )

    def test_les_services_critiques_ont_un_healthcheck(self) -> None:
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        for service_nom in ("clickhouse", "kafka"):
            service = compose["services"].get(service_nom)
            assert service is not None, f"service {service_nom} absent"
            assert "healthcheck" in service, f"{service_nom} n'a pas de healthcheck"

    def test_toutes_les_variables_denvironnement_ont_un_defaut_fonctionnel(self) -> None:
        """`${VAR}` sans défaut échoue silencieusement à l'interpolation
        compose (chaîne vide) — `${VAR:-defaut}` garantit un démarrage
        fonctionnel même sans `.env` personnalisé."""
        # Hors commentaires : un commentaire qui CITE '${VAR}' comme exemple
        # (pour expliquer la regle elle-meme) n'est pas une reference reelle
        # du compose — piege deja documente en tete de ce fichier.
        compose_texte = _sans_commentaires_compose(COMPOSE_FILE.read_text(encoding="utf-8"))
        # On exclut les references a des SECRETS (SNMP_COMMUNITY) qui n'ont
        # legitimement pas de defaut fonctionnel a fournir en clair.
        variables_sans_defaut = [
            m
            for m in re.findall(r"\$\{([A-Z_][A-Z0-9_]*)\}", compose_texte)
            if "COMMUNITY" not in m
            and "PASSWORD" not in m
            and "TOKEN" not in m
            and "SECRET" not in m
        ]
        assert not variables_sans_defaut, (
            f"variables sans defaut ('${{VAR}}' au lieu de '${{VAR:-defaut}}') : "
            f"{sorted(set(variables_sans_defaut))} — le stack ne demarrerait pas "
            "proprement sans .env personnalise."
        )


# ---------------------------------------------------------------------------
# 10. Validation réelle par `docker compose config` (si docker disponible)
# ---------------------------------------------------------------------------


class TestDockerComposeConfig:
    def test_docker_compose_config_valide_le_fichier(self) -> None:
        """Validation par le MOTEUR réel, pas seulement par un parseur YAML
        générique : un compose peut être du YAML valide et pourtant invalide
        pour Docker (clé inconnue, type de service incorrect, etc.)."""
        if shutil.which("docker") is None:
            pytest.skip("docker indisponible dans cet environnement de test")

        resultat = subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), "config", "--quiet"],
            capture_output=True,
            text=True,
            cwd=str(STACK_DIR),
            timeout=60,
        )
        assert resultat.returncode == 0, (
            f"docker compose config a echoue :\nstdout={resultat.stdout}\nstderr={resultat.stderr}"
        )


# ---------------------------------------------------------------------------
# 11. Le README documente la procédure clé en main
# ---------------------------------------------------------------------------


class TestReadme:
    def test_le_readme_couvre_les_etapes_cle_en_main(self) -> None:
        contenu = README.read_text(encoding="utf-8").lower()
        for etape in ("démarr", "routeur", "snmp", "vérif"):
            assert etape in contenu, f"le README ne mentionne pas : {etape}"

    def test_le_readme_ne_mentionne_aucune_adherence_homelab(self) -> None:
        contenu = _sans_commentaires_yaml(README.read_text(encoding="utf-8"))
        for motif in MOTIFS_HOMELAB:
            assert motif not in contenu.lower(), (
                f"le README mentionne '{motif}' (adherence homelab)"
            )


# ---------------------------------------------------------------------------
# 12. Le test MORD — sabotage puis restauration, pour chaque garde-fou central
# ---------------------------------------------------------------------------


class TestLesGardesFousMordent:
    """Preuve que les tests ci-dessus DÉTECTERAIENT une régression, et pas
    seulement qu'ils passent sur un fichier déjà correct. Chaque cas sabote
    une copie temporaire (jamais le fichier réel), vérifie l'échec, puis la
    fixture `tmp_path` restaure automatiquement — aucun état résiduel."""

    def test_une_ip_de_routeur_en_dur_fait_echouer_le_garde_fou_central(
        self, tmp_path: Path
    ) -> None:
        saboté = tmp_path / "outlet.yaml"
        contenu = CONFIG_FILES["outlet"].read_text(encoding="utf-8")
        # On injecte une entree nominative dans le fournisseur static.
        outlet_yaml = yaml.safe_load(contenu)
        static = next(p for p in outlet_yaml["metadata"]["providers"] if p["type"] == "static")
        static["exporters"]["203.0.113.42/32"] = {"default": {"name": "routeur-sabote"}}
        saboté.write_text(yaml.safe_dump(outlet_yaml), encoding="utf-8")

        adresses = _adresses_ipv4_hors_commentaires(saboté)
        assert adresses, "le sabotage aurait du introduire une IP detectable"
        assert "203.0.113.42/32" in adresses

    def test_une_cascade_inversee_fait_echouer_le_garde_fou_dordre(self) -> None:
        """Le sabotage doit produire l'ordre FAUTIF : `static` avant `snmp`.

        Sens rétabli le 2026-08-08 : ce test inversait vers `snmp` en tête, qui
        est désormais l'ordre CORRECT — il sabotait donc vers le bon état et ne
        prouvait plus rien.
        """
        outlet_yaml = _charger_yaml(CONFIG_FILES["outlet"])
        providers = outlet_yaml["metadata"]["providers"]
        providers.reverse()  # sabotage : ramène `static` en tête
        types = [p.get("type") for p in providers]
        assert not (
            "static" in types and "snmp" in types and types.index("snmp") < types.index("static")
        ), "l'inversion aurait dû casser l'ordre attendu par le garde-fou"

    def test_une_communaute_en_clair_fait_echouer_le_garde_fou_secret(self) -> None:
        assert not re.fullmatch(r"\$\{[A-Z_][A-Z0-9_]*\}", "public"), (
            "une communaute litterale comme 'public' doit etre detectee "
            "comme un secret en clair par le garde-fou dedie"
        )

    def test_un_motif_homelab_injecte_est_detecte_hors_commentaire(self) -> None:
        contenu = "reseau:\n  hote: proxy-frontal.example.fr\n"
        nettoye = _sans_commentaires_yaml(contenu)
        assert "proxy-frontal" in nettoye.lower() and "example" in nettoye.lower(), (
            "le nettoyage de commentaires ne doit PAS retirer un motif "
            "homelab ecrit dans du contenu reel (hors commentaire)"
        )

    def test_un_yaml_invalide_est_rejete_par_le_parseur(self) -> None:
        with pytest.raises(yaml.YAMLError):
            yaml.safe_load("clef: [valeur non fermee\n  autre: 1")


# ---------------------------------------------------------------------------
# Toute image non publique doit être CONSTRUCTIBLE depuis le dépôt
# ---------------------------------------------------------------------------


def test_toute_image_non_publique_est_construite_par_le_compose() -> None:
    """Un service dont l'image n'existe nulle part empêche le stack de démarrer.

    DÉFAUT MESURÉ (2026-08-07) en montant ce stack sur une machine VIERGE — le
    seul geste qui pouvait le révéler. Le service `okvorado` déclarait
    `image: okvorado:latest` sans `build:`. Résultat au démarrage :

        pull access denied for okvorado, repository does not exist

    Le stack ne démarrait pas DU TOUT en entreprise, alors que le compose était
    syntaxiquement valide (`docker compose config` passait) et que 1192 tests
    étaient verts. La promesse « clé en main » tombait au premier `up`.

    Règle : une image absente des registres publics DOIT porter un `build:`,
    sinon le déploiement suppose une étape manuelle préalable — exactement ce
    que ce projet supprime.
    """
    compose = yaml.safe_load((STACK_DIR / "docker-compose.yml").read_text(encoding="utf-8"))

    # Registres publics : ces images se téléchargent sans authentification.
    prefixes_publics = ("quay.io/", "docker.io/", "ghcr.io/")
    editeurs_publics = ("grafana/", "clickhouse/", "apache/", "valkey/", "redis/", "bitnami/")

    a_construire: list[str] = []
    for nom, service in (compose.get("services") or {}).items():
        image = str(service.get("image", ""))
        if not image:
            continue
        # Une variable d'environnement peut pointer un registre interne : on
        # regarde la valeur par défaut, celle qui s'applique sans .env sur mesure.
        defaut = re.sub(r"\$\{[A-Z_]+:-([^}]*)\}", r"\1", image)
        publique = defaut.startswith(prefixes_publics) or defaut.startswith(editeurs_publics)
        if not publique and "build" not in service:
            a_construire.append(f"{nom} -> {defaut}")

    assert not a_construire, (
        "Ces services réclament une image absente des registres publics SANS "
        f"savoir la construire : {a_construire}. `docker compose up` échouerait "
        "sur « pull access denied » et le stack ne démarrerait pas. Ajoute une "
        "section `build:` pointant le Dockerfile du dépôt."
    )


# ---------------------------------------------------------------------------
# Les tags d'image doivent EXISTER dans les registres publics
# ---------------------------------------------------------------------------


def test_aucun_tag_d_image_ne_ressemble_a_un_build_local() -> None:
    """Un tag fabriqué localement n'existe pour personne d'autre.

    DÉFAUT MESURÉ (2026-08-07) sur une machine vierge — invisible autrement :

        manifest for apache/kafka:4.3.1-cvefix not found: manifest unknown

    Ce tag n'a JAMAIS été publié sur Docker Hub (tags réels vérifiés à la
    source : latest, 4.3.1, 4.3.0, 4.2.1). C'était un tag LOCAL à la machine de
    qualification, construit six jours plus tôt. Le stack démarrait donc chez
    nous par le seul effet du cache d'images local, et échouait partout ailleurs.

    C'est le pire type d'adhérence : rien dans le fichier ne trahit le problème,
    `docker compose config` valide, et le service tourne — sur LA machine où
    l'image a été fabriquée.

    Ce test ne peut pas interroger les registres (pas de réseau garanti en CI).
    Il refuse donc les SUFFIXES qui signent une fabrication maison. Le contrôle
    complet reste le montage sur machine vierge, documenté dans stack/README.md.
    """
    compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))

    # Suffixes qui ne viennent jamais d'une publication amont officielle.
    suffixes_suspects = ("-cvefix", "-local", "-custom", "-patched", "-fix", "-maison")

    fautifs: list[str] = []
    for nom, service in (compose.get("services") or {}).items():
        image = str(service.get("image", ""))
        if not image or "build" in service:
            continue  # image construite depuis le dépôt : légitime
        tag = image.rsplit(":", 1)[-1] if ":" in image else ""
        if any(tag.endswith(suffixe) for suffixe in suffixes_suspects):
            fautifs.append(f"{nom} -> {image}")

    assert not fautifs, (
        f"Ces images portent un tag qui sent le build local : {fautifs}. "
        "Un tag absent des registres publics fait échouer `docker compose up` "
        "sur « manifest unknown » partout sauf sur la machine qui l'a fabriqué. "
        "Utilise un tag réellement publié en amont."
    )


# ---------------------------------------------------------------------------
# `dimensions` et `homepage-top-widgets` : DEUX conventions de nommage
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# 13. Le répertoire /usr/share/GeoIP doit TOUJOURS exister dans l'outlet
# ---------------------------------------------------------------------------


class TestVolumeGeoipToujoursPresent:
    """DÉFAUT MESURÉ (2026-08-07) sur `.7`, machine vierge — invisible par tous
    les tests précédents et par le statut du conteneur lui-même.

    `docker compose logs akvorado-outlet` s'arrête net après « starting GeoIP
    component » / « cannot watch database directory », SANS JAMAIS logguer
    « starting new client » ni « joining group » (les logs du vrai démarrage
    des workers Kafka). Le conteneur reste pourtant `Up (healthy)`
    indéfiniment : le healthcheck natif (`akvorado healthcheck`) ne vérifie
    que le serveur HTTP interne, pas la consommation Kafka — un ZÉRO
    SILENCIEUX exact. Conséquence mesurée : `kafka-consumer-groups.sh --list`
    ne rend AUCUN groupe, `SELECT count() FROM default.flows` reste à 0.

    CAUSE, prouvée en lisant le code source Akvorado (outlet/geoip/root.go,
    fonction Start()) : `geoip.optional: true` protège UNIQUEMENT l'ouverture
    des fichiers `.mmdb` eux-mêmes (bloc `openDatabase`, condition
    `!c.config.Optional`). L'appel `fsnotify.Watcher.Add(dir)` sur le
    RÉPERTOIRE PARENT, juste après, n'est PAS couvert par cette condition —
    c'est un bug upstream. Si `/usr/share/GeoIP` n'existe pas du tout dans le
    conteneur (aucun volume monté dessus), `watcher.Add()` échoue avec « no
    such file or directory » et `Start()` retourne cette erreur. Le run-group
    de l'outlet annule alors tout le démarrage en cascade — stoppant
    kafkainput, déjà démarré — AVANT d'atteindre le composant `networks` (qui
    dépend de `geoip`) puis `core`, seul point d'appel de
    `kafkainput.StartWorkers()` (le vrai démarrage des workers Kafka).

    POURQUOI AUCUN TEST EXISTANT NE LE VOYAIT : la config YAML elle-même est
    parfaitement valide (`geoip.optional: true` est bien présent et bien
    structuré — testé et vert), `docker compose config` passe, et le
    conteneur affiche `healthy`. Seul le fait de monter le stack pour de vrai
    et de lire les logs JSON de l'outlet jusqu'au bout révèle l'arrêt en
    cascade. La cause n'est pas dans un fichier de `stack/config/` mais dans
    l'ABSENCE d'un volume sur `stack/docker-compose.yml`.

    CORRECTIF : un volume nommé `geoip-data` monté sur `/usr/share/GeoIP`
    dans `akvorado-outlet`. Docker crée toujours le répertoire cible d'un
    volume nommé, même vide — suffisant pour que `watcher.Add()` réussisse
    sans qu'aucune base MaxMind/IPinfo réelle ne soit fournie.
    """

    def test_akvorado_outlet_monte_un_volume_sur_usr_share_geoip(self) -> None:
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        outlet = compose["services"].get("akvorado-outlet")
        assert outlet is not None, "service akvorado-outlet absent du compose"
        volumes = outlet.get("volumes", [])
        cibles = [str(v).split(":")[1] if ":" in str(v) else "" for v in volumes]
        assert "/usr/share/GeoIP" in cibles, (
            "akvorado-outlet ne monte AUCUN volume sur /usr/share/GeoIP — sans "
            "ce répertoire, fsnotify.Watcher.Add() (outlet/geoip/root.go) fait "
            "échouer Start() avec 'no such file or directory', un cas NON "
            "couvert par geoip.optional: true. Le run-group de l'outlet annule "
            "alors tout le démarrage en cascade, stoppant kafkainput avant "
            "même que les workers Kafka ne démarrent (StartWorkers() n'est "
            "jamais appelé) — zéro silencieux mesuré le 2026-08-07 : le "
            "conteneur reste 'healthy' mais ne consomme jamais Kafka et "
            "ClickHouse reste vide."
        )

    def test_le_montage_geoip_cree_le_repertoire_sans_geste_manuel(self) -> None:
        """Le montage GeoIP doit garantir l'EXISTENCE du répertoire au `up`,
        sans aucune préparation manuelle.

        C'est la propriété qui compte — pas la forme du montage. Deux formes
        la satisfont, et le choix a changé le 2026-08-08 :
          - un volume NOMMÉ (choix historique) ;
          - un BIND MOUNT `./data/geoip` (choix actuel, exigence utilisateur
            « stockage et persistence dans des dossiers à la racine du
            projet ») — Docker crée TOUJOURS le répertoire hôte cible d'un
            bind mount s'il n'existe pas, au moment du `up`.

        Ce qui reste INTERDIT : un chemin ABSOLU hors du projet
        (`/opt/geoip`, `/mnt/...`), qui supposerait que l'exploitant l'ait
        créé avant — exactement la préparation manuelle que ce stack
        supprime. Le piège protégé ici est mesuré (2026-08-07) : répertoire
        absent → `fsnotify.Watcher.Add()` échoue → tout le run-group de
        l'outlet meurt, conteneur 'healthy' qui ne consomme RIEN.
        """
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        outlet = compose["services"]["akvorado-outlet"]
        cible_geoip = next(
            (
                v
                for v in outlet.get("volumes", [])
                if isinstance(v, str) and v.endswith(":/usr/share/GeoIP")
            ),
            None,
        )
        assert cible_geoip is not None, "aucun volume ne cible /usr/share/GeoIP"

        source = cible_geoip.split(":")[0]
        declares = set(compose.get("volumes", {}) or {})
        est_volume_nomme = source in declares
        est_dossier_du_projet = source.startswith("./")

        assert est_volume_nomme or est_dossier_du_projet, (
            f"'{source}' monté sur /usr/share/GeoIP n'est ni un volume nommé "
            "déclaré, ni un dossier `./...` du projet. Un chemin absolu hôte "
            "supposerait que l'exploitant l'ait créé À LA MAIN avant le `up` "
            "— sans quoi l'outlet démarre 'healthy' et ne consomme jamais "
            "aucun flux (zéro silencieux mesuré le 2026-08-07)."
        )

    def test_le_defaut_reel_est_documente_au_voisinage_du_volume(self) -> None:
        """Le piège doit être écrit en clair là où il s'applique — pas
        seulement dans ce fichier de test."""
        contenu = COMPOSE_FILE.read_text(encoding="utf-8")
        idx = contenu.find("geoip-data")
        assert idx != -1, "le volume geoip-data n'apparaît pas dans le compose"
        bloc = contenu[max(0, idx - 3000) : idx + 500]
        assert re.search(r"(?i)watcher\.add|fsnotify|cannot watch database", bloc), (
            "la cause réelle (fsnotify.Watcher.Add qui échoue sans le "
            "répertoire) doit être documentée au voisinage du volume "
            "geoip-data dans docker-compose.yml"
        )

    def test_le_garde_fou_mord_sur_le_cas_reellement_vecu(self, tmp_path: Path) -> None:
        """PREUVE QUE LE GARDE-FOU MORD : sabotage d'une copie temporaire du
        compose SANS le volume geoip-data sur akvorado-outlet (exactement
        l'état mesuré sur `.7` avant correction), vérification de la
        détection, puis restauration automatique (`tmp_path`, jamais le
        fichier réel — le compose du dépôt n'est jamais modifié par ce test)."""
        compose = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        outlet = compose["services"]["akvorado-outlet"]
        volumes_avant = list(outlet.get("volumes", []))
        # Sabotage : retire précisément le montage GeoIP, reproduisant l'état
        # du compose AVANT ce correctif.
        outlet["volumes"] = [
            v for v in volumes_avant if not (isinstance(v, str) and v.endswith(":/usr/share/GeoIP"))
        ]
        assert outlet["volumes"] != volumes_avant, "le sabotage n'a rien retiré — test invalide"

        saboté = tmp_path / "docker-compose.yml"
        saboté.write_text(yaml.safe_dump(compose), encoding="utf-8")

        compose_saboté = yaml.safe_load(saboté.read_text(encoding="utf-8"))
        outlet_saboté = compose_saboté["services"]["akvorado-outlet"]
        volumes = outlet_saboté.get("volumes", [])
        cibles = [str(v).split(":")[1] if ":" in str(v) else "" for v in volumes]
        assert "/usr/share/GeoIP" not in cibles, (
            "le sabotage aurait dû retirer le montage /usr/share/GeoIP — s'il "
            "est encore présent, le garde-fou ne mord pas et laisserait "
            "passer la régression réellement vécue le 2026-08-07"
        )
        # Le fichier réel du dépôt, lui, doit toujours porter le montage :
        # preuve que le sabotage a bien opéré sur une COPIE, pas l'original.
        compose_reel = yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))
        volumes_reels = compose_reel["services"]["akvorado-outlet"].get("volumes", [])
        cibles_reelles = [str(v).split(":")[1] if ":" in str(v) else "" for v in volumes_reels]
        assert "/usr/share/GeoIP" in cibles_reelles, (
            "le fichier réel du dépôt a été altéré par ce test — régression "
            "de méthode, le sabotage doit rester cantonné à tmp_path"
        )


def test_les_dimensions_utilisent_des_noms_de_colonnes_pas_des_identifiants_widget() -> None:
    """Deux clés voisines, deux conventions — la confusion empêche le démarrage.

    DÉFAUT MESURÉ (2026-08-07) sur une machine vierge. `console.yaml` déclarait
    `dimensions: [src-as]`, et la console bouclait en Restarting :

        unable to initialize console component: unknown column name src-as

    Le piège : `src-as` est parfaitement VALIDE dans `homepage-top-widgets`, où
    c'est un identifiant de widget. Il est refusé dans `dimensions`, qui attend
    les noms de colonnes ClickHouse (`SrcAS`, `SrcAddr`, `ExporterName`…). Deux
    clés du même fichier, deux conventions, aucune erreur avant le démarrage.

    Ce défaut ne se voit qu'en MONTANT le stack : le YAML est valide, il parse,
    `docker compose config` passe. Seul le binaire refuse.
    """
    console = _charger_yaml(CONFIG_FILES["console"])
    dimensions = (console.get("default-visualize-options") or {}).get("dimensions") or []

    # Un nom de colonne ClickHouse est en CamelCase et ne porte jamais de tiret ;
    # un identifiant de widget est en minuscules-avec-tirets.
    en_style_widget = [d for d in dimensions if "-" in str(d) or str(d).islower()]

    assert not en_style_widget, (
        f"Ces dimensions ressemblent à des identifiants de widget : {en_style_widget}. "
        "`dimensions` attend des NOMS DE COLONNES ClickHouse (SrcAddr, DstPort, "
        "ExporterName…). La console refuserait de démarrer sur « unknown column "
        "name », alors que ces mêmes valeurs sont valides dans "
        "`homepage-top-widgets`."
    )
    assert dimensions, "aucune dimension par défaut : l'écran Visualize s'ouvrirait vide"


# ---------------------------------------------------------------------------
# 14. SNMPv3 — coexistence avec v2c, migration progressive (350 routeurs)
# ---------------------------------------------------------------------------
#
# Doc Akvorado officielle (metadata.providers, provider type: snmp, clé
# `credentials`) : "credentials is a map from exporter subnets to
# credentials. Use ::/0 to set the default value." et "Akvorado uses SNMPv2
# if `communities` is present and SNMPv3 if `user-name` is present."
#
# Mécanisme retenu (voir commentaires du gabarit outlet.yaml.template) :
# `credentials` reste "::/0" -> communities (v2c, INCHANGÉ, défaut global)
# + une entrée CIDR supplémentaire, générée conditionnellement par
# `generate-config.sh` (Akvorado ne résout aucune logique conditionnelle en
# YAML), SI ET SEULEMENT SI `SNMP_V3_USERNAME` est renseigné.

GENERATE_CONFIG_SH = STACK_DIR / "config-generator" / "generate-config.sh"

# Marqueur laissé dans le gabarit : generate-config.sh le remplace (v3
# configuré) ou le supprime (v3 non configuré) — il ne doit JAMAIS survivre
# tel quel dans un outlet.yaml réellement généré.
MARQUEUR_V3 = "__SNMP_V3_CREDENTIALS_PLACEHOLDER__"


def _generer_outlet_yaml(tmp_path: Path, env_supplementaire: dict[str, str]) -> Path:
    """Exécute le VRAI `generate-config.sh` dans le conteneur Alpine ciblé
    par le compose (`alpine:3.20`), sur une copie du gabarit — pas une
    réimplémentation Python du script, qui pourrait diverger du réel exécuté
    en prod. Utilise Docker comme `TestDockerComposeConfig` : skip proprement
    si indisponible plutôt que de faire semblant de valider."""
    if shutil.which("docker") is None:
        pytest.skip("docker indisponible dans cet environnement de test")

    tmp_path.mkdir(parents=True, exist_ok=True)
    etc_akvorado = tmp_path / "etc_akvorado"
    etc_akvorado.mkdir()
    (etc_akvorado / "outlet.yaml.template").write_text(
        OUTLET_TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8"
    )
    etc_templates = tmp_path / "etc_grafana_alerting_templates"
    etc_templates.mkdir()
    etc_out = tmp_path / "etc_grafana_alerting"
    etc_out.mkdir()

    env_base = {
        "SNMP_COMMUNITY": "test-communaute",
        "ALERTE_EXPORTATEUR_MUET_MINUTES": "15",
        "ALERTE_SATURATION_INTERFACE_SEUIL_PCT": "80",
        "ALERTE_CHUTE_TRAFIC_SEUIL_PCT": "50",
        "ALERTE_NOTIFICATION_WEBHOOK_URL": "http://localhost:9999/test",
        "ALERTE_DB_HEALTH_PARTS_ACTIVES_SEUIL": "500",
    }
    env_base.update(env_supplementaire)

    commande = ["docker", "run", "--rm"]
    for cle in (
        "etc_akvorado:/etc/akvorado",
        "etc_grafana_alerting_templates:/etc/grafana-alerting-templates",
        "etc_grafana_alerting:/etc/grafana-alerting",
    ):
        nom_local, cible = cle.split(":")
        commande += ["-v", f"{tmp_path / nom_local}:{cible}"]
    commande += ["-v", f"{GENERATE_CONFIG_SH}:/generate-config.sh"]
    for cle, valeur in env_base.items():
        commande += ["-e", f"{cle}={valeur}"]
    commande += ["alpine:3.20", "/generate-config.sh"]

    resultat = subprocess.run(commande, capture_output=True, text=True, timeout=120)
    if resultat.returncode != 0:
        raise AssertionError(
            f"generate-config.sh a échoué (code {resultat.returncode}) :\n"
            f"stdout={resultat.stdout}\nstderr={resultat.stderr}"
        )
    return etc_akvorado / "outlet.yaml"


class TestSnmpV3Coexistence:
    """Le mécanisme central : v3 s'AJOUTE à côté de v2c, jamais à sa place."""

    def test_le_gabarit_porte_le_marqueur_de_generation_conditionnelle(self) -> None:
        contenu = OUTLET_TEMPLATE.read_text(encoding="utf-8")
        assert MARQUEUR_V3 in contenu, (
            "le gabarit doit porter le marqueur "
            f"{MARQUEUR_V3!r} : sans lui, generate-config.sh n'a aucun point "
            "d'ancrage stable où insérer/omettre l'entrée SNMPv3."
        )

    def test_sans_snmp_v3_username_le_yaml_genere_est_identique_au_comportement_actuel(
        self, tmp_path: Path
    ) -> None:
        """Non-régression explicite du cas par défaut (350 routeurs pas
        encore migrés) : SNMP_V3_USERNAME vide => `credentials` ne contient
        QUE "::/0" en v2c, aucune entrée v3 fantôme."""
        outlet_genere = _generer_outlet_yaml(tmp_path, {})
        contenu = outlet_genere.read_text(encoding="utf-8")
        assert MARQUEUR_V3 not in contenu, (
            "le marqueur de génération conditionnelle a survécu tel quel "
            "dans le YAML généré — generate-config.sh doit le supprimer "
            "quand SNMP_V3_USERNAME est vide"
        )
        outlet = yaml.safe_load(contenu)
        snmp = next(p for p in outlet["metadata"]["providers"] if p["type"] == "snmp")
        assert list(snmp["credentials"].keys()) == ["::/0"], (
            f"credentials={snmp['credentials'].keys()!r} — sans "
            "SNMP_V3_USERNAME, seule l'entrée v2c '::/0' doit être présente, "
            "identique au comportement actuel."
        )
        assert snmp["credentials"]["::/0"]["communities"] == ["test-communaute"]

    def test_avec_snmp_v3_username_lentree_v3_sajoute_sans_retirer_v2c(
        self, tmp_path: Path
    ) -> None:
        """Coexistence : les DEUX entrées CIDR sont présentes après
        génération — v3 ne remplace jamais v2c."""
        outlet_genere = _generer_outlet_yaml(
            tmp_path,
            {
                "SNMP_V3_SUBNET": "10.99.0.0/24",
                "SNMP_V3_USERNAME": "monitoring",
                "SNMP_V3_SECURITY_LEVEL": "authPriv",
                "SNMP_V3_AUTH_PROTOCOL": "SHA256",
                "SNMP_V3_AUTH_PASSPHRASE": "auth-secret",
                "SNMP_V3_PRIV_PROTOCOL": "AES256",
                "SNMP_V3_PRIV_PASSPHRASE": "priv-secret",
            },
        )
        contenu = outlet_genere.read_text(encoding="utf-8")
        assert MARQUEUR_V3 not in contenu
        outlet = yaml.safe_load(contenu)
        snmp = next(p for p in outlet["metadata"]["providers"] if p["type"] == "snmp")
        credentials = snmp["credentials"]

        assert "::/0" in credentials and "communities" in credentials["::/0"], (
            "l'entrée v2c '::/0' doit rester intacte après ajout de v3 — "
            "c'est le défaut global pour tout le parc pas encore migré"
        )
        assert credentials["::/0"]["communities"] == ["test-communaute"]

        assert "10.99.0.0/24" in credentials, (
            f"credentials={credentials.keys()!r} — l'entrée v3 sur le "
            "sous-réseau SNMP_V3_SUBNET doit être présente"
        )
        v3 = credentials["10.99.0.0/24"]
        assert v3["user-name"] == "monitoring"
        assert v3["authentication-protocol"] == "SHA256"
        assert v3["authentication-passphrase"] == "auth-secret"
        assert v3["privacy-protocol"] == "AES256"
        assert v3["privacy-passphrase"] == "priv-secret"
        assert "communities" not in v3, (
            "une entrée v3 ne doit JAMAIS porter 'communities' — la doc "
            "Akvorado est explicite : une entrée credentials est SOIT v2c "
            "SOIT v3, jamais les deux à la fois"
        )

    def test_noauthnopriv_nemet_aucune_passphrase_vide(self, tmp_path: Path) -> None:
        """Doc Akvorado : authentication-passphrase/privacy-passphrase ne
        sont émises "if the previous value was set". Sans protocole (cas
        noAuthNoPriv), aucune clé passphrase ne doit apparaître."""
        outlet_genere = _generer_outlet_yaml(
            tmp_path,
            {
                "SNMP_V3_SUBNET": "10.99.0.0/24",
                "SNMP_V3_USERNAME": "noauth-user",
                "SNMP_V3_SECURITY_LEVEL": "noAuthNoPriv",
                "SNMP_V3_AUTH_PROTOCOL": "",
                "SNMP_V3_AUTH_PASSPHRASE": "",
                "SNMP_V3_PRIV_PROTOCOL": "",
                "SNMP_V3_PRIV_PASSPHRASE": "",
            },
        )
        outlet = yaml.safe_load(outlet_genere.read_text(encoding="utf-8"))
        snmp = next(p for p in outlet["metadata"]["providers"] if p["type"] == "snmp")
        v3 = snmp["credentials"]["10.99.0.0/24"]
        assert v3 == {"user-name": "noauth-user"}, (
            f"v3={v3!r} — en noAuthNoPriv, seule 'user-name' doit être "
            "émise, aucune clé protocole/passphrase vide"
        )

    def test_snmp_v3_username_sans_subnet_echoue_plutot_que_de_collisionner_avec_v2c(
        self, tmp_path: Path
    ) -> None:
        """Garde-fou zéro silencieux : SNMP_V3_SUBNET vide alors que
        SNMP_V3_USERNAME est renseigné ne doit JAMAIS retomber sur '::/0'
        par défaut — ce serait une DEUXIÈME clé '::/0' dans la map YAML
        `credentials`, que le parseur YAML réduit à la DERNIÈRE occurrence :
        la v3 écraserait silencieusement le défaut v2c pour tout le parc non
        migré. Le script doit échouer fort plutôt que produire ce résultat."""
        if shutil.which("docker") is None:
            pytest.skip("docker indisponible dans cet environnement de test")

        etc_akvorado = tmp_path / "etc_akvorado"
        etc_akvorado.mkdir()
        (etc_akvorado / "outlet.yaml.template").write_text(
            OUTLET_TEMPLATE.read_text(encoding="utf-8"), encoding="utf-8"
        )
        etc_templates = tmp_path / "etc_grafana_alerting_templates"
        etc_templates.mkdir()
        etc_out = tmp_path / "etc_grafana_alerting"
        etc_out.mkdir()

        commande = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{etc_akvorado}:/etc/akvorado",
            "-v",
            f"{etc_templates}:/etc/grafana-alerting-templates",
            "-v",
            f"{etc_out}:/etc/grafana-alerting",
            "-v",
            f"{GENERATE_CONFIG_SH}:/generate-config.sh",
            "-e",
            "SNMP_COMMUNITY=test-communaute",
            "-e",
            "SNMP_V3_USERNAME=monitoring",
            "-e",
            "ALERTE_EXPORTATEUR_MUET_MINUTES=15",
            "-e",
            "ALERTE_SATURATION_INTERFACE_SEUIL_PCT=80",
            "-e",
            "ALERTE_CHUTE_TRAFIC_SEUIL_PCT=50",
            "-e",
            "ALERTE_NOTIFICATION_WEBHOOK_URL=http://localhost:9999/test",
            "-e",
            "ALERTE_DB_HEALTH_PARTS_ACTIVES_SEUIL=500",
            "alpine:3.20",
            "/generate-config.sh",
        ]
        resultat = subprocess.run(commande, capture_output=True, text=True, timeout=120)
        assert resultat.returncode != 0, (
            "SNMP_V3_USERNAME sans SNMP_V3_SUBNET doit faire échouer "
            "generate-config.sh (zéro silencieux) — sinon un repli implicite "
            "sur '::/0' produirait une clé dupliquée dans `credentials`, "
            "silencieusement résolue par le DERNIER gagnant du parseur YAML "
            "(la v3), écrasant le défaut v2c pour tout le parc non migré"
        )
        assert "SNMP_V3_SUBNET" in resultat.stderr, (
            f"le message d'erreur devrait citer SNMP_V3_SUBNET : {resultat.stderr!r}"
        )

    def test_aucune_substitution_dollar_snmp_v3_ne_subsiste_apres_generation(
        self, tmp_path: Path
    ) -> None:
        """Extension de TestZeroSubstitutionDollarDansLesYamlLusParAkvorado
        aux nouvelles variables SNMP_V3_* : le YAML RÉELLEMENT généré (pas le
        .template, exempté) ne doit porter aucun ${SNMP_V3_...} littéral."""
        outlet_genere = _generer_outlet_yaml(
            tmp_path,
            {
                "SNMP_V3_SUBNET": "10.99.0.0/24",
                "SNMP_V3_USERNAME": "monitoring",
                "SNMP_V3_SECURITY_LEVEL": "authPriv",
                "SNMP_V3_AUTH_PROTOCOL": "SHA256",
                "SNMP_V3_AUTH_PASSPHRASE": "auth-secret",
                "SNMP_V3_PRIV_PROTOCOL": "AES256",
                "SNMP_V3_PRIV_PASSPHRASE": "priv-secret",
            },
        )
        contenu = _sans_commentaires_yaml(outlet_genere.read_text(encoding="utf-8"))
        trouvees = [m for m in _SUBSTITUTION_NON_RESOLUE_RE.findall(contenu) if "SNMP_V3" in m]
        assert not trouvees, (
            f"substitutions SNMP_V3 non résolues dans le YAML généré : {trouvees!r}"
        )

    def test_lordre_de_la_cascade_et_le_cache_restent_intacts_apres_generation_v3(
        self, tmp_path: Path
    ) -> None:
        """Garde-fous CENTRAUX du fichier (ordre snmp/static, cache 5m) —
        vérifiés ici sur le YAML RÉELLEMENT généré avec v3 actif, pas
        seulement sur le gabarit : l'insertion du bloc v3 ne doit rien
        déplacer d'autre."""
        outlet_genere = _generer_outlet_yaml(
            tmp_path,
            {
                "SNMP_V3_SUBNET": "10.99.0.0/24",
                "SNMP_V3_USERNAME": "monitoring",
            },
        )
        outlet = yaml.safe_load(outlet_genere.read_text(encoding="utf-8"))
        types = [p.get("type") for p in outlet["metadata"]["providers"]]
        assert types.index("snmp") < types.index("static"), (
            f"cascade dans le mauvais ordre après génération v3 : {types}"
        )
        assert outlet["metadata"]["cache-duration"] == "5m"
        assert outlet["metadata"]["cache-refresh"] == "5m"


class TestSnmpV3CredentialsReferenceEnvironnement:
    """Extension de TestAucunSecretEnClair::test_la_communaute_snmp_est_une_reference_environnement
    aux credentials SNMPv3 : user-name/passphrases doivent rester des
    références ${VAR} strictes dans le GABARIT versionné — jamais une valeur
    en clair. Le gabarit ne porte les clés v3 QUE via le marqueur (résolu
    par generate-config.sh), donc ce test travaille sur le YAML généré avec
    des valeurs de test, en s'assurant qu'AUCUNE valeur de test ne fuit
    accidentellement dans le .template versionné lui-même (ce qui serait le
    vrai risque : un opérateur qui coderait en dur une passphrase dans le
    gabarit plutôt que de passer par SNMP_V3_*)."""

    def test_le_gabarit_versionne_ne_contient_aucune_passphrase_litterale(self) -> None:
        """Le gabarit (fichier VERSIONNÉ) ne doit jamais contenir la moindre
        valeur de credential v3 en clair : seules les variables SNMP_V3_*
        (résolues par generate-config.sh) et le marqueur y figurent."""
        contenu = OUTLET_TEMPLATE.read_text(encoding="utf-8")
        assert "authentication-passphrase:" not in contenu, (
            "le gabarit versionné ne doit jamais porter "
            "'authentication-passphrase:' en dur — cette clé n'existe QUE "
            "dans le bloc généré dynamiquement par generate-config.sh, "
            "jamais dans le .template lui-même"
        )
        assert "privacy-passphrase:" not in contenu, (
            "le gabarit versionné ne doit jamais porter 'privacy-passphrase:' "
            "en dur — cette clé n'existe QUE dans le bloc généré "
            "dynamiquement par generate-config.sh"
        )

    def test_la_communaute_et_les_passphrases_v3_du_yaml_genere_sont_des_valeurs_injectees_par_env(
        self, tmp_path: Path
    ) -> None:
        """PREUVE PAR SABOTAGE (RED puis GREEN) : le générateur DOIT refléter
        fidèlement les variables d'environnement fournies (aucune passphrase
        « en dur » indépendante de l'environnement n'est codée dans le
        générateur lui-même). Sabotage : deux jeux de passphrases différents
        doivent produire deux YAML différents — si le générateur codait une
        passphrase en dur (régression), les deux générations produiraient le
        même résultat malgré des variables d'environnement différentes."""
        outlet_a = _generer_outlet_yaml(
            tmp_path / "a",
            {
                "SNMP_V3_SUBNET": "10.99.0.0/24",
                "SNMP_V3_USERNAME": "monitoring",
                "SNMP_V3_AUTH_PROTOCOL": "SHA256",
                "SNMP_V3_AUTH_PASSPHRASE": "passphrase-A",
                "SNMP_V3_PRIV_PROTOCOL": "AES256",
                "SNMP_V3_PRIV_PASSPHRASE": "priv-A",
            },
        )
        outlet_b = _generer_outlet_yaml(
            tmp_path / "b",
            {
                "SNMP_V3_SUBNET": "10.99.0.0/24",
                "SNMP_V3_USERNAME": "monitoring",
                "SNMP_V3_AUTH_PROTOCOL": "SHA256",
                "SNMP_V3_AUTH_PASSPHRASE": "passphrase-B-differente",
                "SNMP_V3_PRIV_PROTOCOL": "AES256",
                "SNMP_V3_PRIV_PASSPHRASE": "priv-B-differente",
            },
        )
        a = yaml.safe_load(outlet_a.read_text(encoding="utf-8"))
        b = yaml.safe_load(outlet_b.read_text(encoding="utf-8"))
        creds_a = a["metadata"]["providers"][0]["credentials"]["10.99.0.0/24"]
        creds_b = b["metadata"]["providers"][0]["credentials"]["10.99.0.0/24"]
        assert creds_a["authentication-passphrase"] == "passphrase-A"
        assert creds_b["authentication-passphrase"] == "passphrase-B-differente"
        assert creds_a != creds_b, (
            "deux jeux de passphrases différents ont produit le MÊME YAML — "
            "le générateur code potentiellement une valeur en dur au lieu "
            "de refléter l'environnement fourni"
        )

    def test_le_garde_fou_mord_une_passphrase_en_clair_saboterait_le_gabarit(
        self, tmp_path: Path
    ) -> None:
        """RED-GREEN explicite demandé : sabote une COPIE temporaire du
        gabarit en y écrivant une passphrase EN CLAIR (comme si un
        opérateur avait codé en dur `authentication-passphrase:
        "motdepasse123"` au lieu du mécanisme ${VAR}/marqueur), vérifie que
        le garde-fou dédié la détecte (RED), puis vérifie que le vrai
        gabarit du dépôt reste propre (GREEN) — preuve que le garde-fou mord
        vraiment et ne passe pas seulement parce que le cas sabote n'est
        jamais testé."""
        contenu_original = OUTLET_TEMPLATE.read_text(encoding="utf-8")

        # RED : sabotage — on remplace le marqueur par un bloc v3 avec une
        # passphrase EN CLAIR, exactement le défaut qu'un opérateur pourrait
        # introduire en pensant bien faire.
        contenu_saboté = contenu_original.replace(
            "        # __SNMP_V3_CREDENTIALS_PLACEHOLDER__",
            "        10.99.0.0/24:\n"
            "          user-name: monitoring\n"
            "          authentication-protocol: SHA256\n"
            '          authentication-passphrase: "motdepasse123"\n',
        )
        assert contenu_saboté != contenu_original, "le sabotage n'a rien remplacé — test invalide"
        saboté = tmp_path / "outlet.yaml.template"
        saboté.write_text(contenu_saboté, encoding="utf-8")

        # Le garde-fou dédié : aucune "authentication-passphrase:" littérale
        # ne doit apparaître dans le gabarit versionné.
        assert "authentication-passphrase:" in saboté.read_text(encoding="utf-8"), (
            "le sabotage aurait dû introduire 'authentication-passphrase:' "
            "détectable — s'il n'y en a aucune, le garde-fou ne mord pas"
        )

        # GREEN : le fichier RÉEL du dépôt, lui, ne porte toujours pas cette
        # clé en dur (seul le marqueur y figure) — preuve que le sabotage est
        # resté cantonné à tmp_path.
        assert "authentication-passphrase:" not in contenu_original, (
            "le gabarit réel du dépôt porte déjà une passphrase en dur — "
            "soit une régression, soit ce test ne prouve plus rien"
        )


# ---------------------------------------------------------------------------
# 15. Toute variable OKVORADO_* attendue par app/config.py est CÂBLÉE, avec
#     le VRAI nom de variable — pas seulement présente quelque part.
# ---------------------------------------------------------------------------


# DÉFAUT MESURÉ (2026-08-09, ce chantier) : `OKVORADO_SNMP_V3_AUTH_PASSPHRASE`
# et `OKVORADO_SNMP_V3_PRIV_PASSPHRASE` étaient câblés dans le compose et
# documentés dans `.env.example`, mais `app/config.py::Settings` (pydantic-
# settings, prefixe OKVORADO_) attend RÉELLEMENT `OKVORADO_SNMP_V3_AUTH_PASSWORD`
# / `OKVORADO_SNMP_V3_PRIV_PASSWORD` (champs `snmp_v3_auth_password` /
# `snmp_v3_priv_password`) — un `_PASSPHRASE` au lieu de `_PASSWORD` n'est
# JAMAIS lu par pydantic : la variable a un nom, une valeur, une place dans
# le compose, mais AUCUN EFFET. Même famille de défaut que celui déjà
# documenté pour `OKVORADO_AUTH_USER` (cf. commentaire du compose,
# service `okvorado`) : « une variable documentée mais non câblée est pire
# qu'absente — elle promet un réglage qui n'a aucun effet ».
#
# Aucun test EXISTANT (avant ce chantier) ne pouvait attraper ce défaut :
# `TestZeroSubstitutionDollarDansLesYamlLusParAkvorado` vérifie l'absence de
# `${...}` non résolus dans les YAML Akvorado, pas la correspondance entre
# le NOM d'une variable d'environnement transmise au conteneur `okvorado`
# et le nom RÉELLEMENT lu par `pydantic_settings.BaseSettings`. Seule
# l'instanciation réelle de `Settings` (comme fait ce test) le révèle — un
# `grep` sur le texte ne suffit pas, car la variable EXISTE bel et bien dans
# le fichier, juste sous un nom différent de celui attendu.
#
# Champs de `Settings` qui n'ont délibérément AUCUNE variable dans le compose
# (voir rapport de chantier) : ce sont soit des constantes internes qu'un
# exploitant n'a pas de raison d'ajuster au déploiement (`outlet_metrics_path`,
# `http_timeout_seconds`, `purge_poll_interval_seconds`,
# `db_health_poll_interval_seconds`, `db_health_history_max_age_days`), soit
# un mécanisme dont le SERVICE associé n'est pas déclaré dans ce compose
# portable (`restart_agent_host/port/token`, `restart_timeout_seconds` —
# l'agent de restart est un service séparé, hors périmètre de ce stack).
CHAMPS_SETTINGS_SANS_VARIABLE_COMPOSE = frozenset(
    {
        "outlet_metrics_path",
        "http_timeout_seconds",
        "purge_poll_interval_seconds",
        "db_health_poll_interval_seconds",
        "db_health_history_max_age_days",
        "restart_agent_host",
        "restart_agent_port",
        "restart_agent_token",
        "restart_timeout_seconds",
    }
)


def _champs_settings() -> list[str]:
    """Liste les champs déclarés sur `Settings`, dans l'ORDRE du fichier
    source — en relisant `app/config.py` en texte plutôt qu'en import Python,
    pour que ce test reste indépendant de tout état d'import préalable
    (aucune surprise liée à un module déjà chargé avec d'autres variables
    d'environnement dans un run pytest complet)."""
    contenu = (STACK_DIR.parent / "app" / "config.py").read_text(encoding="utf-8")
    match = re.search(r"class Settings.*?\n(.*?)\n    @property", contenu, re.S)
    assert match is not None, "structure de app/config.py::Settings inattendue"
    return re.findall(r"^    ([a-z_][a-z0-9_]*): ", match.group(1), re.M)


def _bloc_environment_okvorado() -> str:
    """Extrait le texte brut du bloc `environment:` du service `okvorado`
    dans le compose — en texte plutôt qu'en YAML parsé : un YAML parsé
    perdrait l'info de savoir quelle variable d'env COMPOSE (`${SNMP_V3_...}`)
    alimente quelle clé OKVORADO_*, qui est précisément ce que ce test
    vérifie (le nom de la clé À GAUCHE, pas la valeur résolue à droite)."""
    contenu = COMPOSE_FILE.read_text(encoding="utf-8")
    debut = contenu.index("\n  okvorado:\n")
    fin = contenu.index("\n  # ", debut + 1) if "\n  # " in contenu[debut + 1 :] else len(contenu)
    # Borne la recherche au bloc du service okvorado : jusqu'au prochain
    # service de premier niveau (indentation 2 espaces, ni commentaire ni
    # continuation) après le début du service.
    reste = contenu[debut + 1 :]
    prochain_service = re.search(r"\n  [a-z][a-z0-9_-]*:\n", reste)
    fin = debut + 1 + prochain_service.start() if prochain_service else len(contenu)
    return contenu[debut:fin]


class TestToutChampSettingsEstCorrectementCable:
    """LE test qui aurait attrapé le défaut n°1 de ce chantier (variable
    documentée dans `.env.example` mais non câblée, ou câblée sous un nom
    qui ne correspond pas à ce que `pydantic_settings` lit réellement)."""

    def test_tout_champ_cable_dans_le_compose_porte_le_bon_nom_de_variable(self) -> None:
        bloc = _bloc_environment_okvorado()
        # Le NOM de chaque clé OKVORADO_* effectivement posée dans le bloc
        # environment (à gauche du ':'), quelle que soit la variable compose
        # qui la résout à droite.
        cles_presentes = set(re.findall(r"^\s+(OKVORADO_[A-Z0-9_]+):", bloc, re.M))

        champs = _champs_settings()
        attendus = {champ: f"OKVORADO_{champ.upper()}" for champ in champs}

        manquants = [
            (champ, var)
            for champ, var in attendus.items()
            if champ not in CHAMPS_SETTINGS_SANS_VARIABLE_COMPOSE and var not in cles_presentes
        ]
        assert not manquants, (
            f"champs de Settings sans variable OKVORADO_* correctement nommée "
            f"dans le bloc environment du service okvorado : {manquants} — "
            "soit la variable est absente (réglage sans aucun effet), soit "
            "elle est câblée sous un nom LÉGÈREMENT différent de celui que "
            "pydantic_settings lit réellement (ex: _PASSPHRASE au lieu de "
            "_PASSWORD, défaut réellement mesuré ce chantier) : dans les "
            "deux cas, un exploitant qui règle cette variable dans son .env "
            "n'obtient AUCUN effet, silencieusement. Si ce champ est une "
            "constante interne délibérément non exposée, l'ajouter à "
            "CHAMPS_SETTINGS_SANS_VARIABLE_COMPOSE avec la raison."
        )

    def test_la_liste_dexemptions_ne_couvre_que_des_champs_reellement_absents(self) -> None:
        """Garde-fou de la liste elle-même : un champ mis à tort dans
        `CHAMPS_SETTINGS_SANS_VARIABLE_COMPOSE` alors qu'il EST câblé serait
        inoffensif (le test principal resterait vert), mais un champ qui y
        entre par erreur alors qu'il devrait être câblé masquerait un vrai
        défaut. Ce test vérifie au moins que la liste ne contient que des
        noms de champs qui EXISTENT réellement sur Settings (une faute de
        frappe dans la liste d'exemption ne doit pas passer inaperçue)."""
        champs = set(_champs_settings())
        inconnus = CHAMPS_SETTINGS_SANS_VARIABLE_COMPOSE - champs
        assert not inconnus, (
            f"CHAMPS_SETTINGS_SANS_VARIABLE_COMPOSE cite des champs qui "
            f"n'existent pas (ou plus) sur Settings : {inconnus} — liste à "
            "corriger, un nom mal orthographié ici rendrait l'exemption "
            "inopérante sans avertissement"
        )

    def test_le_garde_fou_mord_sur_le_defaut_reellement_vecu_passphrase_vs_password(self) -> None:
        """PREUVE QUE LE GARDE-FOU MORD : rejoue, sur le texte réel du bloc
        environment, EXACTEMENT le défaut mesuré ce chantier — renommage de
        `OKVORADO_SNMP_V3_AUTH_PASSWORD` en `OKVORADO_SNMP_V3_AUTH_PASSPHRASE`
        (nom qui semble juste, mais que pydantic_settings ne lit jamais).
        Travaille sur une COPIE en mémoire du texte, jamais sur le fichier
        réel du dépôt."""
        bloc = _bloc_environment_okvorado()
        assert "OKVORADO_SNMP_V3_AUTH_PASSWORD:" in bloc, (
            "précondition invalide : le compose réel ne porte plus "
            "OKVORADO_SNMP_V3_AUTH_PASSWORD — rien à saboter, ce test ne "
            "prouve plus rien"
        )
        bloc_saboté = bloc.replace(
            "OKVORADO_SNMP_V3_AUTH_PASSWORD:", "OKVORADO_SNMP_V3_AUTH_PASSPHRASE:"
        )
        assert bloc_saboté != bloc, "le sabotage n'a rien remplacé — test invalide"

        cles_saboté = set(re.findall(r"^\s+(OKVORADO_[A-Z0-9_]+):", bloc_saboté, re.M))
        champs = _champs_settings()
        attendus = {champ: f"OKVORADO_{champ.upper()}" for champ in champs}
        manquants = [
            (champ, var)
            for champ, var in attendus.items()
            if champ not in CHAMPS_SETTINGS_SANS_VARIABLE_COMPOSE and var not in cles_saboté
        ]
        assert ("snmp_v3_auth_password", "OKVORADO_SNMP_V3_AUTH_PASSWORD") in manquants, (
            "le sabotage aurait dû faire réapparaître "
            "'snmp_v3_auth_password' comme champ non câblé — s'il n'y est "
            "pas, le garde-fou ne mord pas et laisserait passer exactement "
            "le défaut réellement vécu ce chantier (une passphrase SNMPv3 "
            "réglée par l'exploitant, sans aucun effet)"
        )

        # Le fichier réel du dépôt, lui, doit toujours porter le bon nom —
        # preuve que le sabotage est resté cantonné à une copie en mémoire.
        bloc_reel = _bloc_environment_okvorado()
        assert "OKVORADO_SNMP_V3_AUTH_PASSWORD:" in bloc_reel, (
            "le fichier réel du dépôt a été altéré par ce test — le "
            "sabotage doit rester cantonné à une variable locale, jamais "
            "toucher docker-compose.yml"
        )

    def test_variables_env_example_correspondent_a_un_champ_settings(  # noqa: E501
        self,
    ) -> None:
        """Sens complémentaire : une variable `OKVORADO_*` présente dans
        `.env.example` qui ne correspond à AUCUN champ de `Settings` serait
        une promesse creuse (documentée, mais que `app/config.py` ne lit
        jamais). Ne couvre que le préfixe OKVORADO_ : les alias compose
        (SNMP_*, CLICKHOUSE_*, AUTH_*...) sont un choix de nommage délibéré
        et n'ont pas à correspondre littéralement au nom du champ Python."""
        env_contenu = ENV_EXAMPLE.read_text(encoding="utf-8")
        variables_okvorado = set(re.findall(r"^(OKVORADO_[A-Z0-9_]+)=", env_contenu, re.M))

        # Variables OKVORADO_* qui pilotent le CONTENEUR (Docker Compose lui-
        # même — port publié, adresse de liaison, tag d'image, mem_limit),
        # pas un champ de `app/config.py::Settings` lu par l'application
        # Python : légitimement absentes de Settings, ne sont pas une
        # "promesse creuse" pour autant.
        variables_pilotage_conteneur = {
            "OKVORADO_BIND_ADDRESS",
            "OKVORADO_PORT",
            "OKVORADO_MEM_LIMIT",
            "OKVORADO_IMAGE",
        }

        champs = _champs_settings()
        noms_valides = {f"OKVORADO_{champ.upper()}" for champ in champs}

        orphelines = variables_okvorado - noms_valides - variables_pilotage_conteneur
        assert not orphelines, (
            f"variables OKVORADO_* documentées dans .env.example sans champ "
            f"Settings correspondant : {orphelines} — soit une faute de "
            "frappe dans .env.example, soit un champ supprimé de "
            "app/config.py sans mise à jour de la doc"
        )


class TestTouteVariableLueParComposeEstDocumentee:
    """Toute variable `${VAR}` REELLEMENT lue par le compose doit exister dans
    `.env.example`, sinon l'exploitant ignore jusqu'a son existence.

    DEFAUT MESURE (2026-08-09), sur le paquet destine a l'entreprise : trois
    variables etaient lues par le compose sans figurer nulle part dans la
    documentation d'installation, et c'etaient precisement les trois qui
    comptent pour un deploiement reel :
      - AKVORADO_IMAGE : la parade au blocage AVX2, qui peut empecher le
        conteneur de demarrer sur une VM a CPU generique ;
      - OKVORADO_PORT : le port d'acces a l'interface ;
      - OKVORADO_AUTH_COOKIE_SECURE : a passer a `true` derriere HTTPS.

    Le garde-fou voisin (`TestToutChampSettingsEstCorrectementCable`) ne les
    couvrait pas : il part des champs `Settings` de l'application, alors que
    ces trois-la sont des reglages d'INFRASTRUCTURE (image, port publie,
    drapeau de cookie) sans champ `Settings` correspondant. Les deux tests
    sont complementaires et aucun ne remplace l'autre.

    Une variable citee dans un COMMENTAIRE du compose n'est pas concernee :
    seules les lignes actives sont lues par docker compose.
    """

    # Variables fournies par l'environnement d'execution, jamais par `.env`.
    _HORS_PERIMETRE: frozenset[str] = frozenset(
        {
            # Pose par l'image Grafana elle-meme ; le compose ne fait que la
            # relire pour construire un chemin derive.
            "GF_PATHS_DATA",
        }
    )

    @staticmethod
    def _variables_lues_hors_commentaires() -> dict[str, int]:
        """Chaque `${VAR}` d'une ligne ACTIVE du compose -> son numero de ligne."""
        trouvees: dict[str, int] = {}
        for numero, ligne in enumerate(COMPOSE_FILE.read_text(encoding="utf-8").splitlines(), 1):
            if ligne.lstrip().startswith("#"):
                continue
            for nom in re.findall(r"\$\{([A-Z0-9_]+)(?::-[^}]*)?\}", ligne):
                trouvees.setdefault(nom, numero)
        return trouvees

    @staticmethod
    def _variables_declarees_dans_env_example() -> set[str]:
        return set(
            re.findall(r"^([A-Z0-9_]+)=", ENV_EXAMPLE.read_text(encoding="utf-8"), re.MULTILINE)
        )

    def test_aucune_variable_lue_par_compose_nest_absente_de_env_example(self) -> None:
        lues = self._variables_lues_hors_commentaires()
        declarees = self._variables_declarees_dans_env_example()

        manquantes = {
            nom: ligne
            for nom, ligne in lues.items()
            if nom not in declarees and nom not in self._HORS_PERIMETRE
        }

        assert not manquantes, (
            "variable(s) lue(s) par docker-compose.yml mais absente(s) de "
            f".env.example — invisible(s) pour l'exploitant : {sorted(manquantes)}"
        )

    def test_le_garde_fou_mord_sur_une_variable_non_documentee(self) -> None:
        """PREUVE DE MORSURE : sans elle, un test toujours vert ne prouve rien."""
        lues = {"AKVORADO_IMAGE": 325, "VARIABLE_JAMAIS_DOCUMENTEE": 999}
        declarees = {"AKVORADO_IMAGE"}

        manquantes = {
            nom: ligne
            for nom, ligne in lues.items()
            if nom not in declarees and nom not in self._HORS_PERIMETRE
        }

        assert manquantes == {"VARIABLE_JAMAIS_DOCUMENTEE": 999}

    def test_une_variable_citee_en_commentaire_seul_nest_pas_exigee(self) -> None:
        """NON-REGRESSION : un exemple dans un commentaire n'est pas un reglage.

        Sans cette exclusion, le test exigerait de documenter des variables
        qui n'existent pas (mesure : la premiere version de l'inventaire
        remontait `VAR`, tire du texte explicatif `${VAR:-defaut}`).
        """
        lues = self._variables_lues_hors_commentaires()
        assert "VAR" not in lues, (
            "un placeholder de commentaire est compte comme une vraie variable"
        )
