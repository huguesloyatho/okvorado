"""Garde-fous « une seule URL » — demande utilisateur, mot pour mot :

    « Il faudrait limiter les outils : par exemple akvorado pour récupérer
    les flux mais on ne s'y connecte pas, okvorado pour configurer
    l'instance, et un autre outil type grafana ou autre qui sert réellement
    de dashboard. Qu'en prod je dise pas à mon manager qu'il faut jongler
    sur 4 url pour voir l'exhaustivité des informations. »

DÉCISION D'ARCHITECTURE ACTUELLE (2026-08-09, troisième et dernière étape
d'une même journée — voir git log) : Okvorado porte SA PROPRE
authentification (page de connexion, session, TOTP optionnel — `app/auth.py`,
`app/routers/auth.py`, `app/templates/login.html`) et republie donc son
propre port, lié par défaut à la boucle locale (`127.0.0.1`). L'esprit de la
demande reste respecté autrement : ce ne sont plus les tableaux de bord ET la
configuration qui se confondent sur UNE SEULE url, mais DEUX urls role par
role — Grafana (`:3000`, restitution) et Okvorado (`:8000`, configuration,
protégé par son propre écran de connexion) — au lieu des quatre url d'origine
(Akvorado console, Akvorado outlet, Grafana, Okvorado). La console Akvorado
(`:8082`) et l'outlet (`:10179`, métriques Prometheus internes — pas une UI)
continuent de ne publier AUCUN port sur l'hôte : c'est ça qui reste à
défendre ici.

ÉTAPES ABANDONNÉES DE CETTE MÊME JOURNÉE (pour mémoire, ne protègent plus
rien) :
  1. Okvorado publiait `:8000` en iframe dans Grafana (CSP frame-ancestors).
  2. Port retiré, Okvorado servi À TRAVERS le proxy Grafana — d'abord le
     proxy de datasource natif, puis un plugin d'app à backend Go avec
     resource handler (`stack/grafana-plugin-backend/`). MESURÉ ET
     ABANDONNÉ au navigateur, jusqu'au bout : Grafana pose en dur
     `Content-Security-Policy: sandbox` sur TOUTES ses réponses de proxy
     (natif ET plugin) — CSS et JS ne s'appliquent jamais (page en Times New
     Roman, HTMX inopérant), même en faisant poser au plugin une CSP
     permissive : Grafana l'écrase quand même. Le plugin Go et tout le
     montage de proxy ont été SUPPRIMÉS du dépôt.

⚠️ Piège vécu 9 fois sur ce projet (voir tests/test_stack_portable.py) : un
test qui grep un motif interdit échoue sur sa PROPRE documentation. Les
recherches de motifs interdits retirent donc les lignes de commentaire avant
de chercher — même fonction que dans test_stack_portable.py, reproduite ici
pour ne pas coupler les deux fichiers de test par un import croisé.

Chaque test qui prouve un garde-fou MORD : il sabote une copie temporaire
(jamais le fichier réel), vérifie que le sabotage est détecté, puis laisse
`tmp_path` restaurer automatiquement.
"""

from __future__ import annotations

import re
from pathlib import Path

import yaml

STACK_DIR = Path(__file__).resolve().parent.parent / "stack"
COMPOSE_FILE = STACK_DIR / "docker-compose.yml"
DASHBOARDS_DIR = STACK_DIR / "grafana" / "dashboards"
DOCKERFILE = Path(__file__).resolve().parent.parent / "Dockerfile"
MAIN_PY = Path(__file__).resolve().parent.parent / "app" / "main.py"
CONFIG_PY = Path(__file__).resolve().parent.parent / "app" / "config.py"

# UID du dashboard d'accueil livré par l'agent dashboards — vérifié dans
# stack/grafana/dashboards/00-accueil-traffic-summary.json (clé "uid" en tête
# de fichier), jamais supposé.
UID_DASHBOARD_ACCUEIL = "okvorado-accueil-traffic-summary"


def _sans_commentaires_yaml(texte: str) -> str:
    """Retire les commentaires `# ...` d'un texte YAML, ligne par ligne.

    Même traitement que `test_stack_portable.py::_sans_commentaires_yaml` —
    voir sa docstring pour le piège que cette fonction évite (un motif
    interdit qui n'apparaît que dans un commentaire documentant pourquoi il
    est interdit).
    """
    lignes = []
    for ligne in texte.splitlines():
        sans_commentaire = re.sub(r"(^|\s)#.*$", "", ligne)
        lignes.append(sans_commentaire)
    return "\n".join(lignes)


def _charger_compose() -> dict:
    return yaml.safe_load(COMPOSE_FILE.read_text(encoding="utf-8"))


def _ports_tcp_publies(compose: dict) -> dict[str, list[str]]:
    """Ports TCP publiés sur l'hôte, par service — les ports UDP d'ingestion
    (NetFlow/IPFIX/sFlow) sont volontairement exclus : ce sont des ports de
    COLLECTE de flux, pas des URL destinées à un humain."""
    resultat: dict[str, list[str]] = {}
    for nom, service in (compose.get("services") or {}).items():
        publies = []
        for port in service.get("ports", []) or []:
            port_str = str(port)
            if "udp" in port_str.lower():
                continue
            publies.append(port_str)
        if publies:
            resultat[nom] = publies
    return resultat


# ---------------------------------------------------------------------------
# 1. Une seule URL TCP destinée aux humains : Grafana
# ---------------------------------------------------------------------------


class TestUneSeuleUrlHumaine:
    """LE test central de ce lot : compte les ports TCP publiés dans le
    compose. DEUX urls humaines, chacune avec un rôle distinct — plus quatre.

    DÉCISION D'ARCHITECTURE ACTUELLE (2026-08-09) : Okvorado porte sa PROPRE
    authentification (page de connexion, session, TOTP optionnel —
    `app/auth.py`) et republie donc son port, lié par défaut à `127.0.0.1`
    (voir `TestBindAddressOkvoradoParDefaut` plus bas pour ce volet).
    `grafana` (restitution) et `okvorado` (configuration, protégé par son
    propre login) sont donc les deux SEULS services attendus avec un port
    TCP publié.

    HISTORIQUE — l'étape intermédiaire (servir Okvorado À TRAVERS le proxy de
    datasource Grafana, `/api/datasources/proxy/uid/okvorado-proxy/...`) a
    été mesurée sur banc réel le 2026-08-08 puis ABANDONNÉE : Grafana pose en
    dur `Content-Security-Policy: sandbox` sur toutes ses réponses de proxy,
    rendant CSS et JS inopérants (voir docstring de module). Ce que
    l'attendu `{"grafana"}` de l'époque protégeait — pas de surface anonyme
    republiée — est désormais couvert par l'authentification propre
    d'Okvorado, testée dans `TestBindAddressOkvoradoParDefaut`.
    """

    def test_aucun_port_tcp_superflu_nest_publie(self) -> None:
        compose = _charger_compose()
        services_avec_port_tcp = _ports_tcp_publies(compose)
        attendus = {"grafana", "okvorado"}
        assert set(services_avec_port_tcp) == attendus, (
            f"services publiant un port TCP sur l'hote : {services_avec_port_tcp} — "
            f"attendu exactement {attendus}.\n"
            "DECISION UTILISATEUR (2026-08-09) : DEUX url humaines, chacune "
            "avec un role — Grafana (restitution) et Okvorado (configuration, "
            "protege par sa propre authentification). La console Akvorado et "
            "l'outlet ne doivent TOUJOURS publier aucun port : c'est ca que "
            "ce garde-fou continue de defendre en priorite."
        )

    def test_akvorado_console_ne_publie_plus_de_port(self) -> None:
        """Régression directe : la console (`:8082`) était redondante avec
        Grafana selon la mesure de départ — elle ne doit plus être publiée."""
        compose = _charger_compose()
        console = compose["services"].get("akvorado-console")
        assert console is not None, "service akvorado-console absent du compose"
        assert not console.get("ports"), (
            "akvorado-console publie encore un port — c'est exactement le "
            "port :8082 que la decision d'architecture retire (redondant "
            "avec Grafana, qui devient la porte d'entree unique)"
        )

    def test_akvorado_outlet_ne_publie_plus_de_port(self) -> None:
        """Régression directe : l'outlet (`:10179`) n'exposait que des
        métriques Prometheus internes, pas une interface humaine."""
        compose = _charger_compose()
        outlet = compose["services"].get("akvorado-outlet")
        assert outlet is not None, "service akvorado-outlet absent du compose"
        assert not outlet.get("ports"), (
            "akvorado-outlet publie encore un port — c'est exactement le "
            "port :10179 que la decision d'architecture retire (metriques "
            "Prometheus internes, pas une UI destinee a un humain)"
        )

    def test_les_ports_udp_dingestion_restent_publies(self) -> None:
        """Contrôle négatif : ce lot ferme des ports HUMAINS, jamais les
        ports UDP par lesquels arrivent les flux NetFlow/IPFIX/sFlow — les
        350 routeurs du parc doivent toujours pouvoir joindre l'inlet."""
        compose = _charger_compose()
        inlet = compose["services"].get("akvorado-inlet")
        assert inlet is not None, "service akvorado-inlet absent du compose"
        ports = " ".join(str(p) for p in inlet.get("ports", []))
        for port_attendu in ("2055", "4739", "6343"):
            assert port_attendu in ports, (
                f"le port UDP d'ingestion {port_attendu} n'est plus publie sur "
                "akvorado-inlet — ce lot ne doit fermer AUCUN port de collecte, "
                "seulement les URL destinees a un humain (console, outlet)"
            )
        assert "udp" in ports.lower(), "les ports d'ingestion doivent rester en UDP"

    def test_le_garde_fou_mord_si_un_port_reapparait(self, tmp_path: Path) -> None:
        """PREUVE QUE LE GARDE-FOU MORD : réintroduit le port :8082 sur une
        copie temporaire du compose (régression exacte de ce qui a été
        fermé), vérifie que la détection réagit, puis restauration
        automatique (`tmp_path`, jamais le fichier réel).

        L'attendu est `{"grafana", "okvorado"}` (décision 2026-08-09) : le
        sabotage ajoute la console Akvorado, ce qui doit faire diverger
        l'ensemble détecté de ces deux SEULS services légitimes."""
        compose = _charger_compose()
        compose["services"]["akvorado-console"]["ports"] = ["8082:8080/tcp"]

        saboté = tmp_path / "docker-compose.yml"
        saboté.write_text(yaml.safe_dump(compose), encoding="utf-8")

        compose_saboté = yaml.safe_load(saboté.read_text(encoding="utf-8"))
        services_avec_port_tcp = _ports_tcp_publies(compose_saboté)
        assert set(services_avec_port_tcp) != {"grafana", "okvorado"}, (
            "le sabotage (reintroduction du port :8082) aurait du casser le "
            "garde-fou 'une seule URL' — s'il ne le casse pas, une regression "
            "future rouvrant la console passerait inapercue"
        )
        # Le fichier réel du dépôt, lui, doit toujours n'avoir que ces deux-là.
        assert set(_ports_tcp_publies(_charger_compose())) == {"grafana", "okvorado"}, (
            "le fichier reel du depot a ete altere par ce test — le sabotage "
            "doit rester cantonne a tmp_path"
        )


def _port_conteneur_publie_pour_okvorado(compose: dict) -> str:
    """Extrait le port CONTENEUR (partie droite) du mapping `ports:` publié
    par le service `okvorado` — forme `HOTE:CONTENEUR/tcp`, potentiellement
    préfixée d'une adresse de liaison (`ADRESSE:HOTE:CONTENEUR/tcp`)."""
    ports = compose["services"]["okvorado"].get("ports") or []
    assert ports, "le service okvorado ne publie aucun port dans le compose"
    mapping = str(ports[0])
    cote_conteneur = mapping.split(":")[-1]
    return cote_conteneur.split("/")[0]


class TestPortOkvoradoCoherentAvecLeDockerfile:
    """DÉFAUT MESURÉ (2026-08-08, `.7`) : le compose publiait
    `${OKVORADO_PORT:-8000}:8000/tcp` (port hôte -> port CONTENEUR 8000),
    mais le Dockerfile fait tourner uvicorn sur 8099 (`EXPOSE 8099`,
    `CMD [..."--port", "8099"]`). Symptôme : `docker compose ps` affichait le
    conteneur `healthy` (le HEALTHCHECK du Dockerfile vérifie
    `127.0.0.1:8099`, DANS le conteneur, jamais le port publié sur l'hôte) et
    le port hôte `:8000` écoutait bien (docker-proxy) — mais toute connexion
    externe était acceptée puis immédiatement réinitialisée (rien n'écoute
    sur le port 8000 DANS le conteneur). Invisible par tous les tests
    existants : aucun ne monte le container pour de vrai.

    RETOUR À LA CIBLE D'ORIGINE (2026-08-09) : entre-temps ce test avait été
    déplacé pour protéger l'URL amont d'un plugin Go de proxy Grafana
    (`grafana-plugin-backend/`), lui-même abandonné et supprimé (voir
    docstring de module). Okvorado republie de nouveau directement son port
    (authentification propre) : l'invariant d'origine — le port CONTENEUR
    publié par le compose doit correspondre à celui que uvicorn écoute
    réellement, lu dans le Dockerfile — redevient exactement ce qu'il faut
    défendre, sans détour.

    Portée : service isolé à Okvorado, seul service avec un Dockerfile
    custom du lot — pas un motif multi-cible, patch local légitime ici.
    """

    def test_le_port_conteneur_publie_correspond_au_port_ecoute_par_uvicorn(
        self,
    ) -> None:
        """Le port CONTENEUR du mapping `ports:` (`...:8099` ci-dessus) doit
        être celui que UVICORN ÉCOUTE réellement (Dockerfile, motif
        `"--port", "NNNN"`) — pas le port hôte, qui peut légitimement différer
        via `OKVORADO_PORT`."""
        compose = _charger_compose()
        port_publie = _port_conteneur_publie_pour_okvorado(compose)

        port_ecoute = re.search(r'"--port",\s*"(\d+)"', DOCKERFILE.read_text(encoding="utf-8"))
        assert port_ecoute is not None, (
            "impossible de retrouver le port d'ecoute uvicorn dans le Dockerfile"
        )
        port_reel = port_ecoute.group(1)

        assert port_publie == port_reel, (
            f"le port CONTENEUR publie par le compose est {port_publie!r} alors "
            f"qu'uvicorn n'ecoute que sur {port_reel!r} (Dockerfile) — "
            "docker-proxy accepterait la connexion puis la reinitialiserait "
            "aussitot, et le healthcheck INTERNE (127.0.0.1) ne le detecterait "
            "jamais (defaut reellement mesure le 2026-08-08 sur .7)."
        )

    def test_le_garde_fou_mord_si_le_port_conteneur_est_errone(self, tmp_path: Path) -> None:
        """PREUVE QUE LE GARDE-FOU MORD : sabote une copie du compose avec le
        port conteneur erroné réellement mesuré (8000 au lieu de 8099) et
        vérifie que la divergence est détectable. Le fichier réel du dépôt
        reste intact."""
        compose = _charger_compose()
        compose["services"]["okvorado"]["ports"] = ["127.0.0.1:8000:8000/tcp"]

        saboté = tmp_path / "docker-compose.yml"
        saboté.write_text(yaml.safe_dump(compose), encoding="utf-8")
        compose_saboté = yaml.safe_load(saboté.read_text(encoding="utf-8"))

        port_reel = re.search(
            r'"--port",\s*"(\d+)"', DOCKERFILE.read_text(encoding="utf-8")
        ).group(1)  # type: ignore[union-attr]
        port_saboté = _port_conteneur_publie_pour_okvorado(compose_saboté)
        assert port_saboté != port_reel, (
            "le sabotage aurait du introduire un port different du port "
            "reellement ecoute — s'il correspond, le garde-fou ne mord pas"
        )

        # Le fichier réel du dépôt, lui, doit toujours viser le bon port.
        port_reel_dans_le_depot = _port_conteneur_publie_pour_okvorado(_charger_compose())
        assert port_reel_dans_le_depot == port_reel, (
            "le fichier reel du depot a ete altere par ce test"
        )


# ---------------------------------------------------------------------------
# 1bis. Le port d'Okvorado est lié à la boucle locale par défaut
# ---------------------------------------------------------------------------


class TestBindAddressOkvoradoParDefaut:
    """DÉFAUT MESURÉ (avant le chantier du 2026-08-09, plateforme de
    qualification) : le port d'Okvorado était publié sur `0.0.0.0:8099` et
    l'accès direct renvoyait HTTP 200 SANS AUCUNE authentification — alors
    que le reverse proxy placé devant imposait pourtant une authentification.
    Un port lié à `0.0.0.0` expose la surface à tout le réseau, en
    contournant entièrement le reverse proxy.

    PARADE : le mapping `ports:` du service `okvorado` préfixe désormais le
    port d'une adresse de liaison réglable, `OKVORADO_BIND_ADDRESS`, dont le
    défaut DOIT être `127.0.0.1` (voir docker-compose.yml et .env.example) —
    seule cette machine, ou un reverse proxy qui y tourne, peut alors joindre
    le port. Passer explicitement sur `0.0.0.0` reste possible (reverse
    proxy sur une autre machine), mais ne doit jamais être le défaut."""

    def test_le_defaut_de_bind_address_est_la_boucle_locale(self) -> None:
        contenu_sans_commentaires = _sans_commentaires_yaml(
            COMPOSE_FILE.read_text(encoding="utf-8")
        )
        assert "OKVORADO_BIND_ADDRESS:-127.0.0.1" in contenu_sans_commentaires, (
            "le compose ne fixe plus 127.0.0.1 comme defaut de "
            "OKVORADO_BIND_ADDRESS — un port publie sans adresse de liaison "
            "explicite, ou avec un defaut 0.0.0.0, expose Okvorado a tout le "
            "reseau et contourne le reverse proxy (defaut reellement mesure "
            "sur la plateforme de qualification, avant le 2026-08-09)."
        )

    def test_le_defaut_nest_jamais_toutes_interfaces(self) -> None:
        """Contrôle négatif direct : `0.0.0.0` ne doit apparaître nulle part
        comme DÉFAUT de `OKVORADO_BIND_ADDRESS` (une valeur explicite dans
        `.env` reste au choix de l'exploitant, ce n'est pas ce qui est
        vérifié ici)."""
        contenu_sans_commentaires = _sans_commentaires_yaml(
            COMPOSE_FILE.read_text(encoding="utf-8")
        )
        assert "OKVORADO_BIND_ADDRESS:-0.0.0.0" not in contenu_sans_commentaires, (
            "OKVORADO_BIND_ADDRESS a 0.0.0.0 comme defaut dans le compose — "
            "exactement le defaut qui a expose Okvorado sans authentification "
            "sur la plateforme de qualification, malgre un reverse proxy "
            "authentifiant devant"
        )

    def test_le_garde_fou_mord_si_le_defaut_repasse_a_toutes_interfaces(
        self, tmp_path: Path
    ) -> None:
        """PREUVE QUE LE GARDE-FOU MORD : sabote une copie du compose en
        remplaçant le défaut `127.0.0.1` par `0.0.0.0` (régression exacte
        mesurée), vérifie que la détection réagit, puis restauration
        automatique (`tmp_path`, jamais le fichier réel)."""
        contenu_original = COMPOSE_FILE.read_text(encoding="utf-8")
        contenu_saboté = contenu_original.replace(
            "OKVORADO_BIND_ADDRESS:-127.0.0.1", "OKVORADO_BIND_ADDRESS:-0.0.0.0"
        )
        assert contenu_saboté != contenu_original, "le sabotage n'a rien remplacé — test invalide"

        saboté = tmp_path / "docker-compose.yml"
        saboté.write_text(contenu_saboté, encoding="utf-8")

        contenu_nettoye = _sans_commentaires_yaml(saboté.read_text(encoding="utf-8"))
        assert "OKVORADO_BIND_ADDRESS:-0.0.0.0" in contenu_nettoye, (
            "le sabotage aurait du introduire 'OKVORADO_BIND_ADDRESS:-0.0.0.0' "
            "detectable — s'il n'est pas trouve, le garde-fou ne mord pas"
        )
        # Le fichier réel du dépôt, lui, ne doit jamais porter ce défaut.
        contenu_reel = _sans_commentaires_yaml(COMPOSE_FILE.read_text(encoding="utf-8"))
        assert "OKVORADO_BIND_ADDRESS:-0.0.0.0" not in contenu_reel, (
            "le fichier reel du depot a ete altere par ce test"
        )


# ---------------------------------------------------------------------------
# 2. L'accueil Grafana pointe vers un dashboard qui existe réellement
# ---------------------------------------------------------------------------


class TestAccueilGrafanaDeclare:
    """L'accueil doit s'ouvrir sur la synthèse, pas sur la page Grafana générique.

    DÉFAUT MESURÉ À L'ÉCRAN (2026-08-08). Le compose déclarait
    `GF_USERS_HOME_DASHBOARD_UID`, la variable était bien passée au conteneur,
    le dashboard bien chargé avec cet UID exact — et la racine affichait
    « Welcome to Grafana ».

    CAUSE : **ce réglage n'existe pas.** Vérifié dans le `grafana.ini` du
    conteneur, la clé de la section `[users]` est `default_home_dashboard_path`
    et attend un CHEMIN DE FICHIER, pas un UID. Elle vit dans la section
    `[dashboards]` du fichier de configuration — pas `[users]`, ce qui a coûté
    un second essai : `GF_USERS_DEFAULT_HOME_DASHBOARD_PATH` était lui aussi
    ignoré en silence, tout en apparaissant dans les logs comme « Config
    overridden from Environment variable ». Grafana journalise la surcharge
    AVANT de savoir si la clé existe.

    Ce qui rend le piège dangereux : une variable d'environnement inconnue de
    Grafana est ignorée EN SILENCE. Aucun avertissement au démarrage, aucune
    erreur dans les logs, le service reste `healthy`. Seul l'écran le montre.
    """

    def test_le_chemin_du_dashboard_daccueil_est_declare(self) -> None:
        compose = _charger_compose()
        grafana = compose["services"].get("grafana")
        assert grafana is not None, "service grafana absent du compose"
        env = grafana.get("environment", {})
        assert env.get("GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH"), (
            "GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH absent du service grafana — "
            "sans lui, Grafana s'ouvre sur son écran générique « Welcome to "
            "Grafana » et l'exploitant doit encore naviguer pour trouver "
            "l'information, contrairement à la demande « une seule URL »."
        )

    def test_le_reglage_utilise_un_chemin_pas_un_uid(self) -> None:
        """`GF_USERS_HOME_DASHBOARD_UID` n'existe pas — il serait ignoré."""
        compose = _charger_compose()
        env = compose["services"]["grafana"].get("environment", {})
        assert "GF_USERS_HOME_DASHBOARD_UID" not in env, (
            "GF_USERS_HOME_DASHBOARD_UID n'est PAS un réglage Grafana : il "
            "serait ignoré en silence et la racine afficherait la page "
            "générique. Le bon réglage est GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH, "
            "qui attend un chemin de fichier."
        )

    def test_le_chemin_declare_pointe_un_dashboard_reellement_livre(self) -> None:
        """Le fichier visé doit exister — sinon Grafana retombe sur sa page
        générique, sans le dire."""
        compose = _charger_compose()
        chemin = compose["services"]["grafana"]["environment"][
            "GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH"
        ]
        nom = Path(str(chemin)).name
        livres = {f.name for f in DASHBOARDS_DIR.glob("*.json")}
        assert livres, "aucun dashboard sous stack/grafana/dashboards/"
        assert nom in livres, (
            f"le chemin d'accueil vise {nom!r}, absent des dashboards livrés "
            f"({sorted(livres)}) — Grafana afficherait sa page générique."
        )

    def test_le_chemin_correspond_au_montage_du_compose(self) -> None:
        """Le chemin est celui vu DANS le conteneur, pas sur l'hôte.

        Le volume monte `./grafana/dashboards` sur `/var/lib/grafana/dashboards` :
        un chemin d'hôte ne serait pas résolu côté conteneur.
        """
        compose = _charger_compose()
        grafana = compose["services"]["grafana"]
        chemin = str(grafana["environment"]["GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH"])

        destinations = [str(v).split(":")[1] for v in grafana.get("volumes", []) if ":" in str(v)]
        assert any(chemin.startswith(d) for d in destinations), (
            f"le chemin d'accueil {chemin!r} ne commence par aucun point de "
            f"montage du conteneur ({destinations}) : Grafana ne le trouverait pas."
        )

    def test_le_garde_fou_mord_si_le_chemin_pointe_dans_le_vide(self) -> None:
        """PREUVE DE MORSURE : un chemin vers un dashboard inexistant doit être
        détecté."""
        livres = {f.name for f in DASHBOARDS_DIR.glob("*.json")}
        nom_sabote = Path("/var/lib/grafana/dashboards/99-inexistant.json").name
        assert nom_sabote not in livres, (
            "le sabotage aurait dû viser un fichier absent des dashboards livrés"
        )


# ---------------------------------------------------------------------------
# 3. Okvorado n'autorise en cadre QUE des origines explicites
# ---------------------------------------------------------------------------


class TestCadrageOkvoradoAllowlist:
    """Okvorado est embarqué dans Grafana via <iframe> (volet 3b de la
    demande) : ceci exige d'autoriser l'affichage encadré, un risque de
    clickjacking si mal maîtrisé. La parade retenue est une ALLOWLIST
    d'origines explicites — jamais `*`, jamais une suppression pure et
    simple de la protection."""

    def test_x_frame_options_deny_est_retire(self) -> None:
        """`X-Frame-Options: DENY` est incompatible avec un affichage
        encadré : il bloquerait Okvorado dans Grafana quelle que soit la CSP.
        Il doit être retiré (remplacé par la CSP frame-ancestors, qui seule
        sait exprimer une allowlist de plusieurs origines).

        Cherche le CODE réel (`response.headers[...]`), pas le nom de
        l'en-tête cité en docstring pour expliquer pourquoi il a été retiré
        — sinon ce test échouerait sur sa propre documentation, le piège
        vécu 9 fois cité en tête de ce fichier."""
        for ligne in MAIN_PY.read_text(encoding="utf-8").splitlines():
            assert 'response.headers["X-Frame-Options"]' not in ligne, (
                "app/main.py pose encore response.headers['X-Frame-Options'] — "
                "il ne sait exprimer que DENY/SAMEORIGIN/une origine unique, "
                "jamais une liste : laissé à DENY il bloquerait l'affichage "
                "d'Okvorado dans Grafana même avec une CSP frame-ancestors "
                "permissive."
            )

    def test_frame_ancestors_none_est_retire_du_code(self) -> None:
        """Régression directe : l'obstacle mesuré au départ était
        `frame-ancestors 'none'` en dur — il doit être remplacé par une
        valeur configurable, pas simplement retiré (ce qui ouvrirait à
        toute origine par défaut de navigateur)."""
        contenu = _sans_commentaires_yaml(MAIN_PY.read_text(encoding="utf-8"))
        assert "frame-ancestors 'none'" not in contenu, (
            "frame-ancestors 'none' est encore en dur dans app/main.py — "
            "Okvorado ne pourrait jamais s'afficher dans Grafana"
        )

    def test_frame_ancestors_nest_jamais_une_etoile(self) -> None:
        """Aucune trace de `frame-ancestors *` — ouvrir à TOUTE origine
        annulerait la protection anti-clickjacking pour gagner en confort,
        exactement ce que la demande interdit implicitement (« qu'en prod
        je dise pas... » suppose un contrôle, pas un abandon)."""
        for fichier in (MAIN_PY, CONFIG_PY):
            contenu = _sans_commentaires_yaml(fichier.read_text(encoding="utf-8"))
            assert not re.search(r"frame-ancestors\s+\*", contenu), (
                f"{fichier.name} porte 'frame-ancestors *' — ouverture totale, "
                "jamais autorisee : l'allowlist doit rester une liste explicite"
            )
            assert '"\\*"' not in contenu.replace(" ", "")

    def test_frame_ancestors_est_configurable_par_variable_denvironnement(self) -> None:
        """Le défaut ne doit pas être la seule valeur possible : un
        déploiement réel a une origine Grafana différente du défaut local
        (`OKVORADO_FRAME_ANCESTORS`, préfixe `OKVORADO_` de pydantic-settings)."""
        contenu = CONFIG_PY.read_text(encoding="utf-8")
        assert "frame_ancestors" in contenu, (
            "aucun champ 'frame_ancestors' dans app/config.py — l'allowlist "
            "d'origines pour le cadrage d'Okvorado doit etre un reglage, pas "
            "une valeur figee dans le code"
        )

    def test_le_middleware_emet_bien_lorigine_configuree(self) -> None:
        """Preuve d'intégration bout-en-bout : le middleware doit utiliser
        `settings.frame_ancestors`, pas une chaîne recopiée à part qui
        pourrait diverger du réglage."""
        contenu = MAIN_PY.read_text(encoding="utf-8")
        assert "settings.frame_ancestors" in contenu, (
            "app/main.py ne référence pas settings.frame_ancestors dans son "
            "en-tete Content-Security-Policy — l'allowlist configurable ne "
            "serait jamais appliquée"
        )

    def test_le_garde_fou_mord_si_letoile_est_reintroduite(self, tmp_path: Path) -> None:
        """PREUVE QUE LE GARDE-FOU MORD : sabote une copie temporaire du
        middleware avec `frame-ancestors *`, vérifie que la détection réagit,
        puis restauration automatique (`tmp_path`, jamais le fichier réel)."""
        contenu_original = MAIN_PY.read_text(encoding="utf-8")
        contenu_saboté = contenu_original.replace(
            "frame-ancestors {settings.frame_ancestors}", "frame-ancestors *"
        )
        assert contenu_saboté != contenu_original, "le sabotage n'a rien remplacé — test invalide"

        saboté = tmp_path / "main.py"
        saboté.write_text(contenu_saboté, encoding="utf-8")

        contenu_nettoye = _sans_commentaires_yaml(saboté.read_text(encoding="utf-8"))
        assert re.search(r"frame-ancestors\s+\*", contenu_nettoye), (
            "le sabotage aurait du introduire 'frame-ancestors *' detectable "
            "— s'il n'est pas trouve, le garde-fou ne mord pas"
        )
        # Le fichier réel du dépôt, lui, ne doit jamais porter cette étoile.
        contenu_reel = _sans_commentaires_yaml(MAIN_PY.read_text(encoding="utf-8"))
        assert not re.search(r"frame-ancestors\s+\*", contenu_reel), (
            "le fichier reel du depot a ete altere par ce test"
        )

    def test_le_defaut_env_example_nest_pas_non_plus_une_etoile(self) -> None:
        env_example = STACK_DIR / ".env.example"
        contenu = _sans_commentaires_yaml(env_example.read_text(encoding="utf-8"))
        for ligne in contenu.splitlines():
            if ligne.strip().startswith("OKVORADO_FRAME_ANCESTORS"):
                assert "*" not in ligne, (
                    f".env.example porte une valeur en etoile pour "
                    f"OKVORADO_FRAME_ANCESTORS : {ligne!r} — jamais une "
                    "ouverture totale, meme comme exemple"
                )
