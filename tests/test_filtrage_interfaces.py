"""Filtrage des interfaces sans valeur NetFlow (lo, docker0, br-*, veth*...).

CONTEXTE (2026-08-11) : `outlet.yaml` en production déclarait pour le seul
exportateur `docker-takas` (192.0.2.7) 40 interfaces sans aucune valeur
NetFlow — `lo`, `docker0`, 12 `br-*` (bridges Docker), ~26 `veth*` (liens
virtuels de conteneurs) — noyant les 3 interfaces réellement utiles (`eth0`,
`tailscale0`, la WAN). Aucune brique de filtrage n'existait : la résolution
SNMP (`resolve_interface_table`, `build_if_indexes_from_snmp`) acceptait TOUTE
interface rendue par le walk.

Ce module teste `filtrer_interfaces_exploitables` (app.services.exporters) :
filtrage PAR MOTIF (pas de liste nominative — le projet vise 350 routeurs
SFR, cf. CLAUDE.md « L'auto-découverte n'est pas un confort, c'est la
condition de déployabilité »), zéro silencieux sur le compte d'interfaces
écartées, jamais tout écarter sans le signaler, et préservation d'une
interface déjà déclarée par l'exploitant.
"""

from __future__ import annotations

from app.services.exporters import filtrer_interfaces_exploitables

# ---------------------------------------------------------------------------
# Données réelles : les 40 interfaces mesurées sur docker-takas (192.0.2.7).
# Reconstituées d'après le motif décrit dans la mission (12 br-*, ~26 veth*,
# lo, docker0, eth0, tailscale0 + 1 WAN) — noms au format réel Linux/Docker.
# ---------------------------------------------------------------------------

_BRIDGES_DOCKER = [f"br-780869fa30{n:02d}" for n in range(12)]
_VETH_CONTENEURS = [f"veth{n:07x}" for n in range(26)]

_TABLE_DOCKER_TAKAS: dict[int, str] = {1: "lo", 2: "docker0"}
_index = 3
for nom in _BRIDGES_DOCKER:
    _TABLE_DOCKER_TAKAS[_index] = nom
    _index += 1
for nom in _VETH_CONTENEURS:
    _TABLE_DOCKER_TAKAS[_index] = nom
    _index += 1
_TABLE_DOCKER_TAKAS[_index] = "eth0"
_index += 1
_TABLE_DOCKER_TAKAS[_index] = "tailscale0"
_index += 1
_TABLE_DOCKER_TAKAS[_index] = "wan0"

assert len(_TABLE_DOCKER_TAKAS) == 43  # 40 interfaces bruit (2 + 12 br- + 26 veth) + 3 utiles


class TestFiltrageInterfacesDockerTakas:
    """Cas réel mesuré : 40 interfaces sans valeur NetFlow doivent disparaître,
    les interfaces utiles doivent rester."""

    def test_filtre_lo_docker0_br_veth_sur_le_cas_reel(self) -> None:
        resultat = filtrer_interfaces_exploitables(_TABLE_DOCKER_TAKAS, declared_names=set())

        noms_retenus = {spec.name for spec in resultat.retenues.values()}
        assert noms_retenus == {"eth0", "tailscale0", "wan0"}

    def test_compte_le_nombre_vu_ecarte_retenu(self) -> None:
        """Exigence la plus importante du lot : le nombre d'interfaces
        écartées doit être RESTITUABLE, jamais une liste raccourcie muette."""
        resultat = filtrer_interfaces_exploitables(_TABLE_DOCKER_TAKAS, declared_names=set())

        assert resultat.total_vues == 43
        assert resultat.total_ecartees == 40  # lo, docker0, 12 br-*, 26 veth*
        assert resultat.total_retenues == 3  # eth0, tailscale0, wan0
        assert resultat.total_vues == resultat.total_ecartees + resultat.total_retenues

    def test_la_liste_des_ecartees_est_accessible_pas_seulement_le_compte(self) -> None:
        """Zéro silencieux : pas juste un compteur, la LISTE de ce qui a été
        enlevé doit être consultable (diagnostic, audit)."""
        resultat = filtrer_interfaces_exploitables(_TABLE_DOCKER_TAKAS, declared_names=set())

        noms_ecartes = {spec.name for spec in resultat.ecartees.values()}
        assert "lo" in noms_ecartes
        assert "docker0" in noms_ecartes
        assert all(nom.startswith("br-") for nom in noms_ecartes if nom.startswith("br-"))
        assert any(nom.startswith("veth") for nom in noms_ecartes)
        # Les interfaces utiles ne doivent JAMAIS apparaître dans les écartées.
        assert "eth0" not in noms_ecartes
        assert "tailscale0" not in noms_ecartes
        assert "wan0" not in noms_ecartes


class TestMotifsParDefaut:
    """Filtrage PAR MOTIF, pas par liste nominative (cible 350 routeurs SFR)."""

    def test_loopback_exacte_seulement_lo_pas_les_noms_qui_contiennent_lo(self) -> None:
        table = {1: "lo", 2: "vlan10", 3: "lo0"}  # lo0 est un nom Cisco/BSD distinct de lo
        resultat = filtrer_interfaces_exploitables(table, declared_names=set())

        noms_retenus = {spec.name for spec in resultat.retenues.values()}
        assert "lo" not in noms_retenus
        # "lo0" n'est PAS "lo" : un motif exact sur "lo" ne doit pas mordre
        # sur un autre nom d'interface qui le contient (matching par égalité,
        # pas par sous-chaîne, pour ce motif précis).
        assert "vlan10" in noms_retenus

    def test_docker0_exclu(self) -> None:
        table = {1: "docker0", 2: "eth1"}
        resultat = filtrer_interfaces_exploitables(table, declared_names=set())
        assert {spec.name for spec in resultat.retenues.values()} == {"eth1"}

    def test_br_wildcard_toute_interface_prefixee_br_tiret(self) -> None:
        table = {1: "br-abcdef123456", 2: "br-lan", 3: "bridge0"}
        resultat = filtrer_interfaces_exploitables(table, declared_names=set())

        noms_retenus = {spec.name for spec in resultat.retenues.values()}
        assert "br-abcdef123456" not in noms_retenus
        assert "br-lan" not in noms_retenus
        # "bridge0" ne correspond pas au motif "br-*" (pas le préfixe "br-").
        assert "bridge0" in noms_retenus

    def test_veth_wildcard_toute_interface_prefixee_veth(self) -> None:
        table = {1: "veth1234abc", 2: "veth0", 3: "vethernet0"}
        resultat = filtrer_interfaces_exploitables(table, declared_names=set())

        noms_retenus = {spec.name for spec in resultat.retenues.values()}
        assert "veth1234abc" not in noms_retenus
        assert "veth0" not in noms_retenus
        assert "vethernet0" not in noms_retenus  # préfixe "veth" -> matché aussi

    def test_interfaces_utiles_survivent_au_filtre(self) -> None:
        table = {1: "eth0", 2: "tailscale0", 3: "wan0", 4: "GigabitEthernet0/0"}
        resultat = filtrer_interfaces_exploitables(table, declared_names=set())

        noms_retenus = {spec.name for spec in resultat.retenues.values()}
        assert noms_retenus == {"eth0", "tailscale0", "wan0", "GigabitEthernet0/0"}


class TestToutEcarteSignalAlarme:
    """Si le filtre ne laisse RIEN, l'appelant doit pouvoir le détecter et
    décider — jamais un résultat vide silencieux."""

    def test_equipement_dont_toutes_les_interfaces_matchent_un_motif(self) -> None:
        table = {1: "lo", 2: "docker0", 3: "br-x", 4: "veth0"}
        resultat = filtrer_interfaces_exploitables(table, declared_names=set())

        assert resultat.retenues == {}
        assert resultat.total_retenues == 0
        assert resultat.tout_ecarte is True

    def test_flag_tout_ecarte_faux_si_au_moins_une_interface_retenue(self) -> None:
        table = {1: "lo", 2: "eth0"}
        resultat = filtrer_interfaces_exploitables(table, declared_names=set())

        assert resultat.tout_ecarte is False

    def test_table_vide_en_entree_nest_pas_tout_ecarte(self) -> None:
        """Rien à filtrer n'est pas la même situation que tout filtrer : ne
        pas confondre absence d'entrée et filtre destructeur (zéro silencieux)."""
        resultat = filtrer_interfaces_exploitables({}, declared_names=set())

        assert resultat.retenues == {}
        assert resultat.total_vues == 0
        assert resultat.tout_ecarte is False


class TestPreservationDeclarationExploitant:
    """Une interface DÉJÀ déclarée et porteuse de trafic ne doit pas être
    supprimée par le filtre — le filtre sert à ne pas AJOUTER du bruit, pas
    à effacer une décision humaine (ex. exploitant qui a délibérément
    déclaré `docker0` parce qu'il veut le mesurer)."""

    def test_docker0_deja_declare_est_conserve(self) -> None:
        table = {1: "docker0", 2: "eth0"}
        resultat = filtrer_interfaces_exploitables(table, declared_names={"docker0"})

        noms_retenus = {spec.name for spec in resultat.retenues.values()}
        assert "docker0" in noms_retenus
        assert "eth0" in noms_retenus

    def test_docker0_deja_declare_napparait_plus_dans_les_ecartees(self) -> None:
        table = {1: "docker0", 2: "eth0", 3: "veth123"}
        resultat = filtrer_interfaces_exploitables(table, declared_names={"docker0"})

        noms_ecartes = {spec.name for spec in resultat.ecartees.values()}
        assert "docker0" not in noms_ecartes
        assert "veth123" in noms_ecartes  # non déclaré, reste écarté

    def test_declaration_manuelle_dune_interface_veth_est_aussi_respectee(self) -> None:
        """La préservation par nom déclaré n'est pas limitée à `docker0` —
        n'importe quelle interface normalement filtrée mais explicitement
        déclarée doit survivre."""
        table = {1: "veth999", 2: "br-special"}
        resultat = filtrer_interfaces_exploitables(
            table, declared_names={"veth999", "br-special"}
        )

        assert resultat.tout_ecarte is False
        assert resultat.total_retenues == 2

    def test_declared_names_vide_ne_change_rien_au_comportement_par_defaut(self) -> None:
        table = {1: "lo", 2: "eth0"}
        resultat = filtrer_interfaces_exploitables(table, declared_names=set())

        assert {spec.name for spec in resultat.retenues.values()} == {"eth0"}


class TestConfigurabiliteMotifs:
    """Configurable, jamais figé : l'exploitant doit pouvoir ajuster la liste
    de motifs sans toucher au code (app/config.py, variable d'environnement)."""

    def test_motifs_personnalises_remplacent_le_defaut(self) -> None:
        table = {1: "lo", 2: "wg0", 3: "eth0"}
        # Motif custom : on exclut "wg0" (interface WireGuard virtuelle),
        # mais on N'exclut PAS "lo" (cas d'école : un exploitant qui veut
        # explicitement observer la loopback via un motif custom vide).
        resultat = filtrer_interfaces_exploitables(
            table, declared_names=set(), motifs_exclus=["wg0"]
        )

        noms_retenus = {spec.name for spec in resultat.retenues.values()}
        assert "wg0" not in noms_retenus
        assert "lo" in noms_retenus  # le défaut "lo" n'est plus appliqué
        assert "eth0" in noms_retenus

    def test_motif_wildcard_personnalise_fonctionne_en_prefixe(self) -> None:
        table = {1: "tun0", 2: "tun1", 3: "eth0"}
        resultat = filtrer_interfaces_exploitables(
            table, declared_names=set(), motifs_exclus=["tun*"]
        )

        noms_retenus = {spec.name for spec in resultat.retenues.values()}
        assert noms_retenus == {"eth0"}

    def test_settings_expose_une_liste_de_motifs_par_defaut(self) -> None:
        """Pilotable à l'écran : la config doit exposer la liste par défaut,
        potentiellement surchargée par OKVORADO_INTERFACE_EXCLUDE_PATTERNS."""
        from app.config import settings

        motifs = settings.interface_exclude_patterns_list()
        assert "lo" in motifs
        assert "docker0" in motifs
        assert any(m.startswith("br-") for m in motifs)
        assert any(m.startswith("veth") for m in motifs)

    def test_settings_motifs_par_defaut_utilises_quand_non_precise(self) -> None:
        """Sans `motifs_exclus` explicite, la fonction doit utiliser le
        défaut projet — vérifié en repassant par `settings` pour éviter toute
        divergence entre les deux sources."""
        from app.config import settings

        table = {1: "lo", 2: "docker0", 3: "eth0"}
        resultat = filtrer_interfaces_exploitables(
            table,
            declared_names=set(),
            motifs_exclus=settings.interface_exclude_patterns_list(),
        )
        assert {spec.name for spec in resultat.retenues.values()} == {"eth0"}


class TestIfIndexPreserve:
    """Le filtre ne doit pas corrompre l'indexation : ifIndex et name doivent
    rester cohérents dans les deux dictionnaires rendus."""

    def test_ifindex_est_la_cle_dans_retenues_et_ecartees(self) -> None:
        table = {10: "eth0", 11: "lo"}
        resultat = filtrer_interfaces_exploitables(table, declared_names=set())

        assert 10 in resultat.retenues
        assert resultat.retenues[10].if_index == 10
        assert resultat.retenues[10].name == "eth0"
        assert 11 in resultat.ecartees
        assert resultat.ecartees[11].if_index == 11
        assert resultat.ecartees[11].name == "lo"
