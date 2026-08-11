"""Catalogue des champs de flux — ce que le stack EXPOSE face à ce qu'on en EXPLOITE.

À QUOI CE MODULE SERT (demande utilisateur du 2026-08-11) : soutenir une
présentation commerciale. L'objection attendue est « vos dashboards sont
légers » ; la réponse est de montrer, chiffres à l'appui, que la majorité du
potentiel NetFlow reste inexploitée et de désigner à l'écran les champs à
ajouter. Ce n'est donc pas une documentation technique : chaque ligne doit être
défendable devant un décideur.

TROIS GARDES STRUCTURANTES, toutes nées d'un risque de CRÉDIBILITÉ :

1. **Rien n'est figé.** Le total vient de `system.columns` (le schéma RÉEL,
   interrogé à chaque affichage), le compte des exploités vient des dashboards
   présents sur le disque. Un chiffre recopié depuis une mesure du jour
   deviendrait faux dès que le client active la géolocalisation, le BGP ou
   qu'on livre un dashboard de plus — et il deviendrait faux EN SILENCE, ce qui
   est la pire des issues devant un client.

   POURQUOI PAS `flow_sample.FLOW_COLUMNS` COMME TOTAL : cette table statique
   est un relevé du 2026-08-06 (61 colonnes). Elle ne contient PAS `IPTos`,
   pourtant présente en production et consommée par 4 dashboards — la preuve
   par l'exemple qu'un schéma recopié dérive du réel. `FLOW_COLUMNS` reste
   utilisée, mais UNIQUEMENT comme dictionnaire de libellés FR (UN concept =
   UNE source : les libellés ne sont pas redéfinis ici).

2. **Aucun faux positif de détection.** Dire « déjà exploité » à tort ferait
   sous-estimer le potentiel restant, c'est-à-dire saborder l'argument. La
   détection se fait sur les seules REQUÊTES (`rawSql`), à la frontière de mot.
   Les `description` de panneaux sont ignorées : plusieurs dashboards réels
   citent `IPTos` en prose (« DSCP = bitShiftRight(IPTos, 2) »), et les scanner
   ferait passer pour exploité un champ seulement mentionné.

3. **L'ORIGINE de la donnée prime sur son remplissage ici.** Correction de
   cadrage de l'utilisateur : « là sur mon infra il n'y a pas de firewall donc
   des infos comme le routage et j'en passe ne seront pas visibles ».

   Les 11 exportateurs de cette maquette sont des serveurs Linux sous softflowd
   (`README.md` documente déjà que softflowd 1.1.0 ne renseigne même pas les
   interfaces). Aucun routeur, aucun pare-feu. Un champ vide ICI peut être
   parfaitement rempli CHEZ LE CLIENT. Présenter un 0 % de la MAQUETTE comme
   une limite du PRODUIT serait le contresens commercial le plus coûteux de
   cette présentation. D'où le classement par origine, et non par remplissage.

ZÉRO SILENCIEUX (règle dure du projet) : ClickHouse muet, dossier de dashboards
absent et mesure de remplissage en échec produisent trois états DISTINCTS et
visibles. Jamais un catalogue vide, jamais « 0 champ », jamais « 0 % » — 0 %
signifie « champ mesuré vide », l'exact contraire d'une mesure manquante.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from app.services.flow_sample import FLOW_COLUMNS

log = logging.getLogger(__name__)


class ClickHouseQueryable(Protocol):
    """Contrat minimal attendu du client — permet d'injecter un double en test."""

    def query(self, sql: str, parameters: dict[str, Any] | None = None) -> Any: ...


# ---------------------------------------------------------------------------
# Origine de la donnée — LA dimension qui sauve la présentation
# ---------------------------------------------------------------------------

ORIGIN_PROTOCOL = "protocol"
"""Porté par NetFlow/IPFIX quelle que soit la source. Fonctionne dès le premier
flux, sur n'importe quelle infrastructure — y compris cette maquette."""

ORIGIN_NETWORK_EQUIPMENT = "network_equipment"
"""Fourni par un ÉQUIPEMENT réseau (routeur, pare-feu). Vide sur cette maquette
FAUTE DE SOURCE et non faute de configuration : un serveur Linux sous softflowd
ne connaît ni table de routage BGP, ni masque appris, ni politique de sécurité.
Un routeur SFR ou un Palo Alto les émet nativement.

C'EST LA CATÉGORIE À METTRE EN AVANT : elle transforme un « 0 % » embarrassant
en argument de déploiement."""

ORIGIN_COLLECTOR_ENRICHMENT = "collector_enrichment"
"""Ajouté par Akvorado, absent de tout flux : base GeoIP, déclarations statiques
de `outlet.yaml` (`networks:`, groupes/sites d'exportateurs), résolution SNMP.
Indépendant des équipements — c'est une configuration du COLLECTEUR."""

ORIGIN_LABELS: dict[str, str] = {
    ORIGIN_PROTOCOL: "Toujours disponible",
    ORIGIN_NETWORK_EQUIPMENT: "Fourni par un équipement réseau",
    ORIGIN_COLLECTOR_ENRICHMENT: "Enrichissement du collecteur",
}

ORIGIN_DESCRIPTIONS: dict[str, str] = {
    ORIGIN_PROTOCOL: (
        "Le protocole NetFlow/IPFIX porte ce champ quelle que soit la source. "
        "Exploitable dès le premier flux reçu, sans aucune configuration."
    ),
    ORIGIN_NETWORK_EQUIPMENT: (
        "Ce champ est renseigné par un routeur ou un pare-feu. Il est vide sur "
        "cette maquette parce qu'elle n'en contient aucun — les exportateurs "
        "sont des serveurs Linux sous softflowd. Un routeur SFR ou un pare-feu "
        "Palo Alto l'émet nativement : la donnée apparaîtra le jour où ces "
        "équipements exporteront vers le collecteur."
    ),
    ORIGIN_COLLECTOR_ENRICHMENT: (
        "La donnée n'existe dans aucun flux : c'est le collecteur qui l'ajoute "
        "(base GeoIP, déclarations statiques, résolution SNMP). Une "
        "configuration à poser sur Akvorado, indépendante des équipements."
    ),
}

ORIGIN_ORDER: tuple[str, ...] = (
    ORIGIN_PROTOCOL,
    ORIGIN_NETWORK_EQUIPMENT,
    ORIGIN_COLLECTOR_ENRICHMENT,
)

USAGE_CHOICES: frozenset[str] = frozenset({"all", "used", "unused"})
"""Énumération FERMÉE du filtre d'exploitation — une valeur hors liste est
refusée, jamais interpolée (garde d'allowlist du projet)."""


# ---------------------------------------------------------------------------
# Référentiel métier — catégorie, origine, argument de vente
# ---------------------------------------------------------------------------

CATEGORY_EXPORTER = "Exportateur"
CATEGORY_ADDRESSING = "Adressage"
CATEGORY_ROUTING = "Routage / BGP"
CATEGORY_INTERFACES = "Interfaces"
CATEGORY_GEO = "Géolocalisation"
CATEGORY_APPLICATION = "Applicatif / ports"
CATEGORY_VOLUME = "Volumétrie"
CATEGORY_QOS = "QoS"
CATEGORY_TIME = "Temps"
CATEGORY_OTHER = "Autres champs"

CATEGORY_ORDER: tuple[str, ...] = (
    CATEGORY_VOLUME,
    CATEGORY_ADDRESSING,
    CATEGORY_APPLICATION,
    CATEGORY_ROUTING,
    CATEGORY_INTERFACES,
    CATEGORY_QOS,
    CATEGORY_GEO,
    CATEGORY_EXPORTER,
    CATEGORY_TIME,
    CATEGORY_OTHER,
)


@dataclass(frozen=True)
class FieldSemantics:
    """Ce qu'on sait dire d'un champ AU-DELÀ de son type ClickHouse.

    `potential_usage` est LA valeur de cet écran : une phrase concrète, vendable
    à un exploitant réseau. Une paraphrase du nom (« le chemin d'AS destination
    contient le chemin d'AS ») ne sert à rien en réunion — il faut le cas
    d'usage, c'est-à-dire la décision que le champ permet de prendre.
    """

    category: str
    origin: str
    potential_usage: str
    required_action: str = ""
    """Ce qu'il faut FAIRE pour obtenir la donnée. Vide pour un champ déjà
    porté par le protocole. Renseigné sinon : brancher tel équipement, ou
    activer telle configuration du collecteur."""


_ACTION_EQUIPMENT = (
    "Brancher un routeur ou un pare-feu (SFR, Palo Alto…) exportant en NetFlow "
    "v9 / IPFIX : ces équipements émettent ce champ nativement. Invisible sur "
    "cette maquette, dont les exportateurs sont des serveurs Linux (softflowd)."
)
_ACTION_BGP = (
    "Brancher un routeur ou un pare-feu exportant en NetFlow v9 / IPFIX, et "
    "établir la session BGP/BMP entre Akvorado et ce routeur : les attributs "
    "de chemin viennent de la table de routage, pas du flux lui-même."
)
_ACTION_GEOIP = (
    "Monter une base GeoIP (MaxMind GeoLite2) dans le collecteur Akvorado et "
    "l'activer dans la configuration : la donnée se dérive des adresses déjà "
    "présentes, aucun équipement supplémentaire n'est requis."
)
_ACTION_STATIC = (
    "Déclarer la correspondance dans la configuration du collecteur "
    "(section `networks:` d'outlet.yaml) : pilotable depuis l'écran "
    "Configuration d'Okvorado, sans toucher aux équipements."
)
_ACTION_SNMP = (
    "Activer la résolution SNMP sur les exportateurs (communauté en variable "
    "d'environnement) : Akvorado interroge alors l'équipement pour compléter "
    "ces attributs d'interface."
)
_ACTION_EXPORTER_META = (
    "Déclarer l'attribut sur l'exportateur dans la configuration du collecteur "
    "(classifieurs d'exportateurs) : c'est une donnée d'inventaire, pas une "
    "donnée de flux."
)

# Le référentiel. Chaque phrase est écrite pour être LUE À VOIX HAUTE devant un
# décideur : elle nomme la décision que le champ permet, pas le champ.
FIELD_SEMANTICS: dict[str, FieldSemantics] = {
    # --- Temps et volumétrie : le socle, toujours là -----------------------
    "TimeReceived": FieldSemantics(
        CATEGORY_TIME,
        ORIGIN_PROTOCOL,
        "Dater chaque flux : l'axe de toute courbe de trafic et de toute "
        "corrélation d'incident.",
    ),
    "SamplingRate": FieldSemantics(
        CATEGORY_VOLUME,
        ORIGIN_PROTOCOL,
        "Rétablir le volume réel quand le routeur n'échantillonne qu'un flux "
        "sur mille : sans lui, tout volume est faux d'un facteur 1000.",
    ),
    "Bytes": FieldSemantics(
        CATEGORY_VOLUME,
        ORIGIN_PROTOCOL,
        "Mesurer le volume transporté : la métrique de base de toute "
        "facturation et de tout dimensionnement de lien.",
    ),
    "Packets": FieldSemantics(
        CATEGORY_VOLUME,
        ORIGIN_PROTOCOL,
        "Compter les paquets : un volume faible avec un nombre de paquets élevé "
        "trahit une attaque ou un protocole bavard.",
    ),
    "PacketSize": FieldSemantics(
        CATEGORY_VOLUME,
        ORIGIN_PROTOCOL,
        "Repérer les flux à très petits paquets, signature d'un scan ou d'un "
        "déni de service, qu'une courbe de volume ne montre jamais.",
    ),
    "PacketSizeBucket": FieldSemantics(
        CATEGORY_VOLUME,
        ORIGIN_PROTOCOL,
        "Classer le trafic par taille de paquet sans calcul : distinguer d'un "
        "coup d'œil la voix (petits paquets réguliers) du transfert de fichiers.",
    ),
    "FlowDirection": FieldSemantics(
        CATEGORY_VOLUME,
        ORIGIN_PROTOCOL,
        "Séparer l'entrant du sortant : mesurer l'asymétrie d'un lien et "
        "dimensionner la bonne direction.",
    ),
    "ForwardingStatus": FieldSemantics(
        CATEGORY_QOS,
        ORIGIN_PROTOCOL,
        "Voir les flux REFUSÉS par l'équipement : un pare-feu qui bloque, une "
        "ACL trop stricte, un routage absent — la panne que le trafic accepté "
        "ne montre pas.",
    ),
    "EType": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_PROTOCOL,
        "Distinguer IPv4 d'IPv6 : mesurer l'avancement réel d'une migration "
        "IPv6 sur le parc.",
    ),
    "Proto": FieldSemantics(
        CATEGORY_APPLICATION,
        ORIGIN_PROTOCOL,
        "Répartir le trafic par protocole (TCP, UDP, ICMP) : une bascule "
        "soudaine vers UDP signale souvent une attaque volumétrique.",
    ),
    "IPTos": FieldSemantics(
        CATEGORY_QOS,
        ORIGIN_PROTOCOL,
        "Lire le marquage DSCP : vérifier que la voix et la vidéo sont bien "
        "prioritaires et que la QoS appliquée correspond à celle contractée.",
    ),
    # --- Adressage ---------------------------------------------------------
    "SrcAddr": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_PROTOCOL,
        "Identifier qui émet : remonter d'un pic de trafic à la machine "
        "responsable.",
    ),
    "DstAddr": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_PROTOCOL,
        "Identifier la destination : repérer une machine qui parle à un "
        "serveur inattendu.",
    ),
    "SrcPort": FieldSemantics(
        CATEGORY_APPLICATION,
        ORIGIN_PROTOCOL,
        "Reconnaître le service émetteur : distinguer un client d'un serveur "
        "dans une conversation.",
    ),
    "DstPort": FieldSemantics(
        CATEGORY_APPLICATION,
        ORIGIN_PROTOCOL,
        "Identifier l'application visée : bâtir la répartition applicative "
        "(web, DNS, sauvegarde) qui parle à un décideur.",
    ),
    "SrcNetPrefix": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_PROTOCOL,
        "Agréger le trafic par plage d'adresses plutôt que machine par "
        "machine : le trafic d'un site tient alors sur une ligne.",
    ),
    "DstNetPrefix": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_PROTOCOL,
        "Agréger les destinations par plage : voir vers quels réseaux part le "
        "trafic sans se noyer dans les adresses individuelles.",
    ),
    "SrcNetMask": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_NETWORK_EQUIPMENT,
        "Connaître la taille du réseau d'origine telle que le routeur la "
        "connaît : rattacher un flux au bon sous-réseau sans table de "
        "correspondance à maintenir.",
        _ACTION_EQUIPMENT,
    ),
    "DstNetMask": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_NETWORK_EQUIPMENT,
        "Connaître la taille du réseau de destination vue par le routeur : "
        "mesurer la dispersion du trafic entre sous-réseaux.",
        _ACTION_EQUIPMENT,
    ),
    # --- Routage / BGP -----------------------------------------------------
    "SrcAS": FieldSemantics(
        CATEGORY_ROUTING,
        ORIGIN_NETWORK_EQUIPMENT,
        "Savoir de quel opérateur provient le trafic entrant : identifier la "
        "source d'une attaque ou d'un pic venu de l'extérieur.",
        _ACTION_EQUIPMENT,
    ),
    "DstAS": FieldSemantics(
        CATEGORY_ROUTING,
        ORIGIN_NETWORK_EQUIPMENT,
        "Savoir vers quel opérateur part le trafic : mesurer la dépendance à "
        "un fournisseur (Google, AWS, Microsoft) et négocier le transit.",
        _ACTION_EQUIPMENT,
    ),
    "DstASPath": FieldSemantics(
        CATEGORY_ROUTING,
        ORIGIN_NETWORK_EQUIPMENT,
        "Voir par quels opérateurs transite le trafic : détecter un reroutage "
        "BGP anormal ou un détour qui explique une latence.",
        _ACTION_BGP,
    ),
    "Dst1stAS": FieldSemantics(
        CATEGORY_ROUTING,
        ORIGIN_NETWORK_EQUIPMENT,
        "Identifier le premier opérateur traversé : vérifier que le trafic "
        "sort bien par le transitaire prévu au contrat.",
        _ACTION_BGP,
    ),
    "Dst2ndAS": FieldSemantics(
        CATEGORY_ROUTING,
        ORIGIN_NETWORK_EQUIPMENT,
        "Voir le deuxième saut opérateur : repérer un changement de route "
        "amont invisible depuis le premier saut.",
        _ACTION_BGP,
    ),
    "Dst3rdAS": FieldSemantics(
        CATEGORY_ROUTING,
        ORIGIN_NETWORK_EQUIPMENT,
        "Voir le troisième saut opérateur : reconstituer la chaîne de transit "
        "sur un incident de bout en bout.",
        _ACTION_BGP,
    ),
    "DstCommunities": FieldSemantics(
        CATEGORY_ROUTING,
        ORIGIN_NETWORK_EQUIPMENT,
        "Lire les étiquettes BGP posées par l'opérateur : distinguer trafic "
        "national, européen et international, souvent facturés différemment.",
        _ACTION_BGP,
    ),
    "DstLargeCommunities": FieldSemantics(
        CATEGORY_ROUTING,
        ORIGIN_NETWORK_EQUIPMENT,
        "Exploiter les étiquettes BGP étendues des grands opérateurs : "
        "affiner le rattachement d'un flux à une offre de transit.",
        _ACTION_BGP,
    ),
    # --- Interfaces --------------------------------------------------------
    "InIfName": FieldSemantics(
        CATEGORY_INTERFACES,
        ORIGIN_PROTOCOL,
        "Savoir par quelle interface le trafic entre : localiser le lien qui "
        "sature.",
    ),
    "OutIfName": FieldSemantics(
        CATEGORY_INTERFACES,
        ORIGIN_PROTOCOL,
        "Savoir par quelle interface le trafic sort : vérifier l'équilibrage "
        "entre deux liens.",
    ),
    "InIfSpeed": FieldSemantics(
        CATEGORY_INTERFACES,
        ORIGIN_PROTOCOL,
        "Rapporter le trafic à la capacité du lien : passer d'un volume brut à "
        "un taux de saturation, la seule métrique qui déclenche un upgrade.",
    ),
    "OutIfSpeed": FieldSemantics(
        CATEGORY_INTERFACES,
        ORIGIN_PROTOCOL,
        "Mesurer la saturation en sortie : anticiper la commande de bande "
        "passante avant la plainte utilisateur.",
    ),
    "InIfDescription": FieldSemantics(
        CATEGORY_INTERFACES,
        ORIGIN_PROTOCOL,
        "Lire le libellé posé par l'exploitant sur l'interface : parler de "
        "« lien MPLS Lyon » plutôt que de « ifIndex 3 » en réunion.",
    ),
    "OutIfDescription": FieldSemantics(
        CATEGORY_INTERFACES,
        ORIGIN_PROTOCOL,
        "Nommer l'interface de sortie en langage d'exploitant : rendre un "
        "tableau lisible sans connaître la numérotation des équipements.",
    ),
    "InIfBoundary": FieldSemantics(
        CATEGORY_INTERFACES,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Séparer automatiquement l'interne de l'externe en entrée : obtenir le "
        "ratio transit / local par site sans écrire une seule règle.",
        _ACTION_STATIC,
    ),
    "OutIfBoundary": FieldSemantics(
        CATEGORY_INTERFACES,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Séparer l'interne de l'externe en sortie : mesurer ce qui quitte "
        "réellement l'entreprise, base de toute analyse de fuite de données.",
        _ACTION_STATIC,
    ),
    "InIfConnectivity": FieldSemantics(
        CATEGORY_INTERFACES,
        ORIGIN_NETWORK_EQUIPMENT,
        "Qualifier le type de lien entrant (transit, peering, client) : "
        "répartir le trafic entre liens payants et liens gratuits.",
        _ACTION_SNMP,
    ),
    "OutIfConnectivity": FieldSemantics(
        CATEGORY_INTERFACES,
        ORIGIN_NETWORK_EQUIPMENT,
        "Qualifier le type de lien sortant : arbitrer une renégociation de "
        "transit avec des chiffres.",
        _ACTION_SNMP,
    ),
    "InIfProvider": FieldSemantics(
        CATEGORY_INTERFACES,
        ORIGIN_NETWORK_EQUIPMENT,
        "Attribuer le trafic entrant à l'opérateur qui le porte : comparer "
        "les fournisseurs sur des volumes réels.",
        _ACTION_SNMP,
    ),
    "OutIfProvider": FieldSemantics(
        CATEGORY_INTERFACES,
        ORIGIN_NETWORK_EQUIPMENT,
        "Attribuer le trafic sortant à son opérateur : vérifier que la "
        "répartition contractuelle est respectée.",
        _ACTION_SNMP,
    ),
    # --- Géolocalisation ---------------------------------------------------
    "SrcCountry": FieldSemantics(
        CATEGORY_GEO,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Cartographier l'origine du trafic entrant par pays : repérer une "
        "sollicitation venue d'une zone sans lien avec l'activité.",
        _ACTION_GEOIP,
    ),
    "DstCountry": FieldSemantics(
        CATEGORY_GEO,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Cartographier le trafic sortant par pays : détecter une exfiltration "
        "vers une destination inhabituelle.",
        _ACTION_GEOIP,
    ),
    "SrcGeoCity": FieldSemantics(
        CATEGORY_GEO,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Descendre à la ville d'origine : distinguer un accès légitime d'une "
        "connexion depuis une zone improbable.",
        _ACTION_GEOIP,
    ),
    "DstGeoCity": FieldSemantics(
        CATEGORY_GEO,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Descendre à la ville de destination : illustrer sur une carte où part "
        "réellement le trafic de l'entreprise.",
        _ACTION_GEOIP,
    ),
    "SrcGeoState": FieldSemantics(
        CATEGORY_GEO,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Regrouper l'origine par région : suivre le trafic par zone "
        "géographique plutôt que par ville isolée.",
        _ACTION_GEOIP,
    ),
    "DstGeoState": FieldSemantics(
        CATEGORY_GEO,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Regrouper les destinations par région : mesurer l'empreinte "
        "géographique des échanges.",
        _ACTION_GEOIP,
    ),
    # --- Enrichissement réseau (déclarations statiques) --------------------
    "SrcNetName": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Nommer le réseau source (« LAN Lyon », « DMZ ») au lieu d'une plage "
        "d'adresses : rendre un tableau compréhensible par un non-réseau.",
        _ACTION_STATIC,
    ),
    "DstNetName": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Nommer le réseau de destination : lire une matrice de trafic en noms "
        "métier plutôt qu'en CIDR.",
        _ACTION_STATIC,
    ),
    "SrcNetRole": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Distinguer serveurs, postes et DMZ à la source : mesurer le trafic "
        "est-ouest qu'un pare-feu périmétrique ne voit pas.",
        _ACTION_STATIC,
    ),
    "DstNetRole": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Distinguer le rôle du réseau visé : repérer un poste qui accède "
        "directement à un segment serveur sans passer par le pare-feu.",
        _ACTION_STATIC,
    ),
    "SrcNetSite": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Rattacher le trafic à son site d'origine : comparer 350 agences sur "
        "une même échelle.",
        _ACTION_STATIC,
    ),
    "DstNetSite": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Rattacher la destination à un site : mesurer les échanges "
        "inter-agences et dimensionner le réseau interne.",
        _ACTION_STATIC,
    ),
    "SrcNetRegion": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Agréger les sites d'origine par région : produire un reporting par "
        "direction régionale sans requête manuelle.",
        _ACTION_STATIC,
    ),
    "DstNetRegion": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Agréger les destinations par région : suivre les flux entre grandes "
        "zones du réseau d'entreprise.",
        _ACTION_STATIC,
    ),
    "SrcNetTenant": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Attribuer le trafic à une entité ou filiale : refacturer la "
        "consommation réseau à son propriétaire.",
        _ACTION_STATIC,
    ),
    "DstNetTenant": FieldSemantics(
        CATEGORY_ADDRESSING,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Identifier l'entité destinataire : mesurer les échanges entre "
        "filiales et isoler les flux mutualisés.",
        _ACTION_STATIC,
    ),
    # --- Exportateur -------------------------------------------------------
    "ExporterAddress": FieldSemantics(
        CATEGORY_EXPORTER,
        ORIGIN_PROTOCOL,
        "Identifier l'équipement émetteur par son adresse : remonter au "
        "routeur exact d'où vient une mesure.",
    ),
    "ExporterName": FieldSemantics(
        CATEGORY_EXPORTER,
        ORIGIN_PROTOCOL,
        "Nommer l'équipement émetteur : filtrer un dashboard sur un site sans "
        "connaître son adresse.",
    ),
    "ExporterRole": FieldSemantics(
        CATEGORY_EXPORTER,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Comparer les équipements par rôle (cœur, accès, sortie) : détecter "
        "l'agence dont le profil s'écarte des autres.",
        _ACTION_EXPORTER_META,
    ),
    "ExporterGroup": FieldSemantics(
        CATEGORY_EXPORTER,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Regrouper les exportateurs par famille : suivre un parc de 350 "
        "routeurs par lots plutôt qu'un par un.",
        _ACTION_EXPORTER_META,
    ),
    "ExporterSite": FieldSemantics(
        CATEGORY_EXPORTER,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Rattacher chaque équipement à son site : classer les agences par "
        "consommation et cibler celles à faire évoluer.",
        _ACTION_EXPORTER_META,
    ),
    "ExporterRegion": FieldSemantics(
        CATEGORY_EXPORTER,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Agréger les équipements par région : un reporting par direction "
        "régionale, sans construire de requête.",
        _ACTION_EXPORTER_META,
    ),
    "ExporterTenant": FieldSemantics(
        CATEGORY_EXPORTER,
        ORIGIN_COLLECTOR_ENRICHMENT,
        "Attribuer un équipement à une entité : cloisonner les vues entre "
        "filiales dans un déploiement mutualisé.",
        _ACTION_EXPORTER_META,
    ),
}

_DEFAULT_SEMANTICS = FieldSemantics(
    CATEGORY_OTHER,
    ORIGIN_PROTOCOL,
    "Champ présent dans le schéma mais non encore qualifié : à examiner pour "
    "déterminer ce qu'il permettrait de mesurer.",
)


# ---------------------------------------------------------------------------
# Structures de sortie
# ---------------------------------------------------------------------------

_LABELS_BY_NAME: dict[str, str] = {column.name: column.label for column in FLOW_COLUMNS}
"""Libellés FR — SEULE chose reprise de `flow_sample.FLOW_COLUMNS`.

UN concept = UNE source : les libellés ne sont pas redéfinis ici. En revanche
la LISTE des colonnes ne vient pas de là (cf. docstring de module) : cette table
est un relevé statique qui a déjà dérivé du schéma réel."""


@dataclass(frozen=True)
class FlowSchemaColumn:
    """Une colonne telle que ClickHouse la déclare AUJOURD'HUI."""

    name: str
    clickhouse_type: str

    @property
    def label(self) -> str:
        """Libellé FR si connu, sinon le nom brut — jamais vide.

        Une colonne inconnue du référentiel reste AFFICHÉE : une colonne
        ajoutée par une future version d'Akvorado est précisément du potentiel
        à montrer, la masquer irait contre l'objet de l'écran.
        """
        return _LABELS_BY_NAME.get(self.name, self.name)


@dataclass(frozen=True)
class CatalogEntry:
    """Un champ, avec tout ce qui permet d'en parler en réunion."""

    name: str
    label: str
    clickhouse_type: str
    category: str
    origin: str
    used: bool
    """Exploité par au moins un dashboard RÉELLEMENT ALIMENTÉ.

    Un champ visé uniquement par un dashboard « en avance de phase » (qui rend
    « No data ») n'est PAS exploité : il est PRÉPARÉ. Les confondre avait fait
    chuter le potentiel inexploité annoncé de 69 % à 32 % (mesuré le
    2026-08-11 sur trois dashboards depuis retirés) sans qu'aucune donnée
    supplémentaire ne soit affichée nulle part."""

    dashboards: list[str]
    pending_dashboards: list[str] = field(default_factory=list)
    """Dashboards livrés en avance de phase qui consomment ce champ — l'écran
    les montre comme « prêt », jamais comme « exploité »."""

    potential_usage: str = ""
    required_action: str = ""
    fill_rate: float | None = None
    """Taux de remplissage MESURÉ, en pourcentage.

    `0.0` = mesuré, et le champ est vide (information exploitable : il manque
    une source ou une configuration). `None` = NON MESURÉ (la requête a échoué).
    Confondre les deux serait le zéro silencieux : « je n'ai pas pu mesurer »
    s'afficherait comme « le champ est vide »."""

    @property
    def origin_label(self) -> str:
        return ORIGIN_LABELS.get(self.origin, self.origin)

    @property
    def prepared(self) -> bool:
        """Champ non exploité, mais dont un dashboard existe DÉJÀ, prêt à
        s'alimenter dès que la source émettra. C'est l'argument « le stack
        n'attend que l'équipement », distinct de « exploité »."""
        return not self.used and bool(self.pending_dashboards)

    @property
    def fill_rate_display(self) -> str:
        """Texte prêt pour l'écran, qui ne ment jamais par omission."""
        if self.fill_rate is None:
            return "indisponible"
        if self.fill_rate == 0:
            return "0 %"
        if self.fill_rate < 1:
            return "< 1 %"
        return f"{self.fill_rate:.0f} %"


@dataclass(frozen=True)
class DashboardUsage:
    """Ce que les dashboards consomment réellement, et ce qu'on n'a pas pu lire."""

    columns_by_name: dict[str, list[str]] = field(default_factory=dict)
    dashboard_titles: list[str] = field(default_factory=list)
    unreadable_files: list[str] = field(default_factory=list)
    """Fichiers présents mais illisibles (JSON corrompu). Signalés et non
    ignorés : un dashboard qu'on n'arrive pas à lire retirerait silencieusement
    ses champs du compte des exploités, donc GONFLERAIT le potentiel annoncé."""

    directory_found: bool = True


@dataclass(frozen=True)
class FieldCatalog:
    """Le catalogue complet, prêt à afficher.

    Les compteurs sont `None` — jamais `0` — quand la mesure correspondante n'a
    pas pu être faite. C'est ce qui rend l'état d'indisponibilité impossible à
    confondre avec une mesure.
    """

    entries: list[CatalogEntry]
    schema_available: bool
    dashboards_available: bool
    fill_rates_available: bool
    error_message: str = ""
    unreadable_dashboards: list[str] = field(default_factory=list)
    dashboard_titles: list[str] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        return len(self.entries)

    @property
    def used_count(self) -> int | None:
        """`None` si les dashboards n'ont pas pu être lus : annoncer « 0
        exploité » serait un mensonge FLATTEUR pour la démonstration (100 % de
        potentiel), donc exactement celui qu'il faut interdire."""
        if not self.dashboards_available:
            return None
        return sum(1 for entry in self.entries if entry.used)

    @property
    def prepared_count(self) -> int | None:
        """Champs non exploités mais dont un dashboard existe déjà, en attente
        de la source. C'est le sous-ensemble le plus vendable des inexploités :
        « rien à développer, il ne manque que l'équipement »."""
        if not self.dashboards_available:
            return None
        return sum(1 for entry in self.entries if entry.prepared)

    @property
    def unused_count(self) -> int | None:
        used = self.used_count
        if used is None:
            return None
        return self.total_count - used

    @property
    def unused_percent(self) -> int | None:
        unused = self.unused_count
        if unused is None or not self.total_count:
            return None
        return round(unused * 100 / self.total_count)

    def by_category(self) -> dict[str, list[CatalogEntry]]:
        """Regroupe par catégorie métier, dans l'ordre de lecture voulu.

        Un tableau de 62 lignes à plat est illisible en présentation : c'est le
        regroupement qui rend l'écran défendable à l'oral."""
        groups: OrderedDict[str, list[CatalogEntry]] = OrderedDict()
        for category in CATEGORY_ORDER:
            members = [entry for entry in self.entries if entry.category == category]
            if members:
                groups[category] = members
        # Une catégorie hors référentiel (champ inédit) ne doit pas disparaître.
        for entry in self.entries:
            if entry.category not in groups:
                groups.setdefault(entry.category, []).append(entry)
        return groups

    def filtered(
        self, *, usage: str = "all", origin: str = "", category: str = ""
    ) -> list[CatalogEntry]:
        """Filtre à la demande de l'écran.

        Les valeurs viennent d'énumérations FERMÉES validées en amont par le
        routeur : rien n'est interpolé, une valeur inconnue est refusée avant
        d'arriver ici.
        """
        result = list(self.entries)
        if usage == "used":
            result = [entry for entry in result if entry.used]
        elif usage == "unused":
            result = [entry for entry in result if not entry.used]
        if origin:
            result = [entry for entry in result if entry.origin == origin]
        if category:
            result = [entry for entry in result if entry.category == category]
        return result


# ---------------------------------------------------------------------------
# Lecture du schéma réel
# ---------------------------------------------------------------------------

FLOWS_TABLE = "flows"
"""Nom de la table, LITTÉRAL du code et passé en paramètre lié — jamais
concaténé depuis une saisie."""


class FieldCatalogUnavailableError(RuntimeError):
    """Le schéma n'a pas pu être lu — distinct d'un schéma vide."""


def read_flow_columns(client: ClickHouseQueryable) -> list[FlowSchemaColumn]:
    """Lit les colonnes RÉELLES de la table de flux via `system.columns`.

    C'est la source de vérité du total affiché. `app/routers/views.py` utilise
    déjà ce mécanisme pour détecter `IPTos` — dont l'absence de
    `flow_sample.FLOW_COLUMNS` prouve qu'un schéma recopié dérive du réel.

    Raises:
        FieldCatalogUnavailableError: la requête n'a pas abouti. Pas de `[]` :
            « je n'ai pas pu lire le schéma » doit rester distinct de « le
            schéma est vide ».
    """
    sql = (
        "SELECT name, type FROM system.columns "
        "WHERE table = {table:String} ORDER BY position"
    )
    try:
        result = client.query(sql, {"table": FLOWS_TABLE})
    except Exception as exc:
        log.error("field_catalog: echec lecture system.columns", exc_info=True)
        raise FieldCatalogUnavailableError(f"schema de flux non lu: {exc}") from exc

    return [
        FlowSchemaColumn(name=str(row[0]), clickhouse_type=str(row[1]))
        for row in result.result_rows
    ]


# ---------------------------------------------------------------------------
# Mesure du remplissage
# ---------------------------------------------------------------------------

FILL_RATE_WINDOW_SECONDS = 86_400
"""Fenêtre de mesure du remplissage : 24 h.

Assez large pour que les champs à événements rares apparaissent, assez courte
pour que la requête reste bornée sur une table de ~60 M de lignes."""

_IDENTIFIER_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
"""Allowlist de forme. Un nom de colonne vient du schéma, donc d'une source de
confiance — mais il transite par une f-string pour construire les `countIf()`,
et ClickHouse n'accepte pas de paramètre lié à la place d'un nom de colonne.
Cette validation est la garde qui rend l'injection impossible malgré cela."""


def _fill_rate_aliases(sql: str) -> list[str]:
    """Extrait les alias `AS fill_<nom>` d'une requête de remplissage.

    Utilisé par les doubles de test pour rendre des colonnes dans le bon ordre,
    et par le parseur de résultat pour ne pas dépendre de l'ordre du driver.
    """
    return re.findall(r"AS fill_([A-Za-z0-9_]+)", sql)


def build_fill_rate_query(column_names: list[str]) -> tuple[str, dict[str, int]]:
    """Construit LA requête unique qui mesure le remplissage de tous les champs.

    Une requête par champ ferait 60 balayages d'une table de 60 M de lignes à
    chaque affichage de l'écran. Une seule passe agrégée suffit : ClickHouse
    évalue tous les `countIf()` en un parcours.

    La fenêtre transite en paramètre lié (`{window_seconds:UInt32}`) via
    `toIntervalSecond()` — la seule forme acceptée, `INTERVAL {p:String}` étant
    refusé par ClickHouse (SYNTAX_ERROR mesuré sur ce projet).

    Raises:
        ValueError: un nom hors allowlist de forme. REFUS, jamais échappement :
            la valeur n'atteint pas le SQL.
    """
    if not column_names:
        raise ValueError("aucune colonne a mesurer")

    for name in column_names:
        if not _IDENTIFIER_RE.match(name):
            raise ValueError(f"nom de colonne refuse (hors allowlist): {name!r}")

    # `notEmpty`/`!= 0` selon le type serait plus fin, mais exigerait de typer
    # chaque colonne ici. `IS NOT NULL` ne suffit pas (ClickHouse ne rend pas
    # NULL sur ces colonnes). On mesure donc « valeur non vide au sens du
    # défaut du type » via une comparaison à la valeur par défaut, qui couvre
    # les trois formes réellement rencontrées : chaîne vide, zéro, tableau vide.
    counters = ",\n    ".join(
        f"countIf(toString({name}) NOT IN ('', '0', '[]', '\\0\\0')) AS fill_{name}"
        for name in column_names
    )
    sql = f"""
SELECT
    count() AS total,
    {counters}
FROM default.flows
WHERE TimeReceived >= now() - toIntervalSecond({{window_seconds:UInt32}})
"""
    return sql, {"window_seconds": FILL_RATE_WINDOW_SECONDS}


def fetch_fill_rates(
    client: ClickHouseQueryable, column_names: list[str]
) -> dict[str, float]:
    """Mesure le taux de remplissage de chaque colonne, en pourcentage.

    Returns:
        `{nom: pourcentage}`. Un champ réellement vide rend `0.0` — une MESURE.

    Raises:
        FieldCatalogUnavailableError: la mesure n'a pas abouti. L'appelant doit
            alors afficher « indisponible », jamais 0 %.
    """
    sql, parameters = build_fill_rate_query(column_names)
    try:
        result = client.query(sql, parameters)
    except Exception as exc:
        log.error("field_catalog: echec mesure du remplissage", exc_info=True)
        raise FieldCatalogUnavailableError(f"taux de remplissage non mesure: {exc}") from exc

    rows = list(result.result_rows)
    if not rows:
        raise FieldCatalogUnavailableError("taux de remplissage non mesure: aucune ligne")

    row = rows[0]
    total = int(row[0] or 0)
    if total <= 0:
        # Aucun flux dans la fenêtre : on ne peut RIEN conclure sur le
        # remplissage. Rendre 0 % partout ferait passer une fenêtre calme pour
        # un schéma vide.
        raise FieldCatalogUnavailableError(
            "taux de remplissage non mesure: aucun flux dans la fenetre"
        )

    aliases = _fill_rate_aliases(sql)
    rates: dict[str, float] = {}
    for index, name in enumerate(aliases, start=1):
        if index >= len(row):
            break
        rates[name] = round(int(row[index] or 0) * 100 / total, 1)
    return rates


# ---------------------------------------------------------------------------
# Lecture des dashboards
# ---------------------------------------------------------------------------

PENDING_DASHBOARD_PREFIX = "[Équipement réseau]"
"""Préfixe des dashboards livrés EN AVANCE DE PHASE.

Un tel écran est construit sur des champs qu'aucun exportateur de la maquette
n'émet : il montre ce qui apparaîtra le jour où un routeur ou un pare-feu
exportera vers le collecteur. Il rend donc « No data » aujourd'hui.

ÉTAT AU 2026-08-11 : plus AUCUN dashboard du dépôt ne porte ce préfixe — les
trois écrans « [Équipement réseau] » ont été retirés, n'étant pas alimentés par
la maquette. Le compte des champs « prêts » vaut donc 0 aujourd'hui, et l'écran
masque la tuile correspondante plutôt que d'afficher une catégorie vide.

POURQUOI LE MÉCANISME RESTE (défaut mesuré à l'écran le 2026-08-11, avant
livraison, sur les dashboards depuis retirés) : sans cette distinction, trois
dashboards non alimentés faisaient basculer le ratio de « 19 exploités sur 62 »
à « 42 sur 62 », donc de 69 % à 32 % de potentiel inexploité. 23 champs
comptaient comme EXPLOITÉS alors qu'ils n'affichaient rien — l'écran aurait
détruit l'argument même qu'il doit porter, en silence, avec un chiffre
d'apparence rigoureuse.

La règle est générique et vaut pour tout écran à venir : un dashboard qui
n'affiche aucune donnée n'exploite rien, il PRÉPARE l'exploitation. Les deux
comptes restent donc tenus séparément."""


def _is_pending_dashboard(title: str) -> bool:
    """Vrai si le dashboard est livré en avance de phase (non alimenté ici)."""
    return title.startswith(PENDING_DASHBOARD_PREFIX)


_SQL_KEYS = ("rawSql", "rawQuery", "expr", "query")
"""Clés portant une REQUÊTE dans un dashboard Grafana.

Volontairement restreint : `description` et `title` en sont exclus. Plusieurs
dashboards réels citent `IPTos` en prose (« DSCP = bitShiftRight(IPTos, 2) »),
et les scanner ferait passer pour exploité un champ seulement MENTIONNÉ."""


def _iter_sql_fragments(node: Any) -> list[str]:
    """Parcourt un dashboard et rend uniquement ses fragments de SQL."""
    found: list[str] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if key in _SQL_KEYS and isinstance(value, str):
                found.append(value)
            else:
                found.extend(_iter_sql_fragments(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_iter_sql_fragments(item))
    return found


def read_dashboard_usage(directory: Path) -> DashboardUsage:
    """Relève, pour chaque colonne, les dashboards dont le SQL la consomme.

    La détection se fait à la FRONTIÈRE DE MOT (`\\b`) : `SrcAddr` ne matche pas
    `SrcAddrX`, et `Bytes` ne matche pas `BytesTotal`. Une détection par
    sous-chaîne annoncerait « déjà exploité » sur un champ qui ne l'est pas —
    et ruinerait l'argument de l'écran.
    """
    if not directory.is_dir():
        return DashboardUsage(directory_found=False)

    known_columns = sorted(
        {column.name for column in FLOW_COLUMNS} | set(FIELD_SEMANTICS),
        key=len,
        reverse=True,
    )
    patterns = {name: re.compile(rf"\b{re.escape(name)}\b") for name in known_columns}

    columns_by_name: dict[str, list[str]] = {}
    titles: list[str] = []
    unreadable: list[str] = []

    for path in sorted(directory.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            # Signalé, PAS ignoré : un dashboard illisible retirerait ses champs
            # du compte des exploités et gonflerait le potentiel annoncé.
            log.error("field_catalog: dashboard illisible %s: %s", path.name, exc)
            unreadable.append(path.name)
            continue

        title = str(payload.get("title") or path.stem)
        titles.append(title)
        blob = "\n".join(_iter_sql_fragments(payload))
        for name, pattern in patterns.items():
            if pattern.search(blob):
                dashboards = columns_by_name.setdefault(name, [])
                if title not in dashboards:
                    dashboards.append(title)

    return DashboardUsage(
        columns_by_name=columns_by_name,
        dashboard_titles=titles,
        unreadable_files=unreadable,
        directory_found=True,
    )


def columns_used_by_dashboards(directory: Path) -> set[str]:
    """Ensemble des noms de colonnes consommées par au moins un dashboard."""
    return set(read_dashboard_usage(directory).columns_by_name)


# ---------------------------------------------------------------------------
# Assemblage
# ---------------------------------------------------------------------------


def build_catalog(client: ClickHouseQueryable, dashboards_dir: Path) -> FieldCatalog:
    """Assemble le catalogue complet — le point d'entrée de l'écran.

    Les trois dépendances (schéma, dashboards, remplissage) échouent
    INDÉPENDAMMENT : une panne de mesure du remplissage ne doit pas emporter le
    ratio exploité/inexploité, qui reste l'argument principal.
    """
    errors: list[str] = []

    try:
        columns = read_flow_columns(client)
        schema_available = True
    except FieldCatalogUnavailableError as exc:
        # Sans schéma, il n'y a RIEN à afficher : ni total, ni ratio. L'écran
        # doit dire « indisponible », pas rendre un catalogue vide.
        return FieldCatalog(
            entries=[],
            schema_available=False,
            dashboards_available=False,
            fill_rates_available=False,
            error_message=(
                "Le schéma des flux n'a pas pu être lu depuis ClickHouse "
                f"({exc}). Le catalogue des champs est indisponible — ceci "
                "n'est pas un catalogue vide, c'est une absence de mesure."
            ),
        )

    usage = read_dashboard_usage(dashboards_dir)
    dashboards_available = usage.directory_found
    if not dashboards_available:
        errors.append(
            "Le dossier des dashboards Grafana est introuvable : impossible de "
            "déterminer quels champs sont déjà exploités. Le décompte "
            "exploités / inexploités est donc indisponible."
        )
    if usage.unreadable_files:
        errors.append(
            "Dashboards illisibles, non pris en compte dans le décompte : "
            + ", ".join(usage.unreadable_files)
        )

    try:
        fill_rates = fetch_fill_rates(client, [column.name for column in columns])
        fill_rates_available = True
    except (FieldCatalogUnavailableError, ValueError) as exc:
        fill_rates = {}
        fill_rates_available = False
        errors.append(
            f"Les taux de remplissage n'ont pas pu être mesurés ({exc}). Les "
            "champs sont affichés sans taux — aucun n'est présenté comme vide."
        )

    entries: list[CatalogEntry] = []
    for column in columns:
        semantics = FIELD_SEMANTICS.get(column.name, _DEFAULT_SEMANTICS)
        all_dashboards = usage.columns_by_name.get(column.name, [])
        # Séparation DÉCISIVE : un dashboard en avance de phase rend « No data ».
        # Le compter comme exploitant le champ ferait chuter le potentiel
        # inexploité annoncé sans qu'aucune donnée ne s'affiche nulle part.
        live = [d for d in all_dashboards if not _is_pending_dashboard(d)]
        pending = [d for d in all_dashboards if _is_pending_dashboard(d)]
        entries.append(
            CatalogEntry(
                name=column.name,
                label=column.label,
                clickhouse_type=column.clickhouse_type,
                category=semantics.category,
                origin=semantics.origin,
                used=bool(live) if dashboards_available else False,
                dashboards=live,
                pending_dashboards=pending,
                potential_usage=semantics.potential_usage,
                required_action=semantics.required_action,
                fill_rate=fill_rates.get(column.name) if fill_rates_available else None,
            )
        )

    return FieldCatalog(
        entries=entries,
        schema_available=schema_available,
        dashboards_available=dashboards_available,
        fill_rates_available=fill_rates_available,
        error_message=" ".join(errors),
        unreadable_dashboards=list(usage.unreadable_files),
        dashboard_titles=list(usage.dashboard_titles),
    )


# ---------------------------------------------------------------------------
# Export CSV
# ---------------------------------------------------------------------------

CSV_COLUMNS: tuple[str, ...] = (
    "champ",
    "libelle",
    "type",
    "categorie",
    "exploite",
    "dashboards",
    "usage_possible",
    "origine",
    "taux_remplissage",
    "action_requise",
    "dashboard_pret",
)


def export_catalog_csv(catalog: FieldCatalog) -> str:
    """Sérialise le catalogue pour ouverture dans un tableur PENDANT la réunion.

    Deux choix dictés par cet usage :

    - `oui`/`non` plutôt que `True`/`False` : le fichier est lu par un décideur,
      pas par un développeur.
    - `indisponible` plutôt que `0` quand le taux n'a pas été mesuré. Le zéro
      silencieux se propage jusque dans les fichiers exportés : un `0` dans une
      colonne « taux de remplissage » se lit « champ vide », et personne ne
      remonte à la panne de mesure une fois le fichier détaché de l'écran.

    Séparateur `;` et quoting complet : les phrases d'usage contiennent des
    virgules et des points-virgules, qui décaleraient les colonnes.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer, delimiter=";", lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(CSV_COLUMNS)

    for entry in catalog.entries:
        writer.writerow(
            [
                entry.name,
                entry.label,
                entry.clickhouse_type,
                entry.category,
                "oui" if entry.used else "non",
                ", ".join(entry.dashboards),
                entry.potential_usage,
                entry.origin_label,
                "indisponible" if entry.fill_rate is None else f"{entry.fill_rate:.1f}",
                entry.required_action,
                ", ".join(entry.pending_dashboards),
            ]
        )
    return buffer.getvalue()
