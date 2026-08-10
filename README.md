# Okvorado

Interface de management pour [Akvorado](https://github.com/akvorado/akvorado) — rendre le
NetFlow du homelab exploitable **par des collègues**, sans édition de YAML et sans que
l'administrateur soit le passage obligé.

> Okvorado ne stocke ni ne décode aucun flux. Akvorado reste la source de vérité :
> Okvorado est la couche de **pilotage** et de **lecture métier** par-dessus.

## Ce qu'il apporte que la console Akvorado ne donne pas

### 1. Exportateurs — croisement déclaré × observé × ingéré

Trois sources qui ne se parlent pas dans Akvorado :

| Source | Ce qu'elle dit |
|---|---|
| `outlet.yaml` | ce qui est **déclaré** |
| ClickHouse | ce qui est **observé** (flux stockés) |
| métriques Prometheus de l'outlet | ce qui est **ingéré ou rejeté** |

Leur croisement produit 5 états, dont deux qu'aucun dashboard Akvorado ne montre :

- **Flux rejetés** — l'exportateur émet, mais Akvorado rejette tout. *Invisible ailleurs :
  un flux rejeté n'arrive jamais dans ClickHouse.* Cas réel détecté en production :
  `192.0.2.18` avec 2,17 M de flux perdus (softflowd 1.1.0 ne renseigne pas les
  interfaces, `outlet/core/enricher.go:83` les rejette).
- **Interface inconnue** — l'exportateur émet sur un ifIndex non déclaré : le flux part
  sur le `default`, avec un `boundary` potentiellement faux. C'est la cause du symptôme
  « dashboard Visualize vide ».

⚠️ **Fenêtre de mesure : 1 heure minimum, imposée.** Un nœud à flux longs peut n'émettre
qu'un datagramme toutes les 75 s : sur 5 minutes il paraît en panne alors qu'il fonctionne.
Aucune fenêtre plus courte n'est proposée dans l'UI.

### 2. Vues métier — lisibles sans construire une requête

Table **port → application éditable** (IANA préchargé + surcharges maison) : `3100` devient
« Gitea », `8082` devient « Akvorado ». Éditable par les utilisateurs, donc l'outil
s'enrichit sans l'administrateur.

Cinq vues : qui parle à qui · quels services · WAN vs mesh · dans le temps · QoS.

**Anti-redondance** : l'explorateur d'Akvorado n'est pas recloné. Chaque vue propose
« ouvrir dans Akvorado » avec le filtre déjà construit.

### 3. Diagnostic d'ingestion — la seule fenêtre sur ce qui se perd

Lit les compteurs Prometheus de l'outlet (`/api/v0/outlet/metrics` — **pas** `/metrics`,
qui renvoie 404). Chaque motif de rejet est expliqué en clair, avec sa remédiation.

### 4. Rétention pilotable

TTL par table, taille disque, croissance estimée et **projection avant tout changement**.
En v1 l'ordre `ALTER TABLE` est **construit pour affichage, jamais exécuté**.

## Configuration

Tout passe par l'environnement (préfixe `OKVORADO_`). Voir `.env.example`.
La seule variable à ajuster pour cibler une autre installation est `OKVORADO_AKVORADO_HOST`.

## Développement

```sh
pip install -e ".[dev]"
pytest                                   # 176 tests, aucune infra requise
mypy --strict app tests && ruff check .  # gates qualité
uvicorn app.main:app --reload
```

**Aucun test n'exige l'infrastructure** : ClickHouse, l'outlet et le YAML sont injectés,
les tests fournissent des doubles. Un test qui exigerait `.6` serait un test cassé.

## Contraintes d'architecture

- **ClickHouse et l'outlet ne sont pas exposés sur l'hôte** (mesuré : `"8123/tcp": null`).
  Okvorado doit donc tourner **sur le réseau docker du stack akvorado** pour les joindre.
- **Lecture seule sur Akvorado en v1.** L'écriture de `outlet.yaml` est prévue en v2, avec
  service seul writer, verrouillage optimiste par hash, commit git et rollback automatique
  si le healthcheck échoue après redémarrage.
- **Pas de `docker.sock` monté.** Le redémarrage d'Akvorado (nécessaire car la v2.4.1 n'a
  aucun reload à chaud) passera par un canal restreint, jamais par un accès root à l'hôte.

## Sécurité

Requêtes ClickHouse **exclusivement paramétrées**, noms de tables et de colonnes en dur.
Les fenêtres transitent par une table figée de littéraux, jamais par une saisie brute.
CSP stricte, aucune ressource externe (HTMX servi localement). Autoescape Jinja2 partout.

Voir `CONTRACT.md` pour les contrats de données et le détail des gardes.
