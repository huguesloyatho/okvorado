/* Glisser-déposer des filtres — écran « Champs disponibles » (/field-catalog).
 *
 * DÉFAUT CORRIGÉ (retour utilisateur 2026-08-12, mot pour mot) : « il faut
 * forcer pour glisser deposer un filtre » — puis, après correction de
 * l'affordance seule : « ca fonctionne a moitie mais pas maitrise a priori,
 * code le jusqu'au bout ». Le glisser-déposer existe déjà ailleurs dans
 * l'application (app/static/field-composer.js, écran de configuration) :
 * l'utilisateur essaie naturellement le même geste ici, où rien ne le gérait.
 *
 * CE FICHIER EST DISTINCT de field-composer.js (UN concept = UNE source, mais
 * ce ne sont PAS le même concept) : field-composer.js réordonne une LISTE
 * interne et synchronise un champ caché pour un POST ultérieur. Ici, glisser
 * un bouton de filtre ne réordonne rien : ça déclenche IMMÉDIATEMENT la même
 * NAVIGATION que le clic sur ce bouton (une requête htmx vers
 * `#field-catalog-rows`, plus la mise à jour de l'URL de la page). Fusionner
 * les deux fichiers créerait une fonction à deux contrats difficiles à lire
 * séparément.
 *
 * POURQUOI AUCUNE BIBLIOTHÈQUE (même raison que field-composer.js) : la CSP
 * du service est `script-src 'self'` sans `unsafe-eval`, un script de CDN
 * serait bloqué et une dépendance embarquée serait un fichier de plus à
 * maintenir pour un comportement que le navigateur fournit déjà (API HTML5
 * `draggable`/`dragstart`/`dragover`/`drop`/`dragend`).
 *
 * PIÈGES DÉJÀ RÉSOLUS DANS field-composer.js, RÉUTILISÉS ICI SANS LES
 * REDÉCOUVRIR :
 *   - les navigateurs interdisent la LECTURE de `dataTransfer` pendant
 *     `dragover` (seul `drop` y a accès) : l'élément en cours de glissement
 *     est gardé en variable de module (`dragged`), pas relu depuis
 *     `dataTransfer` ;
 *   - `event.preventDefault()` dans `dragover` est ce qui AUTORISE le dépôt :
 *     sans lui, le navigateur refuse la zone et l'élément « revient » à sa
 *     place au relâchement, sans le moindre message ;
 *   - Firefox refuse d'initier un glissement si `dataTransfer` reste vide :
 *     une charge utile est toujours posée via `setData` ;
 *   - `dragend` (pas `drop`) est l'endroit où nettoyer les classes visuelles :
 *     il se déclenche TOUJOURS, y compris quand le dépôt est refusé (hors
 *     zone, touche Échap) — un nettoyage placé uniquement dans `drop`
 *     laisserait l'élément figé en état « en cours de déplacement ».
 *
 * CE QUI EST DIFFÉRENT ICI (le drop DÉCLENCHE une navigation, ne réordonne
 * rien) : la zone de dépôt est UNE SEULE (la barre de filtre actif,
 * `[data-filter-dropzone]`), pas une liste réordonnable ; il n'y a ni
 * insertion avant/après un voisin, ni synchronisation de champ caché. Au
 * dépôt, on lit `data-drop-url` / `data-drop-push-url` — déjà calculées par
 * Jinja avec l'état COURANT des trois filtres, EXACTEMENT les mêmes valeurs
 * que `hx-get` / `hx-push-url` sur ce bouton — et on déclenche la requête via
 * `htmx.ajax()` (même mécanisme que app/static/tabs.js), en poussant l'URL de
 * la page complète pour que l'historique et le rechargement restent corrects.
 *
 * LE CLIC RESTE INCHANGÉ : ce fichier n'écoute que `dragstart`/`dragover`/
 * `drop`/`dragend`. Les attributs `hx-get`/`hx-push-url`/`href` des mêmes
 * boutons continuent de fonctionner exactement comme avant, y compris sans
 * JavaScript — le glisser est un AJOUT, jamais un remplacement.
 */
(function () {
  "use strict";

  var DRAG_SOURCE_SELECTOR = "[data-drop-url]";
  var DROPZONE_SELECTOR = "[data-filter-dropzone]";
  var DRAGGING_CLASS = "is-dragging";
  var DROP_TARGET_CLASS = "is-drop-target";

  /* Référence à l'élément en cours de déplacement — voir piège documenté en
   * en-tête : `dataTransfer` n'est pas lisible pendant `dragover`. */
  var dragged = null;

  function closest(node, selector) {
    while (node && node.nodeType === 1) {
      if (node.matches && node.matches(selector)) {
        return node;
      }
      node = node.parentElement;
    }
    return null;
  }

  document.addEventListener("dragstart", function (event) {
    var source = closest(event.target, DRAG_SOURCE_SELECTOR);
    if (!source) {
      return;
    }
    dragged = source;
    source.classList.add(DRAGGING_CLASS);
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = "copy";
      /* Charge utile obligatoire pour Firefox (voir en-tête). L'URL elle-même
       * transite aussi par `dataTransfer`, en secours si jamais la variable de
       * module `dragged` était perdue (ex. rechargement du fragment HTMX
       * pendant le drag, cas limite mais sans risque à couvrir). */
      try {
        event.dataTransfer.setData(
          "text/plain",
          source.getAttribute("data-drop-url") || ""
        );
      } catch (err) {
        /* Certains navigateurs verrouillent setData selon le contexte : le
         * déplacement reste piloté par `dragged`, on continue. */
      }
    }
  });

  document.addEventListener("dragover", function (event) {
    if (!dragged) {
      return;
    }
    var zone = closest(event.target, DROPZONE_SELECTOR);
    if (!zone) {
      return;
    }
    /* Autorise le dépôt — voir piège documenté en en-tête. */
    event.preventDefault();
    if (event.dataTransfer) {
      event.dataTransfer.dropEffect = "copy";
    }
    zone.classList.add(DROP_TARGET_CLASS);
  });

  document.addEventListener("dragleave", function (event) {
    var zone = closest(event.target, DROPZONE_SELECTOR);
    if (zone && (!event.relatedTarget || !closest(event.relatedTarget, DROPZONE_SELECTOR))) {
      zone.classList.remove(DROP_TARGET_CLASS);
    }
  });

  document.addEventListener("drop", function (event) {
    var zone = closest(event.target, DROPZONE_SELECTOR);
    if (!zone || !dragged) {
      return;
    }
    event.preventDefault();
    zone.classList.remove(DROP_TARGET_CLASS);

    var url = dragged.getAttribute("data-drop-url");
    var pushUrl = dragged.getAttribute("data-drop-push-url");
    if (!url) {
      return;
    }

    var target = document.getElementById("field-catalog-rows") || zone;
    if (window.htmx && typeof window.htmx.ajax === "function") {
      window.htmx.ajax("GET", url, {
        target: target,
        swap: "innerHTML",
      });
      /* L'URL est poussée ICI, pas via une option de `htmx.ajax`.
       *
       * DÉFAUT MESURÉ AU NAVIGATEUR (2026-08-12) : une option `pushUrl` était
       * passée à `htmx.ajax` — elle n'existe pas dans son API (vérifié dans
       * `htmx.min.js` 2.0.4 : ni `pushUrl` ni `pushURL` n'y figurent). Elle
       * était donc ignorée EN SILENCE : le tableau se mettait bien à jour, mais
       * la barre d'adresse restait sur le filtre précédent. Un rechargement, un
       * partage de lien ou un retour arrière ramenait l'état d'avant le dépôt —
       * exactement le défaut de persistance corrigé plus tôt sur le CLIC, qui
       * survivait ici sur le GLISSER faute d'avoir exercé ce geste-là.
       *
       * `history.pushState` est l'API du navigateur : elle ne dépend d'aucune
       * convention interne de htmx et fait ce qu'elle dit. */
      if (pushUrl && window.history && window.history.pushState) {
        window.history.pushState({ htmx: true }, "", pushUrl);
      }
    } else if (pushUrl) {
      /* ROBUSTESSE — htmx pas encore chargé (chargement en cours) : la
       * navigation complète reste un geste fonctionnel, jamais un dépôt
       * silencieux sans effet. */
      window.location.href = pushUrl;
    }
  });

  /* ROBUSTESSE — glisser hors zone puis relâcher : `dragend` se déclenche
   * TOUJOURS (voir piège documenté en en-tête), c'est ici et non dans `drop`
   * que le nettoyage visuel doit vivre. */
  document.addEventListener("dragend", function (event) {
    var source = closest(event.target, DRAG_SOURCE_SELECTOR);
    if (source) {
      source.classList.remove(DRAGGING_CLASS);
    }
    if (dragged) {
      dragged.classList.remove(DRAGGING_CLASS);
    }
    var zones = document.querySelectorAll(DROPZONE_SELECTOR);
    for (var i = 0; i < zones.length; i++) {
      zones[i].classList.remove(DROP_TARGET_CLASS);
    }
    dragged = null;
  });
})();
