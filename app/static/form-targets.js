/* Formulaires dont la CIBLE dépend d'un choix dans une liste déroulante.
 *
 * CONFIG_HARDCODE_OK: les adresses citées ci-dessous sont la TRACE d'une mesure
 * faite au navigateur, pas des valeurs contactées par ce fichier. Aucune
 * adresse n'y est codée : la cible est construite à partir d'un modèle porté
 * par le formulaire, lui-même rendu par le serveur.
 *
 * DÉFAUT MESURÉ AU NAVIGATEUR (2026-08-06) — le plus grave de la série :
 * le formulaire « Déclarer une interface » portait un `onchange=` INLINE qui
 * réécrivait son `hx-post` selon l'exportateur choisi. La CSP de l'application
 * est `script-src 'self'`, SANS `unsafe-inline` : le navigateur bloque ce
 * gestionnaire. Mesure sur les 12 exportateurs de production — on choisit le
 * sixième, la cible reste sur le troisième :
 *
 *     choisi          : <exportateur n°6>
 *     hx-post avant   : /config/exporters/<exportateur n°3>/interfaces
 *     hx-post après   : /config/exporters/<exportateur n°3>/interfaces
 *
 * Conséquence : l'interface aurait été déclarée sur une machine que
 * l'utilisateur n'a pas choisie, parmi douze — sans message, sans erreur, avec
 * un « changement mis en attente » affiché en succès. Le formulaire ne cassait
 * pas : il visait ailleurs.
 *
 * Le câblage vit donc ici, dans un fichier statique servi par l'application,
 * seule forme que la CSP autorise. La cible est décrite par des attributs
 * `data-*` sur le formulaire, ce qui rend le mécanisme réutilisable au lieu
 * d'être une ligne de JavaScript noyée dans un template.
 */
(function () {
  "use strict";

  var SELECTEUR = "[data-target-template]";

  function appliquer(formulaire) {
    var modele = formulaire.getAttribute("data-target-template");
    var nomChamp = formulaire.getAttribute("data-target-source");
    if (!modele || !nomChamp) {
      return;
    }
    var champ = formulaire.querySelector("[name='" + nomChamp + "']");
    if (!champ) {
      return;
    }
    /* `encodeURIComponent` et non une simple concaténation : un CIDR contient
     * un `/` qui, laissé tel quel, produirait un chemin à un segment de plus —
     * une route inexistante, donc un 404 au lieu d'une mise en attente. */
    var cible = modele.replace("{value}", encodeURIComponent(champ.value));
    if (formulaire.getAttribute("hx-post") === cible) {
      return;
    }
    formulaire.setAttribute("hx-post", cible);
    /* htmx lit ses attributs à l'initialisation : sans `process`, la nouvelle
     * cible ne serait prise en compte qu'au prochain rendu de la page — donc
     * jamais pour la soumission en cours. */
    if (window.htmx && typeof window.htmx.process === "function") {
      window.htmx.process(formulaire);
    }
  }

  var SELECTEUR_AUTOSUBMIT = "[data-autosubmit]";

  /* SECOND défaut de la même famille, mesuré le même jour : le sélecteur de
   * fenêtre des vues métier portait `onchange="this.form.submit()"`, également
   * bloqué par la CSP. Changer la fenêtre de 1h à 6h ne soumettait RIEN et
   * l'URL restait identique — le sélecteur changeait d'apparence sans effet,
   * et aucun bouton ne permettait de valider. */
  function autoSoumettre(event) {
    var source = event.target;
    if (!source || !source.closest) {
      return;
    }
    var formulaire = source.closest(SELECTEUR_AUTOSUBMIT);
    if (!formulaire) {
      return;
    }
    var attendu = formulaire.getAttribute("data-autosubmit-source");
    if (attendu && source.getAttribute("name") !== attendu) {
      return;
    }
    formulaire.submit();
  }

  function initialiser() {
    var formulaires = document.querySelectorAll(SELECTEUR);
    for (var i = 0; i < formulaires.length; i++) {
      appliquer(formulaires[i]);
    }

    /* Le bouton de repli n'est masqué QUE lorsque ce script s'exécute : posé
     * masqué dans le template, il resterait invisible le seul jour où il sert
     * — celui où le JS ne tourne pas. Le sens du marquage compte plus que son
     * effet visuel. */
    var autos = document.querySelectorAll(SELECTEUR_AUTOSUBMIT);
    for (var j = 0; j < autos.length; j++) {
      autos[j].setAttribute("data-autosubmit-ready", "");
    }
  }

  /* Délégation : les formulaires peuvent arriver par un échange htmx après le
   * chargement initial. Écouter sur le document couvre les deux cas. */
  document.addEventListener("change", function (event) {
    var source = event.target;
    if (!source || !source.closest) {
      return;
    }
    var formulaire = source.closest(SELECTEUR);
    if (formulaire) {
      appliquer(formulaire);
    }
    autoSoumettre(event);
  });

  document.addEventListener("DOMContentLoaded", initialiser);
  document.addEventListener("htmx:afterSwap", initialiser);
})();
