/* Bascule d'onglet pour l'écran exportateur (8 onglets : Résumé, Trafic,
 * Interfaces, Applications, Sources, Destinations, Conversations, QoS).
 *
 * La CSP de l'application est `script-src 'self'` SANS `unsafe-inline` :
 * aucun `onclick=` n'est utilisable dans le template (cf. le défaut vécu et
 * documenté dans app/static/form-targets.js, même famille de contrainte).
 * Le câblage vit donc ici, piloté par des attributs `data-*` posés par le
 * serveur sur chaque bouton d'onglet.
 *
 * Chaque onglet cliqué déclenche SA PROPRE requête HTMX (`data-tab-url`) vers
 * le panneau partagé `#tab-panel` — jamais un chargement groupé des 8 onglets,
 * ce qui garderait la page lente pour des données que l'utilisateur ne
 * regarde pas toutes.
 */
(function () {
  "use strict";

  var SELECTEUR_CONTENEUR = "[data-tabs]";

  function activerOnglet(bouton) {
    var conteneur = bouton.closest(SELECTEUR_CONTENEUR);
    if (!conteneur) {
      return;
    }
    var panneau = conteneur.querySelector(".tabs__panel");
    var url = bouton.getAttribute("data-tab-url");
    if (!panneau || !url) {
      return;
    }

    var boutons = conteneur.querySelectorAll(".tabs__tab");
    for (var i = 0; i < boutons.length; i++) {
      boutons[i].setAttribute("aria-selected", boutons[i] === bouton ? "true" : "false");
    }

    panneau.setAttribute("hx-get", url);
    if (window.htmx && typeof window.htmx.process === "function") {
      window.htmx.process(panneau);
    }
    if (window.htmx && typeof window.htmx.ajax === "function") {
      window.htmx.ajax("GET", url, { target: panneau, swap: "innerHTML" });
    }
  }

  document.addEventListener("click", function (event) {
    var cible = event.target;
    if (!cible || !cible.closest) {
      return;
    }
    var bouton = cible.closest("[data-tab-target]");
    if (bouton) {
      activerOnglet(bouton);
    }
  });
})();
