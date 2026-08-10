/* Confirmation avant soumission d'un formulaire destructeur, SANS gestionnaire
 * inline. Même raison d'être que form-targets.js : la CSP de l'application
 * (`script-src 'self'`, sans `unsafe-inline`) bloque tout `onsubmit="..."`
 * posé dans un template — silencieusement, sans erreur visible à l'écran.
 *
 * Un formulaire portant `data-confirm="<message>"` déclenche une boîte de
 * confirmation native avant sa soumission ; annuler bloque l'envoi.
 */
(function () {
  "use strict";

  document.addEventListener("submit", function (event) {
    var formulaire = event.target;
    if (!formulaire || !formulaire.getAttribute) {
      return;
    }
    var message = formulaire.getAttribute("data-confirm");
    if (!message) {
      return;
    }
    if (!window.confirm(message)) {
      event.preventDefault();
    }
  });
})();
