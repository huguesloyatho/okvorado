/* Suspend le rafraîchissement automatique de l'écran Exportateurs tant qu'un
   compte rendu SNMP est affiché.
 *
 * POURQUOI CE FICHIER EXISTE — deux défauts MESURÉS À L'ÉCRAN le 2026-08-10,
 * sur la plateforme réelle, l'un après l'autre :
 *
 * 1. Après un clic sur « Tout résoudre par SNMP », le tableau de résultats
 *    s'affichait puis DISPARAISSAIT tout seul. Cause : le formulaire de
 *    fenêtre porte `hx-trigger="change, every 30s"` avec
 *    `hx-target`/`hx-select` sur `#exporters-page` et `hx-swap=outerHTML` —
 *    chaque tick remplace la SECTION ENTIÈRE, détruisant le conteneur de
 *    compte rendu avec son contenu. L'exploitant lançait la résolution,
 *    commençait à lire quelles machines avaient répondu, et le tableau
 *    s'effaçait sous ses yeux.
 *
 * 2. Première tentative de correctif : une condition htmx
 *    `every 30s [!document.querySelector(...).innerHTML.trim()]`. ÉCHEC
 *    mesuré : htmx évalue ces conditions en JavaScript DYNAMIQUE, ce que la
 *    CSP du projet interdit (`script-src 'self'`, sans `unsafe-eval` — voir
 *    `app/main.py`). Le navigateur levait `EvalError` à chaque tick, la
 *    condition était ignorée, et le compte rendu disparaissait toujours — en
 *    ajoutant trois erreurs console. Mesure : présent à 5 s, effacé dès 10 s.
 *
 * D'où ce garde : il RETIRE l'attribut `hx-trigger` quand un compte rendu
 * apparaît et le REMET quand il disparaît. Aucune chaîne n'est évaluée, donc
 * rien à autoriser dans la CSP.
 *
 * Le rafraîchissement n'est PAS supprimé : il tient les compteurs de flux à
 * jour et le retirer serait une régression. Il est seulement mis en pause le
 * temps que l'exploitant lise son compte rendu.
 */

(function () {
  "use strict";

  var SELECTEUR_FORMULAIRE = "#exporters-window-form";
  var SELECTEUR_RESULTAT = "#snmp-resolve-all-result";
  // Valeur d'origine, remise telle quelle à la reprise. Gardée ici plutôt que
  // relue depuis le DOM : une fois l'attribut retiré, il n'est plus lisible.
  var DECLENCHEUR = "change, every 30s";

  function appliquer() {
    var formulaire = document.querySelector(SELECTEUR_FORMULAIRE);
    var resultat = document.querySelector(SELECTEUR_RESULTAT);
    if (!formulaire || !resultat) {
      return;
    }

    var compteRenduAffiche = resultat.innerHTML.trim().length > 0;

    if (compteRenduAffiche) {
      if (formulaire.hasAttribute("hx-trigger")) {
        formulaire.removeAttribute("hx-trigger");
        // Sans ce ré-amorçage, htmx conserve le minuteur déjà armé sur
        // l'élément : l'attribut disparaît mais le tick suivant part quand
        // même, et le compte rendu s'efface — le défaut resterait entier.
        if (window.htmx) {
          window.htmx.process(formulaire);
        }
      }
      return;
    }

    if (!formulaire.hasAttribute("hx-trigger")) {
      formulaire.setAttribute("hx-trigger", DECLENCHEUR);
      if (window.htmx) {
        window.htmx.process(formulaire);
      }
    }
  }

  function observer() {
    var resultat = document.querySelector(SELECTEUR_RESULTAT);
    if (!resultat) {
      return;
    }
    // Le conteneur est rempli par htmx (swap), pas par une saisie : seul un
    // MutationObserver voit le changement. `characterData` couvre le cas d'un
    // fragment réduit à du texte.
    new MutationObserver(appliquer).observe(resultat, {
      childList: true,
      subtree: true,
      characterData: true,
    });
    appliquer();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", observer);
  } else {
    observer();
  }

  // La section entière est remplacée à chaque rafraîchissement : le conteneur
  // observé est alors un NOUVEL élément et l'ancien observateur ne voit plus
  // rien. On se ré-accroche après chaque swap htmx.
  document.body.addEventListener("htmx:afterSwap", observer);
})();
