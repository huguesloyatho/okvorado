/* Sonde de fraîcheur d'une section de configuration.
 *
 * POURQUOI cet écran n'auto-rafraîchit PAS son contenu : le panneau d'édition
 * porte 24 champs de saisie et une zone de collage CSV. Un rafraîchissement
 * périodique du contenu effacerait un CSV à moitié collé ou une sélection de
 * cases en cours — le remède serait pire que le mal.
 *
 * L'écran reste néanmoins MONITORABLE : la sonde interroge l'empreinte de la
 * section toutes les 15 s et affiche une bannière dès qu'un autre opérateur a
 * appliqué un changement. Recharger reste une décision de l'utilisateur, qui
 * seul sait s'il a une saisie en cours. C'est le cas d'usage visé par
 * Okvorado : plusieurs collègues sur la même configuration.
 *
 * Ce fichier ne fait qu'une chose : reporter dans un champ caché l'empreinte
 * renvoyée par le serveur, pour que la requête suivante puisse la comparer.
 * Sans ce report, chaque cycle repartirait d'une empreinte vide et la sonde
 * ne signalerait JAMAIS rien — en silence.
 *
 * Le report se fait ici et NON via `hx-vals="js:..."` : htmx évaluerait alors
 * l'expression avec `Function()`, que la CSP de l'application
 * (`script-src 'self'`, sans `unsafe-eval`) bloque. La valeur partirait vide
 * sans le moindre avertissement — même famille de piège que `hx-target-error`,
 * attribut d'une extension absente, ignoré en silence.
 */
(function () {
  "use strict";

  var ZONE_ID = "section-freshness";
  var CHAMP_ID = "section-freshness-seen";

  function reporterEmpreinte(event) {
    var zone = event && event.target;
    if (!zone || zone.id !== ZONE_ID) {
      return;
    }
    var champ = document.getElementById(CHAMP_ID);
    if (!champ) {
      return;
    }
    var porteur = zone.querySelector("[data-fingerprint]");
    if (!porteur) {
      /* Réponse sans empreinte : c'est le cas d'un état INDÉTERMINÉ (lecture
       * du fichier impossible). On laisse la valeur connue en place plutôt que
       * de la vider — repartir à vide ferait taire la sonde au prochain cycle,
       * transformant un incident de lecture en « rien à signaler ». */
      return;
    }

    /* L'empreinte n'est enregistrée QU'UNE FOIS, au premier cycle.
     *
     * DÉFAUT MESURÉ au navigateur (2026-08-06) : en la réécrivant à chaque
     * réponse, la référence suivait le fichier. La sonde détectait bien le
     * changement — l'empreinte passait de 47c2a882 à 39f80964 — puis
     * enregistrait la NOUVELLE valeur, si bien que le cycle suivant comparait
     * la nouvelle empreinte à elle-même : plus aucun écart, plus aucune
     * bannière. La sonde se taisait précisément quand elle aurait dû parler.
     *
     * La référence est ce que le navigateur AFFICHE, figé au chargement. Elle
     * ne doit changer que par un vrai rechargement de la page, décidé par
     * l'utilisateur — c'est tout l'intérêt de ne pas lui imposer le refresh. */
    if (champ.value) {
      return;
    }
    champ.value = porteur.getAttribute("data-fingerprint") || "";
  }

  document.addEventListener("htmx:afterSwap", reporterEmpreinte);
})();
