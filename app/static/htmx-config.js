/* Configuration HTMX partagée — chargée APRÈS htmx sur toutes les pages.
 *
 * DÉFAUT VÉCU (2026-08-06), trouvé au navigateur et par aucun autre moyen :
 * un import CSV contenant une ligne fautive était correctement REFUSÉ par le
 * serveur, qui renvoyait un message précis ("ligne 3: CIDR invalide") en HTTP
 * 422. Mais HTMX ne swappe QUE les réponses 2xx par défaut : le message partait
 * bien sur le réseau et n'était jamais affiché. L'utilisateur cliquait, rien ne
 * bougeait, aucune explication.
 *
 * Ce n'était PAS un défaut local à l'import : des réponses d'erreur métier
 * réparties sur 4 routers (config_sections, config, exporters, views) rendent
 * du HTML destiné à être lu, en 4xx. Toutes étaient invisibles pour la même
 * raison. D'où un fix à LA SOURCE plutôt qu'un contournement route par route.
 *
 * ORDRE DE CHARGEMENT — piège mesuré : une première version posait
 * `window.htmx.config` AVANT le chargement de htmx. Sans effet : htmx REMPLACE
 * `window.htmx` par sa propre instance à l'initialisation, écrasant l'objet
 * préparé. Vérifié dans le navigateur, `responseHandling` contenait la valeur
 * par défaut de htmx, pas la nôtre. La configuration doit donc être appliquée
 * APRÈS que htmx s'est installé — d'où le chargement après htmx.min.js et la
 * réapplication sur htmx:load, qui couvre aussi les fragments échangés.
 *
 * Le statut 422 est conservé côté serveur : il est sémantiquement juste
 * (entité non traitable) et reste correct pour les appels d'API. C'est
 * l'affichage qui devait être corrigé, pas la sémantique HTTP.
 *
 * `swap: true` affiche le corps de la réponse ; `error: true` conserve le
 * marquage d'erreur (événement htmx:responseError), pour qu'un refus ne soit
 * jamais confondu avec un succès.
 */
(function () {
  "use strict";

  /* L'ordre compte : la PREMIÈRE règle dont le code correspond gagne. Les
   * règles d'erreur affichables doivent donc précéder la règle générique 4xx,
   * qui ne swappe pas. */
  var RESPONSE_HANDLING = [
    { code: "204", swap: false },
    { code: "404", swap: true, error: true },
    { code: "422", swap: true, error: true },
    { code: "[23]..", swap: true },
    { code: "[45]..", swap: false, error: true },
    { code: "...", swap: false },
  ];

  function applyConfig() {
    if (!window.htmx || !window.htmx.config) {
      return false;
    }
    window.htmx.config.responseHandling = RESPONSE_HANDLING;
    return true;
  }

  if (!applyConfig()) {
    /* htmx pas encore prêt (ordre de script inattendu) : on retente à son
     * initialisation plutôt que d'abandonner silencieusement. */
    document.addEventListener("htmx:load", applyConfig, { once: true });
    document.addEventListener("DOMContentLoaded", applyConfig, { once: true });
  }

  /* Réponses d'erreur : les afficher LÀ OÙ L'UTILISATEUR REGARDE.
   *
   * Un formulaire vise souvent, en cas de succès, une zone distante de celle
   * qu'on regarde en cliquant — la file d'attente pour une confirmation
   * d'import, par exemple. C'est correct pour un succès, mais un REFUS envoyé
   * dans ce même panneau passe inaperçu : constaté au navigateur le
   * 2026-08-06, le refus d'un import en collision avait bien lieu côté
   * serveur, la prévisualisation restait affichée, et rien à l'écran
   * n'indiquait l'échec.
   *
   * Un élément portant `data-error-target="<sélecteur>"` redirige donc ses
   * réponses d'erreur vers cette cible. `hx-target-error` aurait fait la même
   * chose, mais il vient d'une EXTENSION htmx non embarquée ici : posé sur le
   * formulaire, il aurait été ignoré en silence — le pire des cas, un
   * garde-fou qui ne garde rien. */
  document.addEventListener("htmx:beforeSwap", function (event) {
    var detail = event.detail;
    if (!detail || !detail.xhr || detail.xhr.status < 400) {
      return;
    }

    /* `detail.elt` est l'élément CIBLE du swap, PAS l'émetteur de la requête.
     * Mesuré au navigateur : une sonde sur cet événement rapportait
     * `elt: DIV` et `closest('[data-error-target]') === false` alors que
     * l'attribut était bien posé sur le formulaire. L'émetteur réel vit dans
     * `detail.requestConfig.elt` — c'est lui qui porte l'attribut. */
    var source =
      (detail.requestConfig && detail.requestConfig.elt) || detail.elt;
    if (!source || !source.closest) {
      return;
    }
    var holder = source.closest("[data-error-target]");
    if (!holder) {
      return;
    }
    var target = document.querySelector(holder.getAttribute("data-error-target"));
    if (target) {
      detail.target = target;
    }
  });
})();
