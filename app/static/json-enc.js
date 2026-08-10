/* Extension HTMX "json-enc" — sérialise un formulaire en JSON au lieu de
 * application/x-www-form-urlencoded, pour les endpoints qui attendent un
 * body Pydantic (`hx-ext="json-enc"` sur le formulaire).
 *
 * DÉFAUT CORRIGÉ (2026-08-08) : `retention.html` référençait déjà
 * `hx-ext="json-enc"` sur plusieurs formulaires (TTL preview/apply, purge
 * preview) mais AUCUN script ne définissait cette extension — ni dans
 * `htmx.min.js` (le core HTMX ne l'embarque pas, c'est une extension
 * officielle séparée), ni ailleurs dans `static/`. Sans elle, htmx envoyait
 * les formulaires en `application/x-www-form-urlencoded` classique vers des
 * endpoints qui attendent un body JSON Pydantic (`FastAPI` sans `Form(...)`)
 * → 422 systématique, invisible des tests unitaires (qui postent du JSON
 * directement via le client de test, pas via un vrai formulaire htmx).
 *
 * Portage local (pas de CDN, CSP `script-src 'self'` sans exception) de
 * l'extension officielle htmx-extensions/json-enc, réduite au strict
 * nécessaire : sérialise les valeurs du formulaire soumis en JSON et pose
 * le header `Content-Type: application/json`.
 */
(function () {
  "use strict";

  htmx.defineExtension("json-enc", {
    onEvent: function (name, evt) {
      if (name === "htmx:configRequest") {
        evt.detail.headers["Content-Type"] = "application/json";
      }
    },
    encodeParameters: function (xhr, parameters, elt) {
      xhr.overrideMimeType("text/json");
      return JSON.stringify(parameters);
    },
  });
})();
