/* Sélection de masse des entrées de configuration.
 *
 * POURQUOI CE FICHIER EXISTE plutôt qu'un `<script>` ou des `onclick=` dans le
 * template : la CSP du service est `script-src 'self'`. Tout JS inline — bloc
 * `<script>` comme attribut `onclick` — est BLOQUÉ par le navigateur, et il
 * l'est en silence du point de vue de l'application : la page s'affiche, les
 * cases sont là, mais rien ne réagit au clic. Un comportement qui ne peut pas
 * échouer bruyamment doit vivre dans un fichier servi par l'origine.
 *
 * POURQUOI la délégation d'événements sur `document` plutôt qu'un écouteur par
 * case : les tableaux de section sont réinjectés par HTMX après chaque
 * changement mis en file. Des écouteurs posés une fois au chargement seraient
 * perdus sur le fragment remplacé — la sélection cesserait de fonctionner
 * après la première suppression, ce qui est précisément le moment où
 * l'utilisateur en a encore besoin.
 *
 * POURQUOI un « scope » par section (`data-bulk-scope`) : plusieurs sections
 * peuvent coexister dans la page. Sans cloisonnement, cocher « tout
 * sélectionner » d'une section cocherait les lignes d'une autre — et la
 * suppression de masse porterait sur des entrées que personne n'a regardées.
 */
(function () {
  "use strict";

  var SCOPE_ATTR = "data-bulk-scope";

  function rowsOf(scope) {
    return Array.prototype.slice.call(
      document.querySelectorAll(
        '.bulk-select__row[' + SCOPE_ATTR + '="' + scope + '"]'
      )
    );
  }

  function masterOf(scope) {
    return document.querySelector(
      '.bulk-select__master[' + SCOPE_ATTR + '="' + scope + '"]'
    );
  }

  function formOf(scope) {
    return document.querySelector(
      'form.bulk-actions[' + SCOPE_ATTR + '="' + scope + '"]'
    );
  }

  function countLabelOf(scope) {
    return document.querySelector('[data-bulk-count="' + scope + '"]');
  }

  /* Accord en nombre écrit à la main : afficher « 1 éléments » sur une action
   * destructive donne le sentiment d'un compteur approximatif, au moment
   * précis où l'utilisateur doit avoir confiance dans le chiffre. */
  function describe(n) {
    return n === 1 ? "1 élément sélectionné" : n + " éléments sélectionnés";
  }

  function describeCount(n) {
    return n === 1 ? "1 entrée" : n + " entrées";
  }

  function refresh(scope) {
    var rows = rowsOf(scope);
    var checked = rows.filter(function (row) {
      return row.checked;
    });

    var master = masterOf(scope);
    if (master) {
      /* `indeterminate` et non `checked = false` : après « tout sélectionner »
       * puis décochage d'une seule ligne, une case maîtresse simplement
       * décochée AFFIRME que rien n'est sélectionné, alors que N-1 entrées le
       * sont. Sur une suppression de masse, une case qui ment sur l'état de la
       * sélection est le pire des défauts possibles. L'état partiel doit être
       * visible en tant que tel. */
      master.checked = rows.length > 0 && checked.length === rows.length;
      master.indeterminate = checked.length > 0 && checked.length < rows.length;
    }

    var form = formOf(scope);
    if (form) {
      /* La barre est RETIRÉE (attribut `hidden`) et non seulement grisée quand
       * rien n'est coché : un bouton de suppression présent mais inerte invite
       * à cliquer, puis à recliquer, sur une action destructive. Le formulaire
       * masqué ne peut pas non plus être soumis au clavier. */
      form.hidden = checked.length === 0;
    }

    var label = countLabelOf(scope);
    if (label) {
      label.textContent = checked.length === 0 ? "" : describe(checked.length);
    }

    if (form) {
      /* Le compte exact est réinjecté dans la demande de confirmation : « êtes
       * vous sûr ? » sans chiffre ne permet pas de détecter qu'on s'apprête à
       * supprimer 36 entrées au lieu de la seule qu'on croyait cochée.
       *
       * L'attribut est posé sur le FORMULAIRE, pas sur le bouton. Vérifié dans
       * le bundle htmx servi : la confirmation est résolue par
       * `re(requestElt, "hx-confirm")`, qui remonte la chaîne des ANCÊTRES de
       * l'élément porteur de `hx-post` — ici le formulaire. Un `hx-confirm`
       * écrit sur le bouton est un DESCENDANT du formulaire : htmx ne l'y
       * chercherait jamais, retomberait sur le libellé statique du template, et
       * le compte dynamique n'apparaîtrait jamais — sans la moindre erreur.
       * Même famille de piège que `hx-target-error` : un attribut posé là où
       * le framework ne regarde pas est ignoré en silence. */
      form.setAttribute(
        "hx-confirm",
        "Supprimer définitivement " +
          describeCount(checked.length) +
          " de la configuration ? Cette action est irréversible."
      );
    }
  }

  function refreshAllScopes() {
    var seen = {};
    var nodes = document.querySelectorAll("[" + SCOPE_ATTR + "]");
    Array.prototype.forEach.call(nodes, function (node) {
      var scope = node.getAttribute(SCOPE_ATTR);
      if (scope && !seen[scope]) {
        seen[scope] = true;
        refresh(scope);
      }
    });
  }

  document.addEventListener("change", function (event) {
    var target = event.target;
    if (!target || !target.classList) {
      return;
    }

    if (target.classList.contains("bulk-select__master")) {
      var scope = target.getAttribute(SCOPE_ATTR);
      /* « toutes les lignes VISIBLES » : `rowsOf` n'énumère que les cases
       * présentes dans le DOM de la page servie. Une case absente du document
       * n'est pas sélectionnable, donc jamais supprimée à l'insu de qui coche. */
      rowsOf(scope).forEach(function (row) {
        row.checked = target.checked;
      });
      refresh(scope);
      return;
    }

    if (target.classList.contains("bulk-select__row")) {
      refresh(target.getAttribute(SCOPE_ATTR));
    }
  });

  /* Après un swap HTMX, le tableau réinjecté revient avec toutes ses cases
   * décochées : sans ce recalcul, la barre d'actions resterait affichée avec
   * l'ancien compte, désignant une sélection qui n'existe plus. */
  document.addEventListener("htmx:afterSwap", refreshAllScopes);
  document.addEventListener("DOMContentLoaded", refreshAllScopes);
})();
