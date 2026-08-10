/* Composeur d'étiquettes réordonnables — dimensions de « Vue par défaut de
 * Visualize ».
 *
 * DÉFAUT CORRIGÉ (mesuré en prod le 2026-08-06) : les 6 dimensions
 * (`ExporterName, SrcAddr, DstAddr, DstPort, Proto, InIfBoundary`) tenaient
 * dans UN SEUL `<input type="text">` étroit, séparées par des virgules.
 * Illisible (la chaîne déborde du champ) et non réordonnable autrement qu'en
 * retapant la chaîne entière — alors que l'ordre porte du sens : la 1re
 * dimension est l'axe principal du graphe Akvorado.
 *
 * POURQUOI CE FICHIER EXISTE plutôt qu'un `<script>` inline ou des `onclick=` :
 * la CSP du service est `script-src 'self'`, SANS `unsafe-eval`. Tout JS inline
 * est bloqué par le navigateur, et il l'est en SILENCE du point de vue de
 * l'application : la page s'affiche, les étiquettes sont là, et rien ne bouge
 * au clic. Même raison que bulk-select.js.
 *
 * POURQUOI le glisser-déposer utilise l'API HTML5 native (`draggable`,
 * `dragstart`/`dragover`/`drop`) et AUCUNE bibliothèque : la CSP bloquerait un
 * script de CDN, et une dépendance embarquée serait un fichier de plus à
 * maintenir pour un comportement que le navigateur fournit déjà.
 *
 * POURQUOI la délégation d'événements sur `document` plutôt qu'un écouteur par
 * étiquette : le panneau d'édition est réinjecté par HTMX après chaque
 * changement mis en file. Des écouteurs posés une fois au chargement seraient
 * perdus sur le fragment remplacé — le composeur cesserait de réagir après le
 * premier enregistrement, précisément quand l'utilisateur enchaîne les
 * ajustements.
 *
 * POURQUOI le champ caché est déjà rempli par Jinja et non construit ici : si
 * ce fichier ne s'exécute pas, un champ vide POSTERAIT une liste de dimensions
 * vide et effacerait la configuration de production, sans message. Un chemin
 * d'échec ne doit jamais produire une valeur neutre indistinguable d'une vraie
 * saisie. Ici, le pire cas est un enregistrement à l'identique.
 */
(function () {
  "use strict";

  var ROOT_SELECTOR = "[data-field-composer]";
  var DRAGGING_CLASS = "is-dragging";
  var DROP_TARGET_CLASS = "is-drop-target";

  /* Référence à l'étiquette en cours de déplacement. Gardée en variable de
   * module plutôt que lue depuis `dataTransfer` au `dragover` : les navigateurs
   * interdisent la LECTURE de `dataTransfer` pendant `dragover` (seul `drop` y
   * a accès). Sans cette référence, impossible de savoir quoi surligner. */
  var dragged = null;

  function toArray(nodeList) {
    return Array.prototype.slice.call(nodeList);
  }

  function closest(node, selector) {
    while (node && node.nodeType === 1) {
      if (node.matches && node.matches(selector)) {
        return node;
      }
      node = node.parentElement;
    }
    return null;
  }

  function rootOf(node) {
    return closest(node, ROOT_SELECTOR);
  }

  function tagsOf(root) {
    return toArray(root.querySelectorAll("[data-field-composer-tag]"));
  }

  function listOf(root) {
    return root.querySelector("[data-field-composer-list]");
  }

  /* ------------------------------------------------------------------
   * Synchronisation : le DOM des étiquettes est la SOURCE, le champ caché
   * n'en est que la projection.
   * ------------------------------------------------------------------ */

  /* Format posté : liste séparée par « , ». C'est EXACTEMENT le format que le
   * routeur attend déjà (`form_dict["dimensions"].split(",")` puis `.strip()`
   * sur chaque terme) : le contrat serveur est inchangé, les étiquettes ne sont
   * qu'une façon de COMPOSER cette chaîne. Aucune ligne de app/routers/ à
   * toucher. */
  function sync(root) {
    var tags = tagsOf(root);
    var values = tags.map(function (tag) {
      return tag.getAttribute("data-field-value") || "";
    });

    var hidden = root.querySelector("[data-field-composer-value]");
    if (hidden) {
      hidden.value = values.join(", ");
    }

    /* Le rang est réécrit à chaque changement : un numéro figé après un
     * déplacement afficherait « 1 » sur une étiquette qui n'est plus en tête —
     * un indicateur qui ment sur l'axe principal du graphe. */
    tags.forEach(function (tag, index) {
      var rank = tag.querySelector("[data-field-composer-rank]");
      if (rank) {
        rank.textContent = String(index + 1);
      }
      /* Les flèches des extrémités sont DÉSACTIVÉES, pas masquées : un bouton
       * qui disparaît fait sauter la mise en page et déplace les autres
       * boutons sous le curseur au moment précis où l'on clique en série. */
      var up = tag.querySelector('[data-field-composer-move="up"]');
      var down = tag.querySelector('[data-field-composer-move="down"]');
      if (up) {
        up.disabled = index === 0;
      }
      if (down) {
        down.disabled = index === tags.length - 1;
      }
    });

    /* ROBUSTESSE — retirer TOUTES les dimensions : la zone ne doit jamais
     * rester muette. Un vide sans explication est indistinguable d'un écran
     * qui n'a pas fini de charger. Le message nomme la CONSÉQUENCE (le graphe
     * n'affichera rien), pas seulement le fait. */
    var empty = root.querySelector("[data-field-composer-empty]");
    if (empty) {
      empty.hidden = tags.length > 0;
    }
  }

  /* ------------------------------------------------------------------
   * Ajout / retrait
   * ------------------------------------------------------------------ */

  function optionFor(root, value) {
    return root.querySelector(
      '[data-field-composer-option][data-field-value="' + cssEscape(value) + '"]'
    );
  }

  /* Échappement minimal pour un sélecteur d'attribut. `CSS.escape` n'est pas
   * disponible partout ; les valeurs manipulées ici sont des noms de dimension
   * Akvorado (alphanumériques), mais un sélecteur construit sans garde-fou est
   * une porte ouverte le jour où une valeur exotique arrive du YAML. */
  function cssEscape(value) {
    return String(value).replace(/["\\]/g, "\\$&");
  }

  function addValue(root, value) {
    if (!value) {
      return;
    }

    /* ROBUSTESSE — double-clic rapide sur « ajouter » : une dimension présente
     * DEUX FOIS casse le graphe Akvorado. Le garde-fou porte sur l'état réel du
     * DOM et non sur un verrou temporel (un `setTimeout` anti-rebond laisserait
     * passer le doublon dès que la machine rame). L'option source est par
     * ailleurs retirée de la liste des disponibles juste après, ce qui rend le
     * second clic sans objet — mais les deux protections sont indépendantes :
     * un clavier peut déclencher deux fois avant le retrait. */
    var already = tagsOf(root).some(function (tag) {
      return tag.getAttribute("data-field-value") === value;
    });
    if (already) {
      return;
    }

    var list = listOf(root);
    if (!list) {
      return;
    }

    var option = optionFor(root, value);
    var label = value;
    if (option) {
      var labelNode = option.querySelector(".field-composer__tag-label");
      if (labelNode) {
        label = labelNode.textContent.trim();
      }
    }

    list.appendChild(buildTag(value, label));
    if (option) {
      option.remove();
    }
    refreshAvailability(root);
    sync(root);
  }

  /* Construction par `document.createElement` + `textContent`, JAMAIS par
   * `innerHTML` avec une valeur interpolée : la valeur vient du YAML de
   * configuration, éditable par un collègue. Une concaténation de chaîne HTML
   * en ferait un vecteur d'injection dans la page de tous les autres. */
  function buildTag(value, label) {
    var li = document.createElement("li");
    li.className = "field-composer__tag";
    li.setAttribute("draggable", "true");
    li.setAttribute("data-field-composer-tag", "");
    li.setAttribute("data-field-value", value);

    var rank = document.createElement("span");
    rank.className = "field-composer__rank";
    rank.setAttribute("data-field-composer-rank", "");
    li.appendChild(rank);

    var text = document.createElement("span");
    text.className = "field-composer__tag-text";

    var labelNode = document.createElement("span");
    labelNode.className = "field-composer__tag-label";
    labelNode.textContent = label;
    text.appendChild(labelNode);

    var code = document.createElement("code");
    code.className = "field-composer__tag-code";
    code.textContent = value;
    text.appendChild(code);

    li.appendChild(text);

    /* `type="button"` explicite : un `<button>` sans type vaut `submit` dans un
     * formulaire. Monter une étiquette d'un rang aurait ENVOYÉ le formulaire —
     * et mis un changement en file que personne n'a demandé. */
    li.appendChild(makeButton("field-composer__move", "↑", "Monter " + value + " d'un rang", "data-field-composer-move", "up"));
    li.appendChild(makeButton("field-composer__move", "↓", "Descendre " + value + " d'un rang", "data-field-composer-move", "down"));
    li.appendChild(makeButton("field-composer__remove", "✕", "Retirer " + value, "data-field-composer-remove", ""));

    return li;
  }

  function makeButton(className, text, ariaLabel, dataAttr, dataValue) {
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = className;
    btn.textContent = text;
    btn.setAttribute("aria-label", ariaLabel);
    btn.setAttribute(dataAttr, dataValue);
    return btn;
  }

  function removeTag(root, tag) {
    var value = tag.getAttribute("data-field-value") || "";
    var labelNode = tag.querySelector(".field-composer__tag-label");
    var label = labelNode ? labelNode.textContent.trim() : value;
    tag.remove();
    restoreOption(root, value, label);
    sync(root);
  }

  /* Une dimension retirée doit REDEVENIR disponible : sans cela, un retrait par
   * erreur serait irréversible sans recharger la page — et l'utilisateur
   * perdrait au passage tous ses autres ajustements non enregistrés. */
  function restoreOption(root, value, label) {
    var available = root.querySelector("[data-field-composer-available]");
    if (!available || optionFor(root, value)) {
      return;
    }

    var li = document.createElement("li");
    li.className = "field-composer__available-item";
    li.setAttribute("data-field-composer-option", "");
    li.setAttribute("data-field-value", value);
    li.setAttribute("data-field-search", (value + " " + label).toLowerCase());

    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "field-composer__add";
    btn.setAttribute("data-field-composer-add", "");
    btn.setAttribute("aria-label", "Ajouter " + value + " aux dimensions retenues");

    var sign = document.createElement("span");
    sign.className = "field-composer__add-sign";
    sign.setAttribute("aria-hidden", "true");
    sign.textContent = "+";
    btn.appendChild(sign);

    var labelNode = document.createElement("span");
    labelNode.className = "field-composer__tag-label";
    labelNode.textContent = label;
    btn.appendChild(labelNode);

    var code = document.createElement("code");
    code.className = "field-composer__tag-code";
    code.textContent = value;
    btn.appendChild(code);

    li.appendChild(btn);

    /* Réinsertion à sa place alphabétique plutôt qu'en fin de liste : une
     * dimension qui réapparaît au hasard de l'ordre des retraits se cherche
     * ensuite à l'œil dans une liste de vingt entrées. */
    var siblings = toArray(available.querySelectorAll("[data-field-composer-option]"));
    var before = null;
    for (var i = 0; i < siblings.length; i++) {
      if ((siblings[i].getAttribute("data-field-value") || "") > value) {
        before = siblings[i];
        break;
      }
    }
    available.insertBefore(li, before);

    /* La recherche en cours reste appliquée : réinsérer une entrée visible
     * alors qu'un filtre est actif ferait apparaître un champ qui ne
     * correspond pas à la saisie. */
    applyFilter(root);
  }

  /* ------------------------------------------------------------------
   * Recherche dans les champs disponibles
   * ------------------------------------------------------------------ */

  function applyFilter(root) {
    var input = root.querySelector("[data-field-composer-search]");
    var options = toArray(root.querySelectorAll("[data-field-composer-option]"));
    var query = input ? input.value.trim().toLowerCase() : "";
    var visible = 0;

    options.forEach(function (option) {
      var haystack = option.getAttribute("data-field-search") || "";
      var match = query === "" || haystack.indexOf(query) !== -1;
      option.hidden = !match;
      if (match) {
        visible += 1;
      }
    });

    /* ROBUSTESSE — recherche sans résultat : message explicite. Une liste qui
     * se vide sans rien dire est indistinguable d'un écran cassé ; l'utilisateur
     * conclut que le champ ne sert à rien au lieu de corriger sa saisie.
     * Le message n'apparaît QUE s'il reste des options dans le catalogue :
     * quand tout est déjà retenu, c'est l'autre message (« tous les champs sont
     * déjà retenus », rendu par Jinja) qui est pertinent. */
    var noMatch = root.querySelector("[data-field-composer-no-match]");
    if (noMatch) {
      noMatch.hidden = !(options.length > 0 && visible === 0);
    }
  }

  function refreshAvailability(root) {
    applyFilter(root);
  }

  /* ------------------------------------------------------------------
   * Réordonnancement au clavier
   * ------------------------------------------------------------------ */

  /* Le glisser-déposer était la demande explicite, mais une liste ordonnable
   * UNIQUEMENT à la souris est inutilisable pour qui ne peut pas glisser :
   * clavier seul, tremblement, lecteur d'écran, écran tactile où le DnD HTML5
   * n'est pas gréé. Les flèches ↑ / ↓ sont donc un chemin de PLEIN EXERCICE,
   * pas une consolation. */
  function move(root, tag, direction) {
    var list = listOf(root);
    if (!list) {
      return;
    }
    if (direction === "up") {
      var previous = tag.previousElementSibling;
      if (previous) {
        list.insertBefore(tag, previous);
      }
    } else {
      var next = tag.nextElementSibling;
      if (next) {
        list.insertBefore(next, tag);
      }
    }
    sync(root);
  }

  /* ------------------------------------------------------------------
   * Événements — tous délégués sur `document` (voir en-tête).
   * ------------------------------------------------------------------ */

  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!target || target.nodeType !== 1) {
      return;
    }

    var addBtn = closest(target, "[data-field-composer-add]");
    if (addBtn) {
      var addRoot = rootOf(addBtn);
      var option = closest(addBtn, "[data-field-composer-option]");
      if (addRoot && option) {
        addValue(addRoot, option.getAttribute("data-field-value"));
      }
      return;
    }

    var removeBtn = closest(target, "[data-field-composer-remove]");
    if (removeBtn) {
      var removeRoot = rootOf(removeBtn);
      var tagToRemove = closest(removeBtn, "[data-field-composer-tag]");
      if (removeRoot && tagToRemove) {
        removeTag(removeRoot, tagToRemove);
      }
      return;
    }

    var moveBtn = closest(target, "[data-field-composer-move]");
    if (moveBtn) {
      var moveRoot = rootOf(moveBtn);
      var tagToMove = closest(moveBtn, "[data-field-composer-tag]");
      if (moveRoot && tagToMove) {
        move(moveRoot, tagToMove, moveBtn.getAttribute("data-field-composer-move"));
      }
    }
  });

  document.addEventListener("input", function (event) {
    var search = closest(event.target, "[data-field-composer-search]");
    if (search) {
      var root = rootOf(search);
      if (root) {
        applyFilter(root);
      }
    }
  });

  /* La touche Entrée dans le champ de recherche SOUMETTRAIT le formulaire : un
   * champ de saisie unique visible déclenche l'envoi implicite du formulaire.
   * Mettre un changement en file parce qu'on a validé une recherche est
   * exactement le genre de mauvaise manip que ce lot doit empêcher. */
  document.addEventListener("keydown", function (event) {
    var search = closest(event.target, "[data-field-composer-search]");
    if (search && event.key === "Enter") {
      event.preventDefault();
    }
  });

  /* ---------------- Glisser-déposer HTML5 natif ---------------- */

  document.addEventListener("dragstart", function (event) {
    var tag = closest(event.target, "[data-field-composer-tag]");
    if (!tag) {
      return;
    }
    dragged = tag;
    tag.classList.add(DRAGGING_CLASS);
    if (event.dataTransfer) {
      event.dataTransfer.effectAllowed = "move";
      /* Une charge utile DOIT être posée : Firefox refuse d'initier le
       * glissement quand `dataTransfer` est vide — le glisser-déposer y serait
       * simplement inopérant, sans erreur. */
      try {
        event.dataTransfer.setData("text/plain", tag.getAttribute("data-field-value") || "");
      } catch (err) {
        /* Certains navigateurs verrouillent `setData` selon le contexte. Le
         * déplacement reste piloté par la variable `dragged` : on continue. */
      }
    }
  });

  document.addEventListener("dragover", function (event) {
    if (!dragged) {
      return;
    }
    var over = closest(event.target, "[data-field-composer-tag]");
    var list = closest(event.target, "[data-field-composer-list]");
    if (!over && !list) {
      return;
    }
    /* `preventDefault` est ce qui AUTORISE le dépôt : sans lui, le navigateur
     * refuse la zone et l'étiquette « revient » à sa place au relâchement,
     * sans le moindre message. C'est le piège classique du DnD HTML5. */
    event.preventDefault();
    if (event.dataTransfer) {
      event.dataTransfer.dropEffect = "move";
    }
    if (over && over !== dragged) {
      clearDropTargets(rootOf(over));
      over.classList.add(DROP_TARGET_CLASS);
    }
  });

  document.addEventListener("drop", function (event) {
    if (!dragged) {
      return;
    }
    var root = rootOf(dragged);
    var over = closest(event.target, "[data-field-composer-tag]");
    var list = closest(event.target, "[data-field-composer-list]");

    if (!over && !list) {
      return;
    }
    event.preventDefault();

    if (over && over !== dragged && root && rootOf(over) === root) {
      /* Insertion AVANT ou APRÈS selon la moitié survolée : sans ce test,
       * déposer sur la moitié basse d'une étiquette la placerait quand même
       * au-dessus, et l'ordre obtenu ne serait pas celui visé. */
      var rect = over.getBoundingClientRect();
      var after = event.clientY > rect.top + rect.height / 2;
      over.parentElement.insertBefore(dragged, after ? over.nextElementSibling : over);
      sync(root);
    } else if (list && root && listOf(root) === list) {
      /* Dépôt dans la liste mais à côté de toute étiquette (marge basse) :
       * placement en fin, plutôt qu'un abandon silencieux. */
      list.appendChild(dragged);
      sync(root);
    }
  });

  /* ROBUSTESSE — glisser une étiquette HORS de la zone puis relâcher.
   * `dragend` se déclenche TOUJOURS, y compris quand le dépôt a été refusé
   * (hors zone, touche Échap, relâchement au-dessus de la barre du
   * navigateur). C'est ici, et non dans `drop`, que le nettoyage doit vivre :
   * un `drop` qui n'a jamais lieu laisserait l'étiquette figée en état
   * « en cours de déplacement », à moitié transparente et non cliquable, pour
   * le reste de la session. Aucun déplacement n'est appliqué dans ce cas :
   * l'ordre reste exactement celui d'avant le glissement. */
  document.addEventListener("dragend", function (event) {
    var tag = closest(event.target, "[data-field-composer-tag]");
    if (tag) {
      tag.classList.remove(DRAGGING_CLASS);
    }
    if (dragged) {
      dragged.classList.remove(DRAGGING_CLASS);
      var root = rootOf(dragged);
      if (root) {
        clearDropTargets(root);
        /* Resynchronisation systématique : même si rien n'a bougé, elle
         * garantit que le champ caché et les rangs affichés décrivent le DOM
         * réel. Un état incohérent après une manip avortée est précisément ce
         * qu'on ne peut pas se permettre sur de la configuration. */
        sync(root);
      }
    }
    dragged = null;
  });

  function clearDropTargets(root) {
    if (!root) {
      return;
    }
    toArray(root.querySelectorAll("." + DROP_TARGET_CLASS)).forEach(function (node) {
      node.classList.remove(DROP_TARGET_CLASS);
    });
  }

  /* ------------------------------------------------------------------
   * Initialisation
   * ------------------------------------------------------------------ */

  /* `data-field-composer-ready` est posé UNIQUEMENT ici, quand le fichier
   * s'exécute vraiment. C'est ce marqueur qui masque le bandeau de mode
   * dégradé (règle CSS). Le bandeau est donc visible par DÉFAUT et retiré par
   * le JS, jamais l'inverse : un bandeau caché par défaut que le JS devrait
   * révéler ne s'afficherait justement PAS le jour où le JS ne tourne pas. */
  function init() {
    toArray(document.querySelectorAll(ROOT_SELECTOR)).forEach(function (root) {
      root.setAttribute("data-field-composer-ready", "");
      applyFilter(root);
      sync(root);
    });
  }

  /* Après un swap HTMX, le panneau réinjecté revient avec un composeur neuf,
   * sans le marqueur `ready` et sans rangs recalculés : sans ce ré-init, le
   * bandeau de mode dégradé réapparaîtrait sur une page où le JS tourne
   * parfaitement. */
  document.addEventListener("htmx:afterSwap", init);
  document.addEventListener("DOMContentLoaded", init);
})();
