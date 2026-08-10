/* Compositeur d'expressions de filtre Akvorado — « à la Palo Alto ».
 *
 * LE GESTE QUE CE FICHIER RENVERSE : jusqu'ici, enregistrer un filtre demandait
 * de connaître par cœur la syntaxe d'Akvorado ET le nom exact de ses 61
 * colonnes, puis de les taper dans un champ texte nu. Ici on part de ce qui
 * EXISTE dans les derniers flux : on cherche, on clique un champ, on clique une
 * valeur réellement observée, et l'expression se construit.
 *
 * POURQUOI CE FICHIER EXISTE plutôt qu'un `<script>` ou des `onclick=` dans le
 * template : la CSP du service est `script-src 'self'`, SANS `unsafe-inline` ni
 * `unsafe-eval`. Tout JS inline — bloc `<script>` comme attribut `onclick` — est
 * BLOQUÉ par le navigateur, et il l'est en silence du point de vue de
 * l'application : la page s'affiche, les boutons sont là, rien ne réagit au
 * clic. Défaut mesuré deux fois sur ce projet (2026-08-06 : `onchange=` du
 * formulaire d'interface, `onchange=` du sélecteur de fenêtre).
 *
 * POURQUOI la délégation d'événements sur `document` plutôt qu'un écouteur par
 * bouton : les cartes de champs sont RÉINJECTÉES par htmx à chaque frappe dans
 * la barre de recherche. Des écouteurs posés au chargement seraient perdus sur
 * le premier fragment remplacé — le compositeur cesserait de réagir dès la
 * première recherche, c'est-à-dire immédiatement.
 *
 * CE QUE CE FICHIER NE FAIT PAS, DÉLIBÉRÉMENT :
 * - il ne décide JAMAIS si une valeur a besoin de guillemets. C'est la console
 *   Akvorado qui le dit, via `data-composer-quoted`. Une règle devinée ici
 *   (« un nombre n'a pas besoin de quotes ») divergerait de la version
 *   d'Akvorado déployée et produirait des filtres refusés.
 * - il ne valide JAMAIS la grammaire. Le verdict vient de
 *   `/config/filters/validate`, seule autorité sur sa propre syntaxe.
 * - il n'est JAMAIS un passage obligé : le champ d'expression reste un
 *   `<textarea>` ordinaire dans un `<form>` ordinaire. Script non exécuté, le
 *   formulaire d'ajout reste soumissible à la main (voir « REPLI SANS JS »).
 */
(function () {
  "use strict";

  /* Racine du compositeur. Tout est cherché SOUS elle : la page de section peut
   * contenir d'autres compositeurs (celui des étiquettes de `visualize_defaults`,
   * `field-composer.js`), et deux scripts qui se disputent les mêmes sélecteurs
   * produiraient des insertions dans le mauvais champ. */
  var ROOT_SELECTOR = "[data-filter-composer]";
  var EXPRESSION_SELECTOR = "[data-composer-expression]";

  function root() {
    return document.querySelector(ROOT_SELECTOR);
  }

  function expressionField() {
    /* Recherche dans TOUT le document, et non dans la racine du compositeur.
     *
     * DÉFAUT MESURÉ AU NAVIGATEUR (2026-08-06) : la zone d'expression vit dans
     * le FORMULAIRE D'AJOUT, en dehors du bloc de composition — c'est même sa
     * place naturelle, puisque c'est elle qui est postée. Chercher dans la
     * racine ne la trouvait donc jamais : chaque clic sur un champ, une valeur
     * ou un opérateur ne produisait RIEN, sans erreur en console ni à l'écran.
     * Le compositeur s'affichait parfaitement et ne composait pas.
     *
     * Sonde qui l'a montré : `racine.contains(textarea)` -> false.
     *
     * Le repli sur la racine est conservé pour le cas où plusieurs zones
     * coexisteraient un jour sur la même page. */
    var direct = document.querySelector(EXPRESSION_SELECTOR);
    if (direct) {
      return direct;
    }
    var host = root();
    return host ? host.querySelector(EXPRESSION_SELECTOR) : null;
  }

  /* ---------------------------------------------------------------------
   * Insertion dans l'expression
   * ------------------------------------------------------------------ */

  /* Un fragment s'insère À LA POSITION DU CURSEUR, pas en fin de champ.
   *
   * POURQUOI : l'expression se construit rarement de gauche à droite d'un seul
   * jet. On tape une première comparaison suivie de `AND `, on se rend compte
   * qu'il manque une parenthèse ouvrante au tout début, on clique `(`. Une
   * insertion systématique en fin de champ collerait la parenthèse APRÈS le
   * `AND` — donc au mauvais endroit — et l'utilisateur devrait défaire à la
   * main ce que le bouton vient de faire. Le compositeur doit obéir au curseur,
   * jamais le déplacer d'autorité. */
  function insert(fragment) {
    var field = expressionField();
    if (!field) {
      return;
    }

    var value = field.value;
    /* `selectionStart` vaut `null` sur certains types de champ et quand le
     * champ n'a jamais reçu le focus : on retombe alors sur la fin du texte,
     * qui est le comportement attendu pour une première insertion. */
    var start = typeof field.selectionStart === "number" ? field.selectionStart : value.length;
    var end = typeof field.selectionEnd === "number" ? field.selectionEnd : value.length;

    var avant = value.slice(0, start);
    var apres = value.slice(end);

    /* Espacement calculé, jamais concaténation brute : `SrcPort` collé à un
     * `AND` précédent donnerait `ANDSrcPort`, refusé par Akvorado pour une
     * raison que rien à l'écran n'expliquerait. On n'ajoute d'espace que s'il
     * en manque un — sans quoi cliquer trois champs de suite produirait des
     * doubles espaces qui, eux, sont inoffensifs mais donnent une expression
     * d'apparence négligée. */
    var separateurGauche = avant.length > 0 && !/\s$/.test(avant) ? " " : "";
    var separateurDroite = apres.length > 0 && !/^\s/.test(apres) ? " " : "";

    var insere = separateurGauche + fragment + separateurDroite;
    field.value = avant + insere + apres;

    /* Le curseur se repositionne APRÈS le fragment inséré (avant l'espace de
     * droite) : la frappe suivante continue naturellement l'expression au lieu
     * de repartir du début du champ. */
    var curseur = avant.length + separateurGauche.length + fragment.length;
    if (typeof field.setSelectionRange === "function") {
      field.setSelectionRange(curseur, curseur);
    }
    field.focus();

    /* L'événement `input` est ÉMIS À LA MAIN : une écriture par script sur
     * `field.value` n'en déclenche AUCUN. Sans cette ligne, la validation
     * htmx (câblée sur `input changed delay:500ms`) ne se déclencherait jamais
     * sur les fragments insérés au clic — le verdict resterait figé sur l'état
     * précédent, donc MENTIRAIT sur l'expression réellement affichée. C'est le
     * motif du « zéro silencieux » : un état affiché qui ne correspond plus à
     * la mesure. */
    field.dispatchEvent(new Event("input", { bubbles: true }));
  }

  /* Une valeur ne se cite QUE si la console l'a dit. `data-composer-quoted`
   * vaut "1" (guillemets requis, ex. `ExporterName = 'proxy-frontal'`) ou "0"
   * (valeur nue, ex. `SrcPort = 443`).
   *
   * ABSENCE DE L'ATTRIBUT : la route `/config/filters/fields` rend les valeurs
   * de l'échantillon SANS `data-composer-quoted` — seule
   * `/config/filters/values` le porte. On ne devine pas pour autant : on
   * retombe sur la citation, parce qu'Akvorado accepte `SrcPort = '443'` (une
   * chaîne se compare à un nombre) alors qu'il REFUSE
   * `ExporterName = proxy-frontal` (un identifiant nu n'est pas une chaîne). En cas
   * de doute, citer est le choix qui échoue le moins. */
  function quoteIfNeeded(valeur, quotedAttr) {
    if (quotedAttr === "0") {
      return valeur;
    }
    /* Une apostrophe dans la valeur casserait la chaîne et changerait le sens
     * de l'expression. On la double, comme le fait SQL. */
    return "'" + String(valeur).replace(/'/g, "''") + "'";
  }

  /* ---------------------------------------------------------------------
   * Anti double-insertion
   * ------------------------------------------------------------------ */

  /* Un double-clic sur un champ produit DEUX événements `click`. Sans garde,
   * l'expression recevrait `SrcAddr SrcAddr` — et l'utilisateur, qui a juste
   * cliqué un peu vite, verrait une expression fausse sans comprendre pourquoi.
   *
   * Le garde porte sur (élément + fragment) et non sur un simple verrou global
   * temporel : cliquer volontairement deux fois `AND` à 300 ms d'intervalle est
   * un geste LÉGITIME sur un bouton d'opérateur, alors que deux `click` sur le
   * MÊME bouton de champ en moins de 350 ms ne l'est jamais. */
  var DOUBLE_CLIC_MS = 350;
  var dernierClic = { cible: null, fragment: null, at: 0 };

  function estDoublon(cible, fragment) {
    var maintenant = Date.now();
    var doublon =
      dernierClic.cible === cible &&
      dernierClic.fragment === fragment &&
      maintenant - dernierClic.at < DOUBLE_CLIC_MS;
    dernierClic = { cible: cible, fragment: fragment, at: maintenant };
    return doublon;
  }

  /* ---------------------------------------------------------------------
   * Délégation des clics
   * ------------------------------------------------------------------ */

  document.addEventListener("click", function (event) {
    var target = event.target;
    if (!target || typeof target.closest !== "function") {
      return;
    }

    /* Le compositeur vit dans une page qui contient d'autres blocs cliquables.
     * On ne réagit qu'aux clics DANS le compositeur. */
    var host = target.closest(ROOT_SELECTOR);
    if (!host) {
      return;
    }

    /* --- Une valeur : insère `Champ = valeur` (ou `Champ = 'valeur'`) ---
     * Testé AVANT le champ : un bouton de valeur porte lui aussi
     * `data-composer-field` (il a besoin de savoir à quelle colonne il
     * appartient). Dans l'ordre inverse, cliquer une valeur insérerait le seul
     * nom de colonne — le clic le plus utile du compositeur ne ferait que la
     * moitié de son travail. */
    var valueBtn = target.closest("[data-composer-value]");
    if (valueBtn && host.contains(valueBtn)) {
      var champ = valueBtn.getAttribute("data-composer-field") || "";
      var valeur = valueBtn.getAttribute("data-composer-value") || "";
      var quoted = valueBtn.getAttribute("data-composer-quoted");
      var fragment = champ + " = " + quoteIfNeeded(valeur, quoted);
      if (!estDoublon(valueBtn, fragment)) {
        insert(fragment);
      }
      event.preventDefault();
      return;
    }

    /* --- Un champ : insère le seul nom de colonne ---
     * Sans opérateur ni valeur : l'utilisateur enchaîne avec le bouton `=` puis
     * une valeur, ou tape ce qu'il veut. Insérer `SrcAddr = ` d'autorité
     * imposerait l'égalité alors que `SrcAddr IN (...)` est tout aussi courant. */
    var fieldBtn = target.closest("[data-composer-field]");
    if (fieldBtn && host.contains(fieldBtn)) {
      var nom = fieldBtn.getAttribute("data-composer-field") || "";
      if (nom && !estDoublon(fieldBtn, nom)) {
        insert(nom);
      }
      event.preventDefault();
      return;
    }

    /* --- Un opérateur --- */
    var opBtn = target.closest("[data-composer-operator]");
    if (opBtn && host.contains(opBtn)) {
      var op = opBtn.getAttribute("data-composer-operator") || "";
      if (op && !estDoublon(opBtn, op)) {
        insert(op);
      }
      event.preventDefault();
      return;
    }

    /* --- Vider l'expression ---
     * POURQUOI un bouton dédié plutôt que « sélectionner tout puis supprimer » :
     * une expression composée au clic fait vite 120 caractères, et la reprendre
     * de zéro est un geste courant. Pas de confirmation : rien n'est enregistré
     * à ce stade, l'expression n'est qu'un brouillon. */
    var clearBtn = target.closest("[data-composer-clear]");
    if (clearBtn && host.contains(clearBtn)) {
      var field = expressionField();
      if (field) {
        field.value = "";
        field.focus();
        field.dispatchEvent(new Event("input", { bubbles: true }));
      }
      event.preventDefault();
      return;
    }
  });

  /* ---------------------------------------------------------------------
   * REPLI SANS JS — ce que le script MASQUE, jamais ce qu'il révèle
   * ------------------------------------------------------------------ */

  /* Le compositeur est une AIDE, pas un passage obligé. Le formulaire d'ajout
   * est un `<form>` ordinaire avec un `<textarea name="content">` : sans ce
   * script, on tape l'expression à la main et on l'enregistre — exactement
   * comme avant ce chantier, sans aucune perte de capacité.
   *
   * Cette marque `data-filter-composer-ready` est posée par le SCRIPT, à
   * l'exécution. Le CSS s'en sert pour masquer la mention « composition au clic
   * indisponible » et pour révéler les commandes qui n'ont de sens qu'avec du
   * JS (opérateurs, bouton vider).
   *
   * LE SENS DE LA MARQUE EST CRUCIAL : les commandes JS sont rendues par le
   * serveur puis MASQUÉES si le script ne tourne pas — jamais l'inverse. Posées
   * masquées et révélées par le script, elles resteraient invisibles le seul
   * jour où ça compte : celui où le script échoue. Même raisonnement que le
   * bouton de repli du sélecteur de fenêtre (`autosubmit-fallback`, mesuré
   * 2026-08-06). */
  function marquerPret() {
    var host = root();
    if (host) {
      host.setAttribute("data-filter-composer-ready", "1");
    }
  }

  /* Posée aux deux moments : au chargement initial, et après chaque swap htmx —
   * le panneau de section entier peut être réinjecté après un changement mis en
   * file, ce qui emporterait la marque avec l'ancien DOM. */
  document.addEventListener("DOMContentLoaded", marquerPret);
  document.addEventListener("htmx:afterSwap", marquerPret);
  /* `defer` garantit l'exécution après l'analyse du document, mais le script
   * peut aussi être évalué APRÈS `DOMContentLoaded` (cache, réinjection). Cet
   * appel direct couvre ce cas — sans lui, la marque ne serait jamais posée et
   * l'écran afficherait à tort « composition indisponible ». */
  marquerPret();
})();
