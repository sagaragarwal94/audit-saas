// Loaded with a plain (blocking) <script src> in <head> so the theme is set
// before first paint, and kept in one file so the CSP can be script-src 'self'
// with no inline scripts.
(function () {
  var root = document.documentElement;
  var stored = null;
  try { stored = localStorage.getItem("theme"); } catch (e) { /* storage blocked */ }
  root.dataset.theme = stored || (window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark");

  document.addEventListener("DOMContentLoaded", function () {
    var toggle = document.getElementById("theme-toggle");
    if (toggle) {
      toggle.addEventListener("click", function () {
        var next = root.dataset.theme === "light" ? "dark" : "light";
        root.dataset.theme = next;
        try { localStorage.setItem("theme", next); } catch (e) { /* storage blocked */ }
      });
    }
    addCopyButtons();
    setUpRuleFilter();
  });

  function addCopyButtons() {
    if (!navigator.clipboard) return;
    document.querySelectorAll(".code-block[data-copy]").forEach(function (block) {
      var code = block.querySelector("pre code");
      var head = block.querySelector(".code-head");
      if (!code || !head) return;
      var button = document.createElement("button");
      button.type = "button";
      button.className = "copy-btn";
      button.textContent = "Copy";
      button.setAttribute("aria-label", "Copy code to clipboard");
      button.addEventListener("click", function () {
        // Strip "$ " shell prompts so the pasted text runs as-is.
        var text = code.textContent.replace(/^\$ /gm, "");
        navigator.clipboard.writeText(text).then(function () {
          button.textContent = "Copied";
          setTimeout(function () { button.textContent = "Copy"; }, 1500);
        });
      });
      head.appendChild(button);
    });
  }

  function setUpRuleFilter() {
    var search = document.getElementById("rule-search");
    if (!search) return;
    var chips = Array.prototype.slice.call(document.querySelectorAll("[data-sev-filter]"));
    var rules = Array.prototype.slice.call(document.querySelectorAll(".rule"));
    var categories = Array.prototype.slice.call(document.querySelectorAll(".category"));
    var count = document.getElementById("rule-count");
    var empty = document.getElementById("rule-empty");
    var severity = "all";

    rules.forEach(function (rule) {
      var sev = rule.querySelector(".sev");
      rule.dataset.severity = sev ? sev.textContent.trim() : "";
      rule.dataset.haystack = (rule.id + " " + rule.textContent + " " + rule.closest(".category").querySelector("h2").textContent).toLowerCase();
    });

    function apply() {
      var terms = search.value.toLowerCase().split(/\s+/).filter(Boolean);
      var shown = 0;
      rules.forEach(function (rule) {
        var match = (severity === "all" || rule.dataset.severity === severity) &&
          terms.every(function (term) { return rule.dataset.haystack.indexOf(term) !== -1; });
        rule.hidden = !match;
        if (match) shown += 1;
      });
      categories.forEach(function (category) {
        category.hidden = !category.querySelector(".rule:not([hidden])");
      });
      count.textContent = shown === rules.length ? "All " + rules.length + " rules" : shown + " of " + rules.length + " rules";
      empty.hidden = shown !== 0;
    }

    search.addEventListener("input", apply);
    chips.forEach(function (chip) {
      chip.addEventListener("click", function () {
        severity = chip.dataset.sevFilter;
        chips.forEach(function (other) { other.setAttribute("aria-pressed", String(other === chip)); });
        apply();
      });
    });
    // Browsers restore form values on back/forward; a deep link
    // (/rules#RULE_ID) must never land on a filtered-out rule.
    if (location.hash) search.value = "";
    apply();
  }
})();
