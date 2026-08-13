/* Light/dark theme, shared with nanoinfra.org via the same localStorage key so a
 * visitor's choice carries across both hosts.
 *
 * This lives in an external file rather than inline in layout.html on purpose.
 * The preview view renders untrusted, third-party-submitted SKILL.md, and the
 * tests assert the response never contains a live `<script>` tag -- that is the
 * security property the preview feature depends on. An inline block in the
 * layout would defeat that assertion for every page, so the chrome's own script
 * is loaded by src and the check stays meaningful.
 */

(function () {
  var KEY = "nanoinfra-theme";
  var root = document.documentElement;

  // Runs while the document is still parsing (this file is loaded from <head>
  // without defer), so the saved theme is applied before first paint.
  var saved = localStorage.getItem(KEY);
  if (saved === "dark" || saved === "light") {
    root.setAttribute("data-theme", saved);
  }

  function current() {
    var explicit = root.getAttribute("data-theme");
    if (explicit) {
      return explicit;
    }
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function wire() {
    var button = document.getElementById("theme-toggle");
    if (!button) {
      return;
    }
    button.addEventListener("click", function () {
      var next = current() === "dark" ? "light" : "dark";
      root.setAttribute("data-theme", next);
      localStorage.setItem(KEY, next);
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", wire);
  } else {
    wire();
  }
})();
