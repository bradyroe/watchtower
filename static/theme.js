// Runs before paint so the saved theme never flashes. Dark is the default.
(function () {
  var t = "dark";
  try { t = localStorage.getItem("wt-theme") || "dark"; } catch (e) {}
  document.documentElement.setAttribute("data-theme", t);
})();
