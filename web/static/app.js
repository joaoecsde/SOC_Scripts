// Investigation Tools: landing page tabs, drop zones, key memory, result tabs
// and job status polling. Every block checks for its elements first, so the
// same file is loaded on every page.
(function () {
  var KEY_FIELDS = ["abuseipdb_key", "virustotal_key"];

  // Tool tabs: show the pane, enable only its fields, point the form at the tool.
  var form = document.getElementById("tool-form");
  var tabs = document.querySelectorAll(".switch [data-t]");
  function selectTool(tool) {
    tabs.forEach(function (t) {
      t.setAttribute("aria-selected", t.getAttribute("data-t") === tool ? "true" : "false");
    });
    document.querySelectorAll("fieldset.pane").forEach(function (p) {
      var on = p.id === "p-" + tool;
      p.classList.toggle("on", on);
      p.disabled = !on;
    });
    document.querySelectorAll(".feats").forEach(function (f) {
      var on = f.id === "f-" + tool;
      f.classList.toggle("on", on);
      if (on) {
        document.getElementById("aboutTitle").textContent = f.getAttribute("data-title");
        document.getElementById("aboutLede").textContent = f.getAttribute("data-lede");
      }
    });
    form.action = "/analyse/" + tool;
    form.elements.tool.value = tool;
    try { history.replaceState(null, "", "/?tool=" + tool); } catch (e) {}
  }
  if (form) {
    tabs.forEach(function (t) {
      t.addEventListener("click", function (ev) {
        ev.preventDefault();
        selectTool(t.getAttribute("data-t"));
      });
    });
  }

  // Checkbox that opens a group of fields (online lookups).
  document.querySelectorAll("[data-reveal]").forEach(function (box) {
    var target = document.getElementById(box.getAttribute("data-reveal"));
    box.addEventListener("change", function () { target.classList.toggle("open", box.checked); });
  });

  // Drop zones: drag a file onto the zone or pick one; show its name.
  document.querySelectorAll("[data-drop]").forEach(function (zone) {
    var input = zone.querySelector("input[type=file]");
    var chosen = zone.querySelector(".chosen");
    function showName() {
      chosen.textContent = input.files && input.files.length ? input.files[0].name : "";
    }
    ["dragenter", "dragover"].forEach(function (name) {
      zone.addEventListener(name, function (ev) { ev.preventDefault(); zone.classList.add("over"); });
    });
    ["dragleave", "drop"].forEach(function (name) {
      zone.addEventListener(name, function () { zone.classList.remove("over"); });
    });
    zone.addEventListener("drop", function (ev) {
      ev.preventDefault();
      if (ev.dataTransfer && ev.dataTransfer.files.length) {
        input.files = ev.dataTransfer.files;
        showName();
      }
    });
    input.addEventListener("change", showName);
  });

  // API keys live in sessionStorage only (cleared when the tab closes).
  if (form) {
    KEY_FIELDS.forEach(function (name) {
      var saved = null;
      try { saved = sessionStorage.getItem(name); } catch (e) {}
      if (saved) {
        form.querySelectorAll("input[name=" + name + "]").forEach(function (i) { i.value = saved; });
      }
    });
    form.addEventListener("submit", function () {
      KEY_FIELDS.forEach(function (name) {
        var input = form.querySelector("fieldset:not([disabled]) input[name=" + name + "]");
        if (!input) { return; }
        try {
          if (input.value) { sessionStorage.setItem(name, input.value); }
          else { sessionStorage.removeItem(name); }
        } catch (e) {}
      });
    });
  }

  // Result section tabs.
  document.querySelectorAll("[data-tabs]").forEach(function (list) {
    var buttons = list.querySelectorAll("[role=tab]");
    buttons.forEach(function (b) {
      b.addEventListener("click", function () {
        buttons.forEach(function (x) {
          var on = x === b;
          x.setAttribute("aria-selected", on ? "true" : "false");
          document.getElementById(x.getAttribute("aria-controls")).hidden = !on;
        });
      });
    });
  });

  // Progress page: poll the job status and reload when the job ends.
  var box = document.querySelector("[data-job-status]");
  if (box) {
    var url = box.getAttribute("data-job-status");
    var track = box.querySelector(".track");
    var bar = document.getElementById("bar");
    var tick = function () {
      fetch(url).then(function (r) { return r.json(); }).then(function (s) {
        if (s.status !== "running") { window.location.reload(); return; }
        track.classList.toggle("indeterminate", !s.total);
        bar.style.width = s.total ? Math.round(100 * s.done / s.total) + "%" : "";
        document.getElementById("count").textContent =
          s.total ? s.done + " of " + s.total + " done" : "Analysing…";
        document.getElementById("label").textContent = s.label;
      }).catch(function () {});
    };
    setInterval(tick, 1000);
  }
}());
