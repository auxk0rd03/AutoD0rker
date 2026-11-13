(function () {
  "use strict";

  var consoleEl = document.getElementById("sse-console-log");
  var tabSingle = document.getElementById("tab-mode-single");
  var tabBatch = document.getElementById("tab-mode-batch");
  var exportMdBtn = document.getElementById("btn-export-md");
  var exportDocxBtn = document.getElementById("btn-export-docx");

  function appendSseLine(htmlStr) {
    if (!consoleEl) return;
    var wrapper = document.createElement("div");
    wrapper.innerHTML = htmlStr;
    while (wrapper.firstChild) {
      consoleEl.appendChild(wrapper.firstChild);
    }
    while (consoleEl.children.length > 250) {
      consoleEl.removeChild(consoleEl.firstChild);
    }
    consoleEl.scrollTop = consoleEl.scrollHeight;
  }

  function refreshPanels(detail) {
    var qs = "";
    if (detail && detail.scan_id) {
      qs = "?scan_id=" + encodeURIComponent(detail.scan_id);
      if (detail.batch_id) {
        qs += "&batch_id=" + encodeURIComponent(detail.batch_id);
      }
      if (exportMdBtn) {
        exportMdBtn.setAttribute("href", "/api/export/md/" + encodeURIComponent(detail.scan_id));
      }
      if (exportDocxBtn) {
        exportDocxBtn.setAttribute("href", "/api/export/docx/" + encodeURIComponent(detail.scan_id));
      }
    }

    if (window.htmx) {
      window.htmx.ajax("GET", "/panels/findings" + qs, {
        target: "#oob-sink",
        swap: "innerHTML"
      });
      window.htmx.ajax("GET", "/panels/svg-telemetry" + qs, {
        target: "#panel-visual-telemetry",
        swap: "innerHTML"
      });
      window.htmx.ajax("POST", "/api/backup", {
        target: "#audit-lock-badge",
        swap: "innerHTML"
      });
    }
  }

  function initEventSource() {
    if (typeof EventSource === "undefined") return;
    var es = new EventSource("/api/stream-logs-sse");
    es.addEventListener("connected", function (ev) {
      appendSseLine(ev.data);
    });
    es.addEventListener("log", function (ev) {
      appendSseLine(ev.data);
    });
    es.addEventListener("scanUpdated", function (ev) {
      try {
        var detail = JSON.parse(ev.data);
        refreshPanels(detail);
      } catch (_e) {
        refreshPanels(null);
      }
    });
    es.addEventListener("scanCompleted", function (ev) {
      try {
        var detail = JSON.parse(ev.data);
        refreshPanels(detail);
      } catch (_e) {
        refreshPanels(null);
      }
    });
  }

  document.addEventListener("htmx:beforeSwap", function (evt) {
    if (evt.detail.xhr && evt.detail.xhr.status === 400) {
      evt.detail.shouldSwap = true;
      evt.detail.isError = false;
    }
  });

  document.addEventListener("click", function (evt) {
    var target = evt.target;
    if (!target) return;

    if (target.id === "tab-mode-single" && tabSingle && tabBatch) {
      tabSingle.classList.add("active");
      tabBatch.classList.remove("active");
    } else if (target.id === "tab-mode-batch" && tabSingle && tabBatch) {
      tabBatch.classList.add("active");
      tabSingle.classList.remove("active");
    }

    var curlBtn = target.closest ? target.closest("button[data-curl]") : null;
    if (curlBtn) {
      var cmd = curlBtn.getAttribute("data-curl") || "";
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(cmd).then(function () {
          var prev = curlBtn.textContent;
          curlBtn.textContent = "[COPIED]";
          setTimeout(function () {
            curlBtn.textContent = prev;
          }, 1400);
        });
      }
    }
  });

  initEventSource();
})();
