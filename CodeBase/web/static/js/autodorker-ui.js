(function () {
  "use strict";

  var consoleEl = document.getElementById("sse-console-log");
  var tabSingle = document.getElementById("tab-mode-single");
  var tabBatch = document.getElementById("tab-mode-batch");
  var exportMdBtn = document.getElementById("btn-export-md");
  var exportDocxBtn = document.getElementById("btn-export-docx");
  var exportSarifBtn = document.getElementById("btn-export-sarif");
  var exportJsonlBtn = document.getElementById("btn-export-jsonl");
  var exportBatchZipBtn = document.getElementById("btn-export-batch-zip");
  var historySelect = document.getElementById("select-history-scan");
  var compareSelectA = document.getElementById("select-compare-scan-a");
  var compareSelectB = document.getElementById("select-compare-scan-b");
  var compareBtn = document.getElementById("btn-compare-scans");
  var compareResultEl = document.getElementById("scan-compare-result");
  var progressPanel = document.getElementById("batch-progress-panel");
  var progressLabel = document.getElementById("batch-progress-label");
  var progressFill = document.getElementById("batch-progress-fill");
  var cancelBatchBtn = document.getElementById("btn-cancel-batch");

  var activeBatchId = "";

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

  function updateExportLinks(detail) {
    if (!detail || !detail.scan_id) return;
    var sid = encodeURIComponent(detail.scan_id);
    if (exportMdBtn) exportMdBtn.setAttribute("href", "/api/export/md/" + sid);
    if (exportDocxBtn) exportDocxBtn.setAttribute("href", "/api/export/docx/" + sid);
    if (exportSarifBtn) exportSarifBtn.setAttribute("href", "/api/export/sarif/" + sid);
    if (exportJsonlBtn) exportJsonlBtn.setAttribute("href", "/api/export/jsonl/" + sid);
    if (exportBatchZipBtn && detail.batch_id) {
      exportBatchZipBtn.setAttribute(
        "href",
        "/api/export/batch-zip?batch_id=" + encodeURIComponent(detail.batch_id)
      );
    }
  }

  function refreshPanels(detail) {
    var qs = "";
    if (detail && detail.scan_id) {
      qs = "?scan_id=" + encodeURIComponent(detail.scan_id);
      if (detail.batch_id) {
        qs += "&batch_id=" + encodeURIComponent(detail.batch_id);
      }
      updateExportLinks(detail);
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

  function setStatusBanner(text, clsName) {
    var banner = document.getElementById("scan-status-banner");
    if (!banner) return;
    banner.className = "panel-status " + clsName;
    banner.textContent = text;
  }

  function updateBatchProgress(detail) {
    if (!detail || !progressPanel || !progressLabel || !progressFill) return;
    progressPanel.classList.remove("hidden-panel");
    var completed = Number(detail.completed || 0);
    var total = Number(detail.total || 0);
    var failed = Number(detail.failed || 0);
    var pct = total > 0 ? Math.min(100, Math.round((completed / total) * 100)) : 0;
    progressFill.style.width = pct + "%";
    progressLabel.textContent =
      "[BATCH " +
      (detail.batch_id || "") +
      " // " +
      completed +
      "/" +
      total +
      " TARGETS COMPLETED" +
      (failed > 0 ? " // " + failed + " FAILED" : "") +
      "]";
    if (detail.batch_id && completed < total && !detail.cancelled) {
      activeBatchId = detail.batch_id;
      if (cancelBatchBtn) cancelBatchBtn.disabled = false;
    } else if (completed >= total || detail.cancelled) {
      activeBatchId = "";
      if (cancelBatchBtn) cancelBatchBtn.disabled = true;
    }
  }

  function populateSelectOption(sel, value, label) {
    var opt = document.createElement("option");
    opt.value = value;
    opt.textContent = label;
    sel.appendChild(opt);
  }

  function loadScanHistory(selectedScanId) {
    if (!historySelect) return;
    fetch("/api/scans?limit=40")
      .then(function (r) {
        return r.ok ? r.json() : null;
      })
      .then(function (data) {
        if (!data || !Array.isArray(data.scans)) return;
        var currentVal = selectedScanId || historySelect.value || "";
        historySelect.innerHTML = "";
        populateSelectOption(historySelect, "", "[LATEST SCAN]");
        if (compareSelectA) compareSelectA.innerHTML = "";
        if (compareSelectB) compareSelectB.innerHTML = "";

        data.scans.forEach(function (s, idx) {
          var label =
            "#" +
            s.scan_id +
            " | " +
            s.target_url +
            " (R:" +
            s.surface_risk_score +
            ", TP:" +
            s.verified_count +
            ")";
          var opt = document.createElement("option");
          opt.value = String(s.scan_id);
          opt.setAttribute("data-batch-id", s.batch_id || "");
          opt.textContent = label;
          historySelect.appendChild(opt);

          if (compareSelectA) populateSelectOption(compareSelectA, String(s.scan_id), "#" + s.scan_id + " " + s.target_url);
          if (compareSelectB) populateSelectOption(compareSelectB, String(s.scan_id), "#" + s.scan_id + " " + s.target_url);

          if (idx === 0 && compareSelectB) {
            compareSelectB.value = String(s.scan_id);
          }
          if (idx === 1 && compareSelectA) {
            compareSelectA.value = String(s.scan_id);
          }
        });
        if (currentVal) {
          historySelect.value = currentVal;
        }
      })
      .catch(function () {});
  }

  function renderCompareResult(diff) {
    if (!compareResultEl || !diff) return;
    compareResultEl.classList.remove("hidden-panel");
    compareResultEl.innerHTML = "";

    var hdr = document.createElement("div");
    hdr.className = "compare-summary";
    var delta = Number(diff.risk_delta || 0);
    var deltaSign = delta > 0 ? "+" + delta : String(delta);
    hdr.textContent =
      "[DIFF #" +
      diff.scan_a.scan_id +
      " -> #" +
      diff.scan_b.scan_id +
      " // RISK DELTA: " +
      deltaSign +
      " // NEW: " +
      diff.added_count +
      " // RESOLVED: " +
      diff.resolved_count +
      " // UNCHANGED: " +
      diff.unchanged_count +
      "]";
    hdr.classList.add(delta > 0 ? "val-neg" : delta < 0 ? "val-pos" : "val-muted");
    compareResultEl.appendChild(hdr);

    var addList = Array.isArray(diff.added) ? diff.added : [];
    var resList = Array.isArray(diff.resolved) ? diff.resolved : [];
    var maxItems = 6;
    addList.slice(0, maxItems).forEach(function (f) {
      var line = document.createElement("div");
      line.className = "val-neg compare-item";
      line.textContent = "+ [NEW " + f.severity + "] " + f.category + " @ " + f.matched_endpoint;
      compareResultEl.appendChild(line);
    });
    resList.slice(0, maxItems).forEach(function (f) {
      var line = document.createElement("div");
      line.className = "val-pos compare-item";
      line.textContent = "- [RESOLVED " + f.severity + "] " + f.category + " @ " + f.matched_endpoint;
      compareResultEl.appendChild(line);
    });
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
    es.addEventListener("batchProgress", function (ev) {
      try {
        updateBatchProgress(JSON.parse(ev.data));
      } catch (_e) {}
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
      activeBatchId = "";
      if (cancelBatchBtn) cancelBatchBtn.disabled = true;
      try {
        var detail = JSON.parse(ev.data);
        refreshPanels(detail);
        loadScanHistory(detail.scan_id ? String(detail.scan_id) : "");
      } catch (_e) {
        refreshPanels(null);
        loadScanHistory("");
      }
    });
    es.addEventListener("scanCancelled", function (ev) {
      activeBatchId = "";
      if (cancelBatchBtn) cancelBatchBtn.disabled = true;
      try {
        var detail = JSON.parse(ev.data);
        setStatusBanner(
          "[BATCH " + (detail.batch_id || "") + " CANCELLED // " + (detail.completed || 0) + "/" + (detail.total || 0) + " FINISHED]",
          "val-warn"
        );
        loadScanHistory("");
      } catch (_e) {}
    });
    es.addEventListener("scanFailed", function (ev) {
      activeBatchId = "";
      if (cancelBatchBtn) cancelBatchBtn.disabled = true;
      try {
        var detail = JSON.parse(ev.data);
        setStatusBanner("[ERR_HALT: " + (detail.error || "SCAN FAILED") + "]", "val-neg");
      } catch (_e) {
        setStatusBanner("[ERR_HALT: SCAN FAILED]", "val-neg");
      }
    });
  }

  document.addEventListener("scanStarted", function () {
    var banner = document.getElementById("scan-status-banner");
    if (!banner) return;
    var bid = banner.getAttribute("data-active-batch") || "";
    var total = Number(banner.getAttribute("data-active-total") || "1");
    if (bid) {
      activeBatchId = bid;
      updateBatchProgress({ batch_id: bid, completed: 0, total: total, failed: 0 });
    }
  });

  document.addEventListener("htmx:beforeSwap", function (evt) {
    if (evt.detail.xhr && evt.detail.xhr.status === 400) {
      evt.detail.shouldSwap = true;
      evt.detail.isError = false;
    }
  });

  if (historySelect) {
    historySelect.addEventListener("change", function () {
      var sid = historySelect.value;
      if (!sid) {
        refreshPanels(null);
        return;
      }
      var selectedOpt = historySelect.options[historySelect.selectedIndex];
      var bid = selectedOpt ? selectedOpt.getAttribute("data-batch-id") || "" : "";
      refreshPanels({ scan_id: sid, batch_id: bid });
    });
  }

  if (compareBtn) {
    compareBtn.addEventListener("click", function () {
      var a = compareSelectA ? compareSelectA.value : "";
      var b = compareSelectB ? compareSelectB.value : "";
      if (!a || !b) return;
      fetch("/api/scans/compare?a=" + encodeURIComponent(a) + "&b=" + encodeURIComponent(b))
        .then(function (r) {
          return r.ok ? r.json() : null;
        })
        .then(function (diff) {
          if (diff) renderCompareResult(diff);
        })
        .catch(function () {});
    });
  }

  if (cancelBatchBtn) {
    cancelBatchBtn.addEventListener("click", function () {
      if (!activeBatchId) return;
      cancelBatchBtn.disabled = true;
      fetch("/api/scan/" + encodeURIComponent(activeBatchId) + "/cancel", { method: "POST" }).catch(function () {});
    });
  }

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

    var catLoadBtn = target.closest ? target.closest(".btn-load-cats") : null;
    if (catLoadBtn) {
      var hintEl = document.querySelector(".cat-hint");
      if (hintEl) hintEl.textContent = "Loading DorkSet catalog categories...";
      fetch("/api/dork-categories")
        .then(function (r) {
          return r.ok ? r.json() : null;
        })
        .then(function (data) {
          if (!hintEl || !data || !Array.isArray(data.categories)) return;
          hintEl.innerHTML = "";
          data.categories.forEach(function (c) {
            var chip = document.createElement("button");
            chip.type = "button";
            chip.className = "btn-mini cat-chip";
            chip.setAttribute("data-cat", c.category);
            chip.textContent = c.category + " (" + c.count + ")";
            hintEl.appendChild(chip);
          });
        })
        .catch(function () {});
      return;
    }

    var catChip = target.closest ? target.closest("button.cat-chip") : null;
    if (catChip) {
      var catInput = document.getElementById("opt_categories");
      var catName = catChip.getAttribute("data-cat") || "";
      if (catInput && catName) {
        var existing = catInput.value
          .split(",")
          .map(function (s) {
            return s.trim();
          })
          .filter(Boolean);
        if (existing.indexOf(catName) === -1) {
          existing.push(catName);
          catInput.value = existing.join(", ");
        }
      }
      return;
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

  loadScanHistory("");
  initEventSource();
})();
