package main

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type sseMsg struct {
	Event string
	Data  string
}

type SSEHub struct {
	mu      sync.Mutex
	clients map[chan sseMsg]struct{}
	history []string
}

func NewSSEHub() *SSEHub {
	return &SSEHub{
		clients: make(map[chan sseMsg]struct{}),
		history: make([]string, 0, 128),
	}
}

func (h *SSEHub) Subscribe() (chan sseMsg, []string) {
	ch := make(chan sseMsg, 64)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	histCopy := make([]string, len(h.history))
	copy(histCopy, h.history)
	h.mu.Unlock()
	return ch, histCopy
}

func (h *SSEHub) Unsubscribe(ch chan sseMsg) {
	h.mu.Lock()
	delete(h.clients, ch)
	close(ch)
	h.mu.Unlock()
}

func (h *SSEHub) BroadcastLog(line string) {
	ts := time.Now().UTC().Format("15:04:05")
	cls := "val-muted"
	if strings.Contains(line, "[OK]") || strings.Contains(line, "[EXPORT]") || strings.Contains(line, "[AUDIT_LOCK]") {
		cls = "val-pos"
	} else if strings.Contains(line, "[WARN") {
		cls = "val-warn"
	} else if strings.Contains(line, "[ERR") {
		cls = "val-neg"
	} else if strings.Contains(line, "[SPIDER]") || strings.Contains(line, "[AST") || strings.Contains(line, "[PY-AST]") {
		cls = "val-primary"
	}
	htmlLine := fmt.Sprintf(`<div class="sse-line"><span class="val-muted">&gt; [%s]</span> <span class="%s">%s</span></div>`, ts, cls, html.EscapeString(line))

	h.mu.Lock()
	if len(h.history) >= 120 {
		h.history = h.history[1:]
	}
	h.history = append(h.history, htmlLine)
	for ch := range h.clients {
		select {
		case ch <- sseMsg{Event: "log", Data: htmlLine}:
		default:
		}
	}
	h.mu.Unlock()
}

func (h *SSEHub) BroadcastEvent(eventName string, jsonPayload string) {
	h.mu.Lock()
	for ch := range h.clients {
		select {
		case ch <- sseMsg{Event: eventName, Data: jsonPayload}:
		default:
		}
	}
	h.mu.Unlock()
}

type dashboardState struct {
	DorkCount     int64  `json:"dork_count"`
	ChainCount    int64  `json:"chain_count"`
	LatestScanID  int64  `json:"latest_scan_id"`
	LatestBatchID string `json:"latest_batch_id"`
	LatestTarget  string `json:"latest_target"`
	Targets       int64  `json:"targets"`
	DorksRun      int64  `json:"dorks_run"`
	VerifiedTP    int64  `json:"verified_tp"`
	FPDropped     int64  `json:"fp_dropped"`
	MaxRisk       int64  `json:"max_risk"`
}

func fetchDashboardState(paths AppPaths) dashboardState {
	var state dashboardState
	spiderBin := resolveSpiderBin(paths)
	out, _, err := runSubprocess(
		nopCtx(),
		8*time.Second,
		paths,
		spiderBin,
		"--latest-state-json",
		"--db", paths.DBPath,
	)
	if err == nil {
		_ = json.Unmarshal(bytes.TrimSpace(out), &state)
	}
	return state
}

func registerRoutes(mux *http.ServeMux, paths AppPaths, hub *SSEHub) {
	staticDir := filepath.Join(paths.WebDir, "static")
	fileSrv := http.FileServer(http.Dir(staticDir))
	mux.Handle("/static/", http.StripPrefix("/static/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/") {
			http.NotFound(w, r)
			return
		}
		fileSrv.ServeHTTP(w, r)
	})))

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		handleIndex(w, r, paths)
	})

	mux.HandleFunc("/ui/input-mode", func(w http.ResponseWriter, r *http.Request) {
		handleInputMode(w, r, paths)
	})

	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		handleStartScan(w, r, paths, hub)
	})

	mux.HandleFunc("/api/stream-logs-sse", func(w http.ResponseWriter, r *http.Request) {
		handleSSELogs(w, r, hub)
	})

	mux.HandleFunc("/panels/svg-telemetry", func(w http.ResponseWriter, r *http.Request) {
		handleSVGTelemetry(w, r, paths)
	})

	mux.HandleFunc("/panels/findings", func(w http.ResponseWriter, r *http.Request) {
		handleFindingsPanel(w, r, paths)
	})

	mux.HandleFunc("/telemetry/status", func(w http.ResponseWriter, r *http.Request) {
		handleTelemetryStatus(w, r, paths)
	})

	mux.HandleFunc("/api/backup", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleBackupBadge(w, r, paths)
	})

	mux.HandleFunc("/api/export/md/", func(w http.ResponseWriter, r *http.Request) {
		handleExportArtifact(w, r, paths, "md")
	})

	mux.HandleFunc("/api/export/docx/", func(w http.ResponseWriter, r *http.Request) {
		handleExportArtifact(w, r, paths, "docx")
	})

	mux.HandleFunc("/api/export/batch-zip", func(w http.ResponseWriter, r *http.Request) {
		handleExportBatchZip(w, r, paths)
	})
}

func handleIndex(w http.ResponseWriter, r *http.Request, paths AppPaths) {
	tmplPath := filepath.Join(paths.WebDir, "templates", "index.html")
	partialPath := filepath.Join(paths.WebDir, "templates", "partials", "input_single.html")
	tmpl, err := template.ParseFiles(tmplPath, partialPath)
	if err != nil {
		http.Error(w, "Template load error", http.StatusInternalServerError)
		return
	}

	state := fetchDashboardState(paths)
	statusBarHTML, _, _ := runSubprocess(
		r.Context(),
		5*time.Second,
		paths,
		"/bin/sh",
		filepath.Join(paths.CodeBaseDir, "scripts", "sys_telemetry.sh"),
		paths.DBPath,
	)

	pyBin := resolvePythonBin(paths)
	svgArgs := []string{"-m", "py_engine.cli", "--svg", "--db", paths.DBPath}
	if state.LatestBatchID != "" {
		svgArgs = append(svgArgs, "--batch-id", state.LatestBatchID)
	}
	svgOut, _, _ := runSubprocess(r.Context(), 8*time.Second, paths, pyBin, svgArgs...)

	var initialFindingsHTML template.HTML
	if state.LatestScanID > 0 {
		out, _, err := runSubprocess(
			r.Context(),
			8*time.Second,
			paths,
			resolveSpiderBin(paths),
			"--render",
			"--scan-id", strconv.FormatInt(state.LatestScanID, 10),
			"--batch-id", state.LatestBatchID,
			"--db", paths.DBPath,
		)
		if err == nil {
			// Extract only inner tbody rows or pass empty if first run
			str := string(out)
			if start := strings.Index(str, `<tbody id="dork-findings-tbody" hx-swap-oob="innerHTML">`); start >= 0 {
				rest := str[start+len(`<tbody id="dork-findings-tbody" hx-swap-oob="innerHTML">`):]
				if end := strings.Index(rest, "</tbody>"); end >= 0 {
					initialFindingsHTML = template.HTML(rest[:end])
				}
			}
		}
	}
	if initialFindingsHTML == "" {
		initialFindingsHTML = template.HTML(`<tr><td colspan="5" class="val-muted" style="text-align:center;padding:24px;">[READY // SUBMIT TARGET URL(S) TO AUDIT AGAINST 295 DORK AST RULES]</td></tr>`)
	}

	data := struct {
		State           dashboardState
		StatusBarHTML   template.HTML
		SVGHTML         template.HTML
		InitialRowsHTML template.HTML
		RiskClass       string
	}{
		State:           state,
		StatusBarHTML:   template.HTML(statusBarHTML),
		SVGHTML:         template.HTML(svgOut),
		InitialRowsHTML: initialFindingsHTML,
		RiskClass:       riskClassFor(state.MaxRisk),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, "index.html", data); err != nil {
		http.Error(w, "Template execution error", http.StatusInternalServerError)
	}
}

func riskClassFor(score int64) string {
	if score >= 70 {
		return "val-neg"
	}
	if score >= 40 {
		return "val-warn"
	}
	return "val-pos"
}

func handleInputMode(w http.ResponseWriter, r *http.Request, paths AppPaths) {
	mode := r.URL.Query().Get("mode")
	fileName := "input_single.html"
	if mode == "batch" {
		fileName = "input_batch.html"
	}
	p, err := resolveSandboxedPath(filepath.Join(paths.WebDir, "templates", "partials"), fileName)
	if err != nil {
		http.Error(w, "Invalid mode", http.StatusBadRequest)
		return
	}
	content, err := os.ReadFile(p)
	if err != nil {
		http.Error(w, "Partial missing", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(content)
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func handleStartScan(w http.ResponseWriter, r *http.Request, paths AppPaths, hub *SSEHub) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	ct := r.Header.Get("Content-Type")
	var rawTargets string
	if strings.Contains(ct, "multipart/form-data") {
		if err := r.ParseMultipartForm(2 << 20); err != nil {
			writeScanErr(w, "Multipart payload exceeds 2 MB limit or is malformed")
			return
		}
		rawTargets = r.FormValue("target_urls")
		if file, hdr, err := r.FormFile("src_list_file"); err == nil {
			defer file.Close()
			_ = sanitizeFilename(hdr.Filename, "targets.csv")
			limited := io.LimitReader(file, 2<<20)
			data, _ := io.ReadAll(limited)
			if len(data) > 0 {
				if rawTargets != "" {
					rawTargets += "\n"
				}
				rawTargets += string(data)
			}
		}
	} else {
		if err := r.ParseForm(); err != nil {
			writeScanErr(w, "Malformed form submission")
			return
		}
		rawTargets = r.FormValue("target_urls")
	}

	stealthMode := r.FormValue("stealth_mode") == "on" || r.FormValue("stealth_mode") == "true" || r.FormValue("stealth_mode") == "1"
	// Default checkbox semantics: when hidden field stealth_present is sent and stealth_mode is omitted, stealth is off
	if r.FormValue("stealth_present") == "" && r.FormValue("stealth_mode") == "" {
		stealthMode = true
	}
	shadowMode := r.FormValue("shadow_mode") == "on" || r.FormValue("shadow_mode") == "true"
	allowLocal := r.FormValue("local_staging") == "on" || r.FormValue("local_staging") == "true"
	engagementID := sanitizeHeaderToken(r.FormValue("engagement_id"))

	targets, err := parseTargetInput(rawTargets, allowLocal)
	if err != nil {
		writeScanErr(w, err.Error())
		return
	}

	batchID := fmt.Sprintf("ADK-%s-%s", time.Now().UTC().Format("20060102-150405"), randomHex(3))
	cfg := ScanRequestConfig{
		BatchID:           batchID,
		Targets:           targets,
		StealthMode:       stealthMode,
		ShadowMode:        shadowMode,
		AllowLocalStaging: allowLocal,
		EngagementID:      engagementID,
	}

	go executeScanPipeline(paths, hub, cfg)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("HX-Trigger", "scanStarted")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(
		w,
		`<div id="scan-status-banner" class="panel-status val-warn">[PIPELINE RUNNING // BATCH %s // %d TARGET(S) QUEUED]</div>`,
		html.EscapeString(batchID),
		len(targets),
	)
}

func writeScanErr(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusBadRequest)
	fmt.Fprintf(
		w,
		`<div id="scan-status-banner" class="panel-status val-neg">[ERR_HALT: %s]</div>`,
		html.EscapeString(msg),
	)
}

func handleSSELogs(w http.ResponseWriter, r *http.Request, hub *SSEHub) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch, history := hub.Subscribe()
	defer hub.Unsubscribe(ch)

	for _, line := range history {
		fmt.Fprintf(w, "event: log\ndata: %s\n\n", line)
	}
	fmt.Fprintf(w, "event: connected\ndata: <div class=\"sse-line val-pos\">&gt; [SSE CONNECTED // LOOPBACK 127.0.0.1]</div>\n\n")
	flusher.Flush()

	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, open := <-ch:
			if !open {
				return
			}
			cleanData := strings.ReplaceAll(msg.Data, "\n", " ")
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.Event, cleanData)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}

func handleSVGTelemetry(w http.ResponseWriter, r *http.Request, paths AppPaths) {
	scanID := r.URL.Query().Get("scan_id")
	batchID := r.URL.Query().Get("batch_id")
	args := []string{"-m", "py_engine.cli", "--svg", "--db", paths.DBPath}
	if scanID != "" {
		if id, err := strconv.ParseInt(scanID, 10, 64); err == nil && id > 0 {
			args = append(args, "--scan-id", strconv.FormatInt(id, 10))
		}
	}
	if batchID != "" {
		args = append(args, "--batch-id", sanitizeHeaderToken(batchID))
	}

	out, _, err := runSubprocess(r.Context(), 10*time.Second, paths, resolvePythonBin(paths), args...)
	if err != nil {
		http.Error(w, `<div class="val-neg">[SVG TELEMETRY UNAVAILABLE]</div>`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(out)
}

func handleFindingsPanel(w http.ResponseWriter, r *http.Request, paths AppPaths) {
	scanIDStr := r.URL.Query().Get("scan_id")
	batchID := sanitizeHeaderToken(r.URL.Query().Get("batch_id"))
	state := fetchDashboardState(paths)
	if scanIDStr == "" && state.LatestScanID > 0 {
		scanIDStr = strconv.FormatInt(state.LatestScanID, 10)
	}
	if batchID == "" {
		batchID = state.LatestBatchID
	}
	sid, err := strconv.ParseInt(scanIDStr, 10, 64)
	if err != nil || sid <= 0 {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<div id="scan-status-banner" class="panel-status val-muted">[NO SCANS IN LEDGER]</div>`))
		return
	}

	args := []string{"--render", "--scan-id", strconv.FormatInt(sid, 10), "--db", paths.DBPath}
	if batchID != "" {
		args = append(args, "--batch-id", batchID)
	}
	out, _, err := runSubprocess(r.Context(), 8*time.Second, paths, resolveSpiderBin(paths), args...)
	if err != nil {
		http.Error(w, `<div class="val-neg">[FINDINGS RENDER FAULT]</div>`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(out)
}

func handleTelemetryStatus(w http.ResponseWriter, r *http.Request, paths AppPaths) {
	out, _, err := runSubprocess(
		r.Context(),
		5*time.Second,
		paths,
		"/bin/sh",
		filepath.Join(paths.CodeBaseDir, "scripts", "sys_telemetry.sh"),
		paths.DBPath,
	)
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(`<span class="val-neg">[TELEMETRY OFFLINE]</span>`))
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(out)
}

func handleBackupBadge(w http.ResponseWriter, r *http.Request, paths AppPaths) {
	out, _, err := runSubprocess(
		r.Context(),
		15*time.Second,
		paths,
		"/bin/sh",
		filepath.Join(paths.CodeBaseDir, "scripts", "backup_and_sign.sh"),
		paths.DBPath,
		paths.BackupDir,
	)
	if err != nil {
		http.Error(w, `<span class="val-neg">[BACKUP_FAULT]</span>`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(out)
}

func handleExportArtifact(w http.ResponseWriter, r *http.Request, paths AppPaths, ext string) {
	prefix := fmt.Sprintf("/api/export/%s/", ext)
	idStr := strings.TrimPrefix(r.URL.Path, prefix)
	idStr = strings.TrimSpace(idStr)
	var scanID int64
	if idStr == "latest" || idStr == "" {
		scanID = fetchDashboardState(paths).LatestScanID
	} else {
		var err error
		scanID, err = strconv.ParseInt(idStr, 10, 64)
		if err != nil || scanID <= 0 {
			http.Error(w, "Invalid scan_id", http.StatusBadRequest)
			return
		}
	}
	if scanID <= 0 {
		http.Error(w, "No completed scan available to export", http.StatusNotFound)
		return
	}

	var filename string
	var contentType string
	var cliFlag string
	if ext == "md" {
		filename = fmt.Sprintf("autodorker_triage_scan_%d.md", scanID)
		contentType = "text/markdown; charset=utf-8"
		cliFlag = "--export-md"
	} else {
		filename = fmt.Sprintf("AutoDorker_Enterprise_Report_%d.docx", scanID)
		contentType = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
		cliFlag = "--export-docx"
	}
	filename = sanitizeFilename(filename, fmt.Sprintf("report_%d.%s", scanID, ext))

	// Look inside Output/Targ* first
	var artifactPath string
	entries, _ := os.ReadDir(paths.OutputDir)
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Targ") {
			cand, err := resolveSandboxedPath(paths.OutputDir, entry.Name(), filename)
			if err == nil {
				if _, statErr := os.Stat(cand); statErr == nil {
					artifactPath = cand
					break
				}
			}
		}
	}

	if artifactPath == "" {
		onDemandDir, err := resolveSandboxedPath(paths.OutputDir, "on_demand")
		if err != nil {
			http.Error(w, "Output sandbox error", http.StatusInternalServerError)
			return
		}
		_ = os.MkdirAll(onDemandDir, 0750)
		dest, err := resolveSandboxedPath(onDemandDir, filename)
		if err != nil {
			http.Error(w, "Output sandbox error", http.StatusInternalServerError)
			return
		}
		_, stderr, err := runSubprocess(
			r.Context(),
			25*time.Second,
			paths,
			resolvePythonBin(paths),
			"-m", "py_engine.cli",
			cliFlag,
			"--scan-id", strconv.FormatInt(scanID, 10),
			"--out", dest,
			"--db", paths.DBPath,
		)
		if err != nil {
			http.Error(w, fmt.Sprintf("Export generation failed: %s", string(stderr)), http.StatusInternalServerError)
			return
		}
		artifactPath = dest
	}

	data, err := os.ReadFile(artifactPath)
	if err != nil {
		http.Error(w, "Artifact read error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	_, _ = w.Write(data)
}

func handleExportBatchZip(w http.ResponseWriter, r *http.Request, paths AppPaths) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	added := 0

	absOut, err := filepath.Abs(paths.OutputDir)
	if err == nil {
		_ = filepath.WalkDir(absOut, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil || d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if d.IsDir() {
				return nil
			}
			rel, relErr := filepath.Rel(absOut, path)
			if relErr != nil || strings.HasPrefix(rel, "..") {
				return nil
			}
			if !strings.HasPrefix(rel, "Targ") {
				return nil
			}
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return nil
			}
			fWriter, zErr := zw.Create(filepath.ToSlash(rel))
			if zErr != nil {
				return nil
			}
			_, _ = fWriter.Write(content)
			added++
			return nil
		})
	}
	_ = zw.Close()

	if added == 0 {
		http.Error(w, "No per-target Output/Targ* artifacts found yet; run a scan first.", http.StatusNotFound)
		return
	}

	zipName := fmt.Sprintf("AutoDorker_Batch_Audit_%s.zip", time.Now().UTC().Format("20060102_150405"))
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, zipName))
	_, _ = w.Write(buf.Bytes())
}

func nopCtx() interface {
	Deadline() (time.Time, bool)
	Done() <-chan struct{}
	Err() error
	Value(any) any
} {
	return timeCtx{}
}

type timeCtx struct{}

func (timeCtx) Deadline() (time.Time, bool) { return time.Time{}, false }
func (timeCtx) Done() <-chan struct{}       { return nil }
func (timeCtx) Err() error                  { return nil }
func (timeCtx) Value(any) any               { return nil }
