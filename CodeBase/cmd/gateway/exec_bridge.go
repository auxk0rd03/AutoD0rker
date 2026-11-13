package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type AppPaths struct {
	CodeBaseDir string
	DBPath      string
	OutputDir   string
	BackupDir   string
	DorkSetCSV  string
	WebDir      string
}

func resolveAppPaths() AppPaths {
	cwd, err := os.Getwd()
	if err != nil {
		cwd = "."
	}
	// If launched from cmd/gateway, walk up to CodeBase
	if _, err := os.Stat(filepath.Join(cwd, "web", "templates", "index.html")); err != nil {
		parent := filepath.Dir(filepath.Dir(cwd))
		if _, err2 := os.Stat(filepath.Join(parent, "web", "templates", "index.html")); err2 == nil {
			cwd = parent
		}
	}

	dbPath := os.Getenv("AUTODORKER_DB_PATH")
	if dbPath == "" {
		dbPath = filepath.Join(cwd, "data", "autodorker_state.db")
	}
	outDir := os.Getenv("AUTODORKER_OUTPUT_DIR")
	if outDir == "" {
		outDir = filepath.Join(cwd, "data", "Output")
	}
	backupDir := os.Getenv("AUTODORKER_BACKUP_DIR")
	if backupDir == "" {
		backupDir = filepath.Join(cwd, "data", "backups")
	}
	dorkCSV := os.Getenv("AUTODORKER_DORKSET_PATH")
	if dorkCSV == "" {
		dorkCSV = filepath.Clean(filepath.Join(cwd, "..", "Docs", "DorkSet.csv"))
	}

	return AppPaths{
		CodeBaseDir: cwd,
		DBPath:      dbPath,
		OutputDir:   outDir,
		BackupDir:   backupDir,
		DorkSetCSV:  dorkCSV,
		WebDir:      filepath.Join(cwd, "web"),
	}
}

func scrubbedEnv(dbPath string) []string {
	pathVal := os.Getenv("PATH")
	if pathVal == "" {
		pathVal = "/usr/local/bin:/usr/bin:/bin"
	}
	tmpDir := os.TempDir()
	env := []string{
		"PATH=" + pathVal,
		"HOME=" + tmpDir,
		"TMPDIR=" + tmpDir,
		"LANG=C.UTF-8",
		"LC_ALL=C.UTF-8",
		"AUTODORKER_DB_PATH=" + dbPath,
	}
	for _, key := range []string{
		"SystemRoot",
		"USERPROFILE",
		"LOCALAPPDATA",
		"HTTP_PROXY",
		"HTTPS_PROXY",
		"ALL_PROXY",
		"NO_PROXY",
		"http_proxy",
		"https_proxy",
		"all_proxy",
		"no_proxy",
		"SSL_CERT_FILE",
		"SSL_CERT_DIR",
		"REQUESTS_CA_BUNDLE",
		"CURL_CA_BUNDLE",
	} {
		if val := os.Getenv(key); val != "" {
			env = append(env, key+"="+val)
		}
	}
	return env
}

func resolveSpiderBin(paths AppPaths) string {
	name := "dork_spider"
	if runtime.GOOS == "windows" {
		name = "dork_spider.exe"
	}
	return filepath.Join(paths.CodeBaseDir, "bin", name)
}

func resolvePythonBin(paths AppPaths) string {
	venvUnix := filepath.Join(paths.CodeBaseDir, ".venv", "bin", "python")
	if _, err := os.Stat(venvUnix); err == nil {
		return venvUnix
	}
	venvWin := filepath.Join(paths.CodeBaseDir, ".venv", "Scripts", "python.exe")
	if _, err := os.Stat(venvWin); err == nil {
		return venvWin
	}
	if _, err := exec.LookPath("python3"); err == nil {
		return "python3"
	}
	return "python"
}

func runTelemetryStatus(ctx context.Context, paths AppPaths) ([]byte, error) {
	if runtime.GOOS != "windows" {
		shScript := filepath.Join(paths.CodeBaseDir, "scripts", "sys_telemetry.sh")
		if _, statErr := os.Stat(shScript); statErr == nil {
			out, _, err := runSubprocess(ctx, 5*time.Second, paths, "/bin/sh", shScript, paths.DBPath)
			if err == nil {
				return out, nil
			}
		}
	}
	out, stderr, err := runSubprocess(
		ctx,
		8*time.Second,
		paths,
		resolvePythonBin(paths),
		"-m", "py_engine.cli",
		"--telemetry-status",
		"--db", paths.DBPath,
	)
	if err != nil && len(out) == 0 {
		return stderr, err
	}
	return out, err
}

func runBackupAndSign(ctx context.Context, paths AppPaths) ([]byte, error) {
	if runtime.GOOS != "windows" {
		shScript := filepath.Join(paths.CodeBaseDir, "scripts", "backup_and_sign.sh")
		if _, statErr := os.Stat(shScript); statErr == nil {
			out, _, err := runSubprocess(ctx, 15*time.Second, paths, "/bin/sh", shScript, paths.DBPath, paths.BackupDir)
			if err == nil {
				return out, nil
			}
		}
	}
	out, stderr, err := runSubprocess(
		ctx,
		15*time.Second,
		paths,
		resolvePythonBin(paths),
		"-m", "py_engine.cli",
		"--backup-sign",
		"--db", paths.DBPath,
		"--backup-dir", paths.BackupDir,
	)
	if err != nil && len(out) == 0 {
		return stderr, err
	}
	return out, err
}

func runSubprocess(ctx context.Context, timeout time.Duration, paths AppPaths, bin string, args ...string) ([]byte, []byte, error) {
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, bin, args...)
	cmd.Dir = paths.CodeBaseDir
	cmd.Env = scrubbedEnv(paths.DBPath)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func runSubprocessStreamingStderr(
	ctx context.Context,
	timeout time.Duration,
	paths AppPaths,
	hub *SSEHub,
	bin string,
	args ...string,
) ([]byte, error) {
	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(execCtx, bin, args...)
	cmd.Dir = paths.CodeBaseDir
	cmd.Env = scrubbedEnv(paths.DBPath)

	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Start(); err != nil {
		return nil, err
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		scanner := bufio.NewScanner(stderrPipe)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" && hub != nil {
				hub.BroadcastLog(line)
			}
		}
	}()

	waitErr := cmd.Wait()
	wg.Wait()
	if waitErr != nil && waitErr != io.EOF {
		return stdout.Bytes(), fmt.Errorf("subprocess %s failed: %w", bin, waitErr)
	}
	return stdout.Bytes(), nil
}

type ScanRequestConfig struct {
	BatchID           string
	Targets           []string
	StealthMode       bool
	ShadowMode        bool
	AllowLocalStaging bool
	EngagementID      string
	MaxDepth          int
	JitterMinMs       int64
	JitterMaxMs       int64
	ProxyURL          string
	CategoriesCSV     string
	Wordlist          []string
	SPAHydrate        bool
	Workers           int
}

type BatchState struct {
	BatchID   string
	Total     int
	Completed atomic.Int32
	Failed    atomic.Int32
	Cancelled atomic.Bool
	cancel    context.CancelFunc
}

type BatchManager struct {
	mu      sync.Mutex
	batches map[string]*BatchState
}

func NewBatchManager() *BatchManager {
	return &BatchManager{
		batches: make(map[string]*BatchState),
	}
}

func (m *BatchManager) Register(batchID string, total int) (context.Context, *BatchState) {
	ctx, cancel := context.WithCancel(context.Background())
	st := &BatchState{
		BatchID: batchID,
		Total:   total,
		cancel:  cancel,
	}
	m.mu.Lock()
	m.batches[batchID] = st
	m.mu.Unlock()
	return ctx, st
}

func (m *BatchManager) Cancel(batchID string) bool {
	m.mu.Lock()
	st, ok := m.batches[batchID]
	m.mu.Unlock()
	if !ok {
		return false
	}
	st.Cancelled.Store(true)
	st.cancel()
	return true
}

func (m *BatchManager) Complete(batchID string) {
	m.mu.Lock()
	if st, ok := m.batches[batchID]; ok {
		st.cancel()
		delete(m.batches, batchID)
	}
	m.mu.Unlock()
}

type rustScanJSON struct {
	ScanID           int64  `json:"scan_id"`
	BatchID          string `json:"batch_id"`
	TargetURL        string `json:"target_url"`
	PagesCrawled     int64  `json:"pages_crawled"`
	DorksEvaluated   int64  `json:"dorks_evaluated"`
	VerifiedCount    int64  `json:"verified_count"`
	AstFPDropped     int64  `json:"ast_fp_dropped"`
	Soft404FPDropped int64  `json:"soft404_fp_dropped"`
	EntropyFPDropped int64  `json:"entropy_fp_dropped"`
	RiskScore        int64  `json:"risk_score"`
	WafVendor        string `json:"waf_vendor"`
	WafTripped       bool   `json:"waf_tripped"`
}

func purgeOldTargOutputs(outputDir string) {
	_ = os.MkdirAll(outputDir, 0750)
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "Targ") {
			safePath, err := resolveSandboxedPath(outputDir, entry.Name())
			if err == nil {
				_ = os.RemoveAll(safePath)
			}
		}
	}
}

func executeScanPipeline(paths AppPaths, hub *SSEHub, mgr *BatchManager, cfg ScanRequestConfig) {
	workers := cfg.Workers
	if workers <= 0 {
		workers = 2
	}
	if workers > 4 {
		workers = 4
	}
	if workers > len(cfg.Targets) {
		workers = len(cfg.Targets)
	}
	if workers < 1 {
		workers = 1
	}

	depth := cfg.MaxDepth
	if depth <= 0 {
		depth = 2
	} else if depth > 6 {
		depth = 6
	}
	jitterMin := cfg.JitterMinMs
	if jitterMin < 0 {
		jitterMin = 0
	} else if jitterMin > 30000 {
		jitterMin = 30000
	}
	jitterMax := cfg.JitterMaxMs
	if jitterMax <= 0 {
		jitterMax = 750
	}
	if jitterMax < jitterMin {
		jitterMax = jitterMin
	}

	batchCtx, batchState := mgr.Register(cfg.BatchID, len(cfg.Targets))
	defer mgr.Complete(cfg.BatchID)

	hub.BroadcastLog(fmt.Sprintf(
		"[OK] Provisioning batch %s (%d target(s) // GUI=127.0.0.1 // Egress=INTERNET // Stealth=%v // Depth=%d // Workers=%d // SPA=%v)",
		cfg.BatchID, len(cfg.Targets), cfg.StealthMode, depth, workers, cfg.SPAHydrate,
	))
	purgeOldTargOutputs(paths.OutputDir)

	spiderBin := resolveSpiderBin(paths)
	pyBin := resolvePythonBin(paths)

	var scanMu sync.Mutex
	var maxScanID int64

	type scanJob struct {
		idx    int
		target string
	}
	jobs := make(chan scanJob, len(cfg.Targets))
	for i, t := range cfg.Targets {
		jobs <- scanJob{idx: i, target: t}
	}
	close(jobs)

	emitProgress := func() {
		hub.BroadcastEvent("batchProgress", fmt.Sprintf(
			`{"batch_id":%q,"completed":%d,"total":%d,"failed":%d,"cancelled":%v}`,
			cfg.BatchID,
			batchState.Completed.Load(),
			batchState.Total,
			batchState.Failed.Load(),
			batchState.Cancelled.Load(),
		))
	}
	emitProgress()

	runOneTarget := func(job scanJob) {
		if batchCtx.Err() != nil {
			return
		}
		targIndex := job.idx + 1
		targRel := fmt.Sprintf("Output/Targ%03d", targIndex)
		targOutDir, err := resolveSandboxedPath(paths.OutputDir, fmt.Sprintf("Targ%03d", targIndex))
		if err != nil {
			hub.BroadcastLog(fmt.Sprintf("[ERR_HALT] Path sandbox rejected %s: %v", targRel, err))
			batchState.Failed.Add(1)
			batchState.Completed.Add(1)
			emitProgress()
			return
		}
		_ = os.MkdirAll(targOutDir, 0750)

		harvestDir, err := os.MkdirTemp("", "adk_harvest_")
		if err != nil {
			hub.BroadcastLog(fmt.Sprintf("[ERR_HALT] Temp harvest allocation failed: %v", err))
			batchState.Failed.Add(1)
			batchState.Completed.Add(1)
			emitProgress()
			return
		}
		defer func() {
			_ = os.RemoveAll(harvestDir)
		}()
		_ = os.Chmod(harvestDir, 0700)

		hub.BroadcastLog(fmt.Sprintf("[TARGET %d/%d] Auditing %s -> %s", targIndex, len(cfg.Targets), job.target, targRel))

		var spaSeedPath string
		if cfg.SPAHydrate && batchCtx.Err() == nil {
			loopbackProxy, stopProxy, pErr := startSSRFSafeSPAProxy(cfg.AllowLocalStaging)
			if pErr == nil {
				spaSeedCandidate := filepath.Join(harvestDir, "spa_seed.json")
				spaOut, _, spaErr := runSubprocess(
					batchCtx,
					20*time.Second,
					paths,
					pyBin,
					"-m", "py_engine.cli",
					"--hydrate-spa",
					"--target", job.target,
					"--proxy", loopbackProxy,
					"--out", spaSeedCandidate,
				)
				stopProxy()
				if spaErr == nil {
					if _, statErr := os.Stat(spaSeedCandidate); statErr == nil {
						spaSeedPath = spaSeedCandidate
					}
					hub.BroadcastLog(fmt.Sprintf("[SPA] Stage-0 hydration: %s", strings.TrimSpace(string(spaOut))))
				} else {
					hub.BroadcastLog(fmt.Sprintf("[WARN] Stage-0 SPA hydration skipped: %v", spaErr))
				}
			} else {
				hub.BroadcastLog(fmt.Sprintf("[WARN] SPA SSRF proxy failed to bind: %v", pErr))
			}
		}

		if batchCtx.Err() != nil {
			return
		}

		args := []string{
			"--scan",
			"--target", job.target,
			"--batch-id", cfg.BatchID,
			"--batch-index", strconv.Itoa(targIndex),
			"--depth", strconv.Itoa(depth),
			"--jitter-min-ms", strconv.FormatInt(jitterMin, 10),
			"--jitter-max-ms", strconv.FormatInt(jitterMax, 10),
			"--db", paths.DBPath,
			"--out-rel", targRel,
			"--harvest-dir", harvestDir,
			"--keep-harvest",
			"--json",
		}
		if !cfg.StealthMode {
			args = append(args, "--active")
		}
		if cfg.ShadowMode {
			args = append(args, "--shadow")
		}
		if cfg.AllowLocalStaging {
			args = append(args, "--allow-local")
		}
		if cfg.EngagementID != "" {
			args = append(args, "--engagement-id", cfg.EngagementID)
		}
		if cfg.ProxyURL != "" {
			args = append(args, "--proxy", cfg.ProxyURL)
		}
		if cfg.CategoriesCSV != "" {
			args = append(args, "--categories", cfg.CategoriesCSV)
		}
		if len(cfg.Wordlist) > 0 {
			args = append(args, "--wordlist", strings.Join(cfg.Wordlist, ","))
		}
		if spaSeedPath != "" {
			args = append(args, "--spa-seed", spaSeedPath)
		}

		rawOut, err := runSubprocessStreamingStderr(batchCtx, 180*time.Second, paths, hub, spiderBin, args...)
		if err != nil {
			if batchCtx.Err() != nil {
				hub.BroadcastLog(fmt.Sprintf("[WARN] Scan cancelled for %s", job.target))
			} else {
				hub.BroadcastLog(fmt.Sprintf("[ERR_HALT] Rust spider failed for %s: %v", job.target, err))
			}
			batchState.Failed.Add(1)
			batchState.Completed.Add(1)
			emitProgress()
			return
		}

		var res rustScanJSON
		if jErr := json.Unmarshal(bytes.TrimSpace(rawOut), &res); jErr != nil {
			hub.BroadcastLog(fmt.Sprintf("[ERR_HALT] Failed parsing Rust telemetry JSON: %v", jErr))
			batchState.Failed.Add(1)
			batchState.Completed.Add(1)
			emitProgress()
			return
		}

		scanMu.Lock()
		if res.ScanID > maxScanID {
			maxScanID = res.ScanID
		}
		scanMu.Unlock()

		// Stage-2 Python AST verification (esprima, pyyaml, lxml) before Zero-Footprint harvest cleanup
		astOut, astErrOut, astErr := runSubprocess(
			batchCtx,
			30*time.Second,
			paths,
			pyBin,
			"-m", "py_engine.cli",
			"--verify-ast",
			"--scan-id", strconv.FormatInt(res.ScanID, 10),
			"--harvest-dir", harvestDir,
			"--db", paths.DBPath,
		)
		if astErr == nil {
			hub.BroadcastLog(fmt.Sprintf("[PY-AST] Stage-2 deep AST verification: %s", strings.TrimSpace(string(astOut))))
		} else {
			hub.BroadcastLog(fmt.Sprintf("[WARN] Stage-2 Python AST warning: %v %s", astErr, strings.TrimSpace(string(astErrOut))))
		}

		// Zero-Footprint Cleanup
		_ = os.RemoveAll(harvestDir)

		// Generate Enterprise .md, .docx, .sarif, and .jsonl deliverables
		_, expErrOut, expErr := runSubprocess(
			batchCtx,
			35*time.Second,
			paths,
			pyBin,
			"-m", "py_engine.cli",
			"--export-all",
			"--scan-id", strconv.FormatInt(res.ScanID, 10),
			"--out-dir", targOutDir,
			"--db", paths.DBPath,
		)
		if expErr == nil {
			hub.BroadcastLog(fmt.Sprintf("[EXPORT] Generated .MD, .DOCX, .SARIF, .JSONL deliverables in %s", targRel))
		} else {
			hub.BroadcastLog(fmt.Sprintf("[WARN] Report export warning: %v %s", expErr, strings.TrimSpace(string(expErrOut))))
		}

		// Atomic SQLite VACUUM INTO hot backup + SHA-256 lock
		if backupOut, bErr := runBackupAndSign(batchCtx, paths); bErr == nil {
			hub.BroadcastLog(fmt.Sprintf("[AUDIT_LOCK] %s", strings.TrimSpace(string(backupOut))))
		}

		batchState.Completed.Add(1)
		emitProgress()
		hub.BroadcastEvent("scanUpdated", fmt.Sprintf(`{"scan_id":%d,"batch_id":%q}`, res.ScanID, cfg.BatchID))
	}

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				if batchCtx.Err() != nil {
					return
				}
				runOneTarget(job)
			}
		}()
	}
	wg.Wait()

	if batchState.Cancelled.Load() {
		hub.BroadcastLog(fmt.Sprintf("[WARN] Batch %s cancelled by operator (%d/%d finished)", cfg.BatchID, batchState.Completed.Load(), batchState.Total))
		hub.BroadcastEvent("scanCancelled", fmt.Sprintf(`{"batch_id":%q,"completed":%d,"total":%d}`, cfg.BatchID, batchState.Completed.Load(), batchState.Total))
	} else if maxScanID > 0 {
		hub.BroadcastLog(fmt.Sprintf("[OK] Pipeline completed for batch %s (latest scan #%d)", cfg.BatchID, maxScanID))
		hub.BroadcastEvent("scanCompleted", fmt.Sprintf(`{"scan_id":%d,"batch_id":%q}`, maxScanID, cfg.BatchID))
	} else {
		hub.BroadcastLog(fmt.Sprintf("[ERR_HALT] Batch %s finished with 0 completed scan sessions", cfg.BatchID))
		hub.BroadcastEvent("scanFailed", fmt.Sprintf(`{"batch_id":%q,"error":"Target scan failed (check DNS/TLS/SSRF logs in telemetry console)"}`, cfg.BatchID))
	}
}
