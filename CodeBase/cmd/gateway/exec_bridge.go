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
	if sysRoot := os.Getenv("SystemRoot"); sysRoot != "" {
		env = append(env, "SystemRoot="+sysRoot)
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
	return "python3"
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

func executeScanPipeline(paths AppPaths, hub *SSEHub, cfg ScanRequestConfig) {
	hub.BroadcastLog(fmt.Sprintf("[OK] Provisioning batch %s (%d target(s) // Stealth=%v)", cfg.BatchID, len(cfg.Targets), cfg.StealthMode))
	purgeOldTargOutputs(paths.OutputDir)

	spiderBin := resolveSpiderBin(paths)
	pyBin := resolvePythonBin(paths)
	var lastScanID int64

	for idx, target := range cfg.Targets {
		targIndex := idx + 1
		targRel := fmt.Sprintf("Output/Targ%03d", targIndex)
		targOutDir, err := resolveSandboxedPath(paths.OutputDir, fmt.Sprintf("Targ%03d", targIndex))
		if err != nil {
			hub.BroadcastLog(fmt.Sprintf("[ERR_HALT] Path sandbox rejected %s: %v", targRel, err))
			continue
		}
		_ = os.MkdirAll(targOutDir, 0750)

		harvestDir, err := os.MkdirTemp("", "adk_harvest_")
		if err != nil {
			hub.BroadcastLog(fmt.Sprintf("[ERR_HALT] Temp harvest allocation failed: %v", err))
			continue
		}
		_ = os.Chmod(harvestDir, 0700)

		hub.BroadcastLog(fmt.Sprintf("[TARGET %d/%d] Auditing %s -> %s", targIndex, len(cfg.Targets), target, targRel))

		args := []string{
			"--scan",
			"--target", target,
			"--batch-id", cfg.BatchID,
			"--batch-index", strconv.Itoa(targIndex),
			"--depth", "2",
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

		ctx := context.Background()
		rawOut, err := runSubprocessStreamingStderr(ctx, 75*time.Second, paths, hub, spiderBin, args...)
		if err != nil {
			_ = os.RemoveAll(harvestDir)
			hub.BroadcastLog(fmt.Sprintf("[ERR_HALT] Rust spider failed for %s: %v", target, err))
			continue
		}

		var res rustScanJSON
		if jErr := json.Unmarshal(bytes.TrimSpace(rawOut), &res); jErr != nil {
			_ = os.RemoveAll(harvestDir)
			hub.BroadcastLog(fmt.Sprintf("[ERR_HALT] Failed parsing Rust telemetry JSON: %v", jErr))
			continue
		}
		lastScanID = res.ScanID

		// Stage-2 Python AST verification (esprima, pyyaml, lxml) before Zero-Footprint harvest cleanup
		astOut, astErrOut, astErr := runSubprocess(
			ctx,
			25*time.Second,
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

		// Generate Enterprise .md and .docx deliverables
		_, expErrOut, expErr := runSubprocess(
			ctx,
			30*time.Second,
			paths,
			pyBin,
			"-m", "py_engine.cli",
			"--export-all",
			"--scan-id", strconv.FormatInt(res.ScanID, 10),
			"--out-dir", targOutDir,
			"--db", paths.DBPath,
		)
		if expErr == nil {
			hub.BroadcastLog(fmt.Sprintf("[EXPORT] Generated .MD & .DOCX VIDS deliverables in %s", targRel))
		} else {
			hub.BroadcastLog(fmt.Sprintf("[WARN] Report export warning: %v %s", expErr, strings.TrimSpace(string(expErrOut))))
		}

		// Atomic SQLite VACUUM INTO hot backup + SHA-256 lock
		backupOut, _, bErr := runSubprocess(
			ctx,
			15*time.Second,
			paths,
			"/bin/sh",
			filepath.Join(paths.CodeBaseDir, "scripts", "backup_and_sign.sh"),
			paths.DBPath,
			paths.BackupDir,
		)
		if bErr == nil {
			hub.BroadcastLog(fmt.Sprintf("[AUDIT_LOCK] %s", strings.TrimSpace(string(backupOut))))
		}

		// Broadcast UI refresh event so HTMX panels re-render immediately after each target
		hub.BroadcastEvent("scanUpdated", fmt.Sprintf(`{"scan_id":%d,"batch_id":%q}`, res.ScanID, cfg.BatchID))
	}

	if lastScanID > 0 {
		hub.BroadcastLog(fmt.Sprintf("[OK] Pipeline completed for batch %s (latest scan #%d)", cfg.BatchID, lastScanID))
		hub.BroadcastEvent("scanCompleted", fmt.Sprintf(`{"scan_id":%d,"batch_id":%q}`, lastScanID, cfg.BatchID))
	} else {
		hub.BroadcastLog(fmt.Sprintf("[WARN] Batch %s finished with no completed scan sessions", cfg.BatchID))
	}
}
