package main

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	webassets "github.com/auxk0rd03/AutoD0rker/gateway"
)

func buildReleaseTarball(paths AppPaths, outTarGz string) error {
	cleanOut := filepath.Clean(outTarGz)
	if st, err := os.Lstat(cleanOut); err == nil {
		if st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("CWE-377 blocked: output target %s is a symlink", cleanOut)
		}
	}
	if err := os.MkdirAll(filepath.Dir(cleanOut), 0o750); err != nil {
		return err
	}

	tmpPath := fmt.Sprintf("%s.tmp.%d", cleanOut, os.Getpid())
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return err
	}
	success := false
	defer func() {
		_ = f.Close()
		if !success {
			_ = os.Remove(tmpPath)
		}
	}()

	gzw := gzip.NewWriter(f)
	tw := tar.NewWriter(gzw)
	now := time.Now().UTC()
	seen := make(map[string]bool)

	addBytes := func(relPath string, data []byte, mode int64) error {
		archivePath := filepath.ToSlash(filepath.Join("autodorker-release", relPath))
		if seen[archivePath] {
			return nil
		}
		seen[archivePath] = true
		hdr := &tar.Header{
			Name:    archivePath,
			Mode:    mode,
			Size:    int64(len(data)),
			ModTime: now,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err := tw.Write(data)
		return err
	}

	addDiskFile := func(srcPath, relArchive string, mode int64) error {
		st, err := os.Lstat(srcPath)
		if err != nil || !st.Mode().IsRegular() {
			return nil
		}
		in, err := os.Open(srcPath)
		if err != nil {
			return err
		}
		defer in.Close()

		archivePath := filepath.ToSlash(filepath.Join("autodorker-release", relArchive))
		if seen[archivePath] {
			return nil
		}
		seen[archivePath] = true
		hdr := &tar.Header{
			Name:    archivePath,
			Mode:    mode,
			Size:    st.Size(),
			ModTime: st.ModTime(),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		_, err = io.Copy(tw, in)
		return err
	}

	gatewayAdded := false
	for _, cand := range []string{
		filepath.Join(paths.CodeBaseDir, "bin", "gateway"),
		filepath.Join(paths.CodeBaseDir, "bin", "gateway.exe"),
	} {
		if st, err := os.Lstat(cand); err == nil && st.Mode().IsRegular() {
			if err := addDiskFile(cand, filepath.Join("bin", filepath.Base(cand)), 0o750); err != nil {
				return err
			}
			gatewayAdded = true
		}
	}
	if !gatewayAdded {
		if exePath, err := os.Executable(); err == nil {
			gwName := filepath.Join("bin", filepath.Base(exePath))
			if !strings.Contains(filepath.Base(exePath), "gateway") {
				gwName = filepath.Join("bin", "gateway")
			}
			if err := addDiskFile(exePath, gwName, 0o750); err != nil {
				return err
			}
		}
	}
	spiderBin := resolveSpiderBin(paths)
	if spiderBin != "" {
		if err := addDiskFile(spiderBin, filepath.Join("bin", filepath.Base(spiderBin)), 0o750); err != nil {
			return err
		}
	}
	if paths.DorkSetCSV != "" {
		if err := addDiskFile(paths.DorkSetCSV, filepath.Join("Docs", "DorkSet.csv"), 0o640); err != nil {
			return err
		}
	}
	_ = addDiskFile(filepath.Join(paths.CodeBaseDir, "data", "migrations", "001_init_schema.sql"), filepath.Join("data", "migrations", "001_init_schema.sql"), 0o640)
	_ = addDiskFile(filepath.Join(paths.CodeBaseDir, "requirements.txt"), "requirements.txt", 0o640)

	for _, dirRel := range []string{"py_engine", "scripts"} {
		fullDir := filepath.Join(paths.CodeBaseDir, dirRel)
		_ = filepath.WalkDir(fullDir, func(p string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d.IsDir() || d.Type()&os.ModeSymlink != 0 {
				return nil
			}
			if strings.Contains(p, "__pycache__") || strings.HasSuffix(p, ".pyc") {
				return nil
			}
			relSub, err := filepath.Rel(paths.CodeBaseDir, p)
			if err != nil {
				return nil
			}
			mode := int64(0o640)
			if dirRel == "scripts" {
				mode = 0o750
			}
			return addDiskFile(p, relSub, mode)
		})
	}

	if err := fs.WalkDir(webassets.EmbeddedWebFS, "web", func(p string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return nil
		}
		data, err := fs.ReadFile(webassets.EmbeddedWebFS, p)
		if err != nil {
			return err
		}
		return addBytes(p, data, 0o640)
	}); err != nil {
		return err
	}

	readme := "AutoDorker Self-Contained Release Bundle\n" +
		"========================================\n" +
		"Run standalone embedded-UI gateway strictly on localhost (outbound scans traverse the internet):\n" +
		"  ./bin/gateway --embedded-ui --bind 127.0.0.1:8090\n"
	if err := addBytes("README_RELEASE.txt", []byte(readme), 0o644); err != nil {
		return err
	}

	if err := tw.Close(); err != nil {
		return err
	}
	if err := gzw.Close(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, cleanOut); err != nil {
		return err
	}
	success = true
	return nil
}
