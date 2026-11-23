package ghapp

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

// Limits bound what a repository download may consume. Repository content is
// untrusted: the extractor only ever writes regular files under dest.
type Limits struct {
	MaxTotalBytes int64 // compressed + uncompressed budget
	MaxFileBytes  int64 // larger files are skipped (analyzers don't need them)
	MaxFiles      int
}

// DefaultLimits suits the built-in analyzers on a small VM.
var DefaultLimits = Limits{MaxTotalBytes: 400 << 20, MaxFileBytes: 2 << 20, MaxFiles: 60000}

// ErrTooLarge is returned when a repository exceeds Limits.
var ErrTooLarge = errors.New("repository exceeds scan size limits")

// DownloadTree downloads repo@sha as a tarball and extracts it into dest.
func (a *App) DownloadTree(ctx context.Context, installationID int64, repo, sha, dest string, lim Limits) error {
	tok, err := a.InstallationToken(ctx, installationID)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/repos/%s/tarball/%s", APIBase, repo, sha), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "token "+tok)
	req.Header.Set("User-Agent", "trishul-app")
	client := &http.Client{Timeout: 0} // bounded by ctx
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return &APIError{Status: resp.StatusCode, Body: "tarball download failed"}
	}
	return ExtractTarGz(io.LimitReader(resp.Body, lim.MaxTotalBytes+1), dest, lim)
}

// ExtractTarGz safely extracts a GitHub tarball (which wraps everything in one
// top-level directory) into dest. Symlinks, hard links, devices and any entry
// that would escape dest are skipped; oversized files are skipped.
func ExtractTarGz(r io.Reader, dest string, lim Limits) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return err
	}
	defer func() { _ = gz.Close() }()
	tr := tar.NewReader(gz)
	root, err := filepath.Abs(dest)
	if err != nil {
		return err
	}
	var total int64
	files := 0
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		// Strip GitHub's "<owner>-<repo>-<sha>/" prefix.
		name := h.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		} else {
			continue
		}
		if name == "" {
			continue
		}
		clean := filepath.Clean(filepath.FromSlash(name))
		if filepath.IsAbs(clean) || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
			continue
		}
		target := filepath.Join(root, clean)
		if !strings.HasPrefix(target, root+string(filepath.Separator)) {
			continue
		}
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o755); err != nil {
				return err
			}
		case tar.TypeReg:
			if h.Size > lim.MaxFileBytes {
				continue
			}
			files++
			total += h.Size
			if files > lim.MaxFiles || total > lim.MaxTotalBytes {
				return ErrTooLarge
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return err
			}
			fh, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC|os.O_EXCL, 0o644)
			if err != nil {
				if os.IsExist(err) {
					continue
				}
				return err
			}
			_, err = io.Copy(fh, io.LimitReader(tr, h.Size))
			_ = fh.Close()
			if err != nil {
				return err
			}
		default:
			// Symlinks, hard links, devices, FIFOs: never materialized.
		}
	}
}
