package ghapp

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestVerifySignature(t *testing.T) {
	secret, body := []byte("s3cret"), []byte(`{"a":1}`)
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	good := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if !VerifySignature(secret, body, good) {
		t.Fatal("valid signature rejected")
	}
	for _, bad := range []string{"", "sha256=00", "sha1=" + good[7:], good[:len(good)-1] + "0"} {
		if VerifySignature(secret, body, bad) {
			t.Errorf("accepted bad signature %q", bad)
		}
	}
	if VerifySignature(nil, body, good) {
		t.Error("empty secret must never verify")
	}
}

type entry struct {
	name, body, link string
	typ              byte
}

func makeTarGz(t *testing.T, entries []entry) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Typeflag: e.typ, Size: int64(len(e.body)), Linkname: e.link}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	return buf.Bytes()
}

func TestExtractTarGzIsSafe(t *testing.T) {
	outside := t.TempDir()
	dest := t.TempDir()
	data := makeTarGz(t, []entry{
		{name: "o-r-sha/", typ: tar.TypeDir},
		{name: "o-r-sha/src/app.js", body: "ok", typ: tar.TypeReg},
		{name: "o-r-sha/../../escape.txt", body: "x", typ: tar.TypeReg},
		{name: "o-r-sha/link", link: outside, typ: tar.TypeSymlink},
		{name: "o-r-sha/hard", link: "/etc/passwd", typ: tar.TypeLink},
		{name: "o-r-sha/big.bin", body: string(make([]byte, 100)), typ: tar.TypeReg},
	})
	lim := Limits{MaxTotalBytes: 1 << 20, MaxFileBytes: 50, MaxFiles: 10}
	if err := ExtractTarGz(bytes.NewReader(data), dest, lim); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "src/app.js")); err != nil || string(b) != "ok" {
		t.Fatalf("regular file not extracted: %v", err)
	}
	for _, p := range []string{"link", "hard", "big.bin"} {
		if _, err := os.Lstat(filepath.Join(dest, p)); err == nil {
			t.Errorf("%s should not be materialized", p)
		}
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), "escape.txt")); err == nil {
		t.Error("path traversal escaped dest")
	}
}

func TestExtractTarGzLimits(t *testing.T) {
	var es []entry
	for i := 0; i < 5; i++ {
		es = append(es, entry{name: "r/f" + string(rune('a'+i)), body: "x", typ: tar.TypeReg})
	}
	err := ExtractTarGz(bytes.NewReader(makeTarGz(t, es)), t.TempDir(), Limits{MaxTotalBytes: 1 << 20, MaxFileBytes: 10, MaxFiles: 3})
	if err != ErrTooLarge {
		t.Fatalf("want ErrTooLarge, got %v", err)
	}
}
