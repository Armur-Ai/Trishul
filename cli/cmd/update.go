package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Armur-Ai/Trishul/internal/bundle"
)

const defaultBundleURL = "https://armur.ai/trishul/bundle.json"

// embeddedBundleKey is the base64 Ed25519 public key the client verifies the
// update bundle against. Populating it with the real production key is a D-HUMAN
// action; until then --pubkey must be supplied and updates are off by default.
var embeddedBundleKey = ""

var (
	updateURL    string
	updateFile   string
	updatePubKey string
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Pull and verify the signed rules/advisory bundle (antivirus-model)",
	Long: `Downloads Trishul's daily signed advisory bundle and verifies its Ed25519
signature against the embedded public key before applying it to the local cache.
No code or user data leaves your machine — Trishul only fetches a static, signed
file. Use --file to apply a local bundle, or --url for a mirror.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		var data []byte
		var err error
		if updateFile != "" {
			data, err = os.ReadFile(updateFile)
		} else {
			data, err = fetchBundle(updateURL)
		}
		if err != nil {
			return err
		}
		key := updatePubKey
		if key == "" {
			key = embeddedBundleKey
		}
		if key == "" {
			return fmt.Errorf("no bundle public key configured; pass --pubkey (the production key ships in a later release)")
		}
		cache, _ := os.UserCacheDir()
		n, err := runUpdate(data, key, filepath.Join(cache, "trishul"), os.Stdout)
		if err != nil {
			return err
		}
		fmt.Printf("updated: %d advisories applied\n", n)
		return nil
	},
}

// runUpdate verifies the signed bundle against pubKeyB64 and writes its advisories
// to cacheDir/advisories.json. Returns the advisory count. Verification failure
// applies nothing (fail closed).
func runUpdate(signed []byte, pubKeyB64, cacheDir string, w io.Writer) (int, error) {
	pub, err := bundle.ParsePublicKey(pubKeyB64)
	if err != nil {
		return 0, err
	}
	b, err := bundle.Verify(signed, pub)
	if err != nil {
		return 0, err // fail closed on a bad/forged bundle
	}
	if err := os.MkdirAll(filepath.Join(cacheDir, "advisories"), 0o755); err != nil {
		return 0, err
	}
	out, err := json.MarshalIndent(b.Advisories, "", "  ")
	if err != nil {
		return 0, err
	}
	dst := filepath.Join(cacheDir, "advisories", "bundle.json")
	if err := os.WriteFile(dst, out, 0o644); err != nil {
		return 0, err
	}
	fmt.Fprintf(w, "bundle %s verified (%s)\n", b.Version, b.GeneratedAt)
	return len(b.Advisories), nil
}

func fetchBundle(url string) ([]byte, error) {
	if url == "" {
		url = defaultBundleURL
	}
	c := &http.Client{Timeout: 10 * time.Second}
	resp, err := c.Get(url)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch bundle: HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 16<<20))
}

func init() {
	updateCmd.Flags().StringVar(&updateURL, "url", defaultBundleURL, "bundle URL")
	updateCmd.Flags().StringVar(&updateFile, "file", "", "apply a local bundle file instead of fetching")
	updateCmd.Flags().StringVar(&updatePubKey, "pubkey", "", "base64/hex Ed25519 public key to verify the bundle")
	rootCmd.AddCommand(updateCmd)
}
