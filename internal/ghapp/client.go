// Package ghapp is a small, dependency-free GitHub App client: app JWTs,
// cached installation tokens, REST calls, webhook signature verification and
// safe repository tarball extraction.
package ghapp

import (
	"bytes"
	"context"
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// APIBase is the GitHub REST API root (overridable in tests).
var APIBase = "https://api.github.com"

// App authenticates as a GitHub App.
type App struct {
	ID   int64
	Key  *rsa.PrivateKey
	HTTP *http.Client

	mu     sync.Mutex
	tokens map[int64]cachedToken
}

type cachedToken struct {
	token   string
	expires time.Time
}

// ParsePrivateKey parses a PEM-encoded RSA key (PKCS#1 or PKCS#8).
func ParsePrivateKey(pemBytes []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block in private key")
	}
	if k, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rk, nil
}

// New returns an App client.
func New(id int64, key *rsa.PrivateKey) *App {
	return &App{ID: id, Key: key, HTTP: &http.Client{Timeout: 60 * time.Second}, tokens: map[int64]cachedToken{}}
}

// JWT returns a short-lived RS256 app JWT.
func (a *App) JWT() (string, error) {
	now := time.Now()
	header := b64(`{"alg":"RS256","typ":"JWT"}`)
	claims, _ := json.Marshal(map[string]interface{}{
		"iat": now.Add(-60 * time.Second).Unix(), // clock-skew allowance
		"exp": now.Add(9 * time.Minute).Unix(),
		"iss": fmt.Sprint(a.ID),
	})
	signing := header + "." + b64(string(claims))
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, a.Key, crypto.SHA256, sum[:])
	if err != nil {
		return "", err
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// InstallationToken returns a cached installation access token.
func (a *App) InstallationToken(ctx context.Context, installationID int64) (string, error) {
	a.mu.Lock()
	if t, ok := a.tokens[installationID]; ok && time.Until(t.expires) > 5*time.Minute {
		a.mu.Unlock()
		return t.token, nil
	}
	a.mu.Unlock()

	jwt, err := a.JWT()
	if err != nil {
		return "", err
	}
	var out struct {
		Token     string    `json:"token"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	if err := a.do(ctx, "POST", fmt.Sprintf("/app/installations/%d/access_tokens", installationID), "Bearer "+jwt, nil, &out); err != nil {
		return "", err
	}
	a.mu.Lock()
	a.tokens[installationID] = cachedToken{out.Token, out.ExpiresAt}
	a.mu.Unlock()
	return out.Token, nil
}

// AppRequest calls the API authenticated as the app itself (JWT).
func (a *App) AppRequest(ctx context.Context, method, path string, body, out interface{}) error {
	jwt, err := a.JWT()
	if err != nil {
		return err
	}
	return a.do(ctx, method, path, "Bearer "+jwt, body, out)
}

// Request calls the API as an installation.
func (a *App) Request(ctx context.Context, installationID int64, method, path string, body, out interface{}) error {
	tok, err := a.InstallationToken(ctx, installationID)
	if err != nil {
		return err
	}
	return a.do(ctx, method, path, "token "+tok, body, out)
}

// APIError is a non-2xx GitHub response.
type APIError struct {
	Status int
	Body   string
}

func (e *APIError) Error() string { return fmt.Sprintf("github api: %d: %s", e.Status, e.Body) }

func (a *App) do(ctx context.Context, method, path, auth string, body, out interface{}) error {
	var rdr io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(buf)
	}
	url := path
	if !strings.HasPrefix(path, "http") {
		url = APIBase + path
	}
	req, err := http.NewRequestWithContext(ctx, method, url, rdr)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", auth)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "trishul-app")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := a.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if resp.StatusCode/100 != 2 {
		msg := string(data)
		if len(msg) > 500 {
			msg = msg[:500]
		}
		return &APIError{Status: resp.StatusCode, Body: msg}
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// VerifySignature checks an X-Hub-Signature-256 header in constant time.
func VerifySignature(secret, body []byte, header string) bool {
	const prefix = "sha256="
	if !strings.HasPrefix(header, prefix) || len(secret) == 0 {
		return false
	}
	got, err := hex.DecodeString(strings.TrimPrefix(header, prefix))
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write(body)
	return hmac.Equal(got, mac.Sum(nil))
}
