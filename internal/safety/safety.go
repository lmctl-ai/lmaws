// SPDX-License-Identifier: MIT

package safety

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	PrefixUnderscore         = "lmoci_"
	PrefixHyphen             = "lmoci-"
	PrefixCloud              = "lmcloud-"
	DefaultExampleCostCapUSD = 0.05
	HardRunCostCeilingUSD    = 0.25
)

var (
	rePEMKey      = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)
	reJSONPrivKey = regexp.MustCompile(`"private_key"\s*:\s*"[^"]*"`)
	reAuthHeader  = regexp.MustCompile(`(?i)(Authorization\s*:\s*Signature\s+)[^\r\n]+`)
	reBearer      = regexp.MustCompile(`(?i)(Bearer\s+)[A-Za-z0-9._\-+/=]+`)
	reKVSecret    = regexp.MustCompile(`(?i)(password|passwd|passphrase|secret_value|client_secret|access_token|refresh_token|private_key|session_token|signature)\s*([=:])\s*([^\s,;"]+)`)
)

// RedactSecrets scrubs private keys, signatures, bearer tokens, userinfo, and secret values.
func RedactSecrets(s string) string {
	if s == "" {
		return ""
	}
	out := rePEMKey.ReplaceAllString(s, "[REDACTED_PRIVATE_KEY]")
	out = reJSONPrivKey.ReplaceAllString(out, `"private_key":"[REDACTED]"`)
	out = reAuthHeader.ReplaceAllString(out, "${1}[REDACTED]")
	out = reBearer.ReplaceAllString(out, "${1}[REDACTED]")
	out = reKVSecret.ReplaceAllString(out, "$1$2[REDACTED]")
	return out
}

// Redact is an alias for RedactSecrets.
func Redact(s string) string {
	return RedactSecrets(s)
}

// SanitizeURL strips any userinfo or query parameters from a URL string.
func SanitizeURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil {
		return RedactSecrets(trimmed)
	}
	u.User = nil
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimRight(u.String(), "/")
}

// LedgerEntry records a resource created during the current host run.
type LedgerEntry struct {
	Kind          string
	Name          string
	CreatedAtUnix int64
}

// RunLedger tracks resources created by the current run.
type RunLedger struct {
	mu      sync.Mutex
	entries []LedgerEntry
}

func NewRunLedger() *RunLedger {
	return &RunLedger{}
}

func (l *RunLedger) Record(kind, name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, e := range l.entries {
		if e.Kind == kind && e.Name == name {
			return
		}
	}
	l.entries = append(l.entries, LedgerEntry{
		Kind:          kind,
		Name:          name,
		CreatedAtUnix: time.Now().Unix(),
	})
}

func (l *RunLedger) Remove(kind, name string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	kept := l.entries[:0]
	for _, e := range l.entries {
		if e.Kind == kind && e.Name == name {
			continue
		}
		kept = append(kept, e)
	}
	l.entries = kept
}

func (l *RunLedger) Snapshot() []LedgerEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]LedgerEntry, len(l.entries))
	copy(out, l.entries)
	return out
}

func (l *RunLedger) FormatEntry(e LedgerEntry) string {
	return fmt.Sprintf("%s:%s", e.Kind, e.Name)
}
