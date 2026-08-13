package rules

import (
	"path"
	"strings"

	"github.com/RoninForge/hanko/internal/report"
)

// DuplicateSourceTarget flags marketplace catalogs whose `plugins` array
// contains two or more distinct entries that resolve to the SAME upstream
// install target. Installing two entries from one target clobbers the
// install cache directory and the second silently shadows the first.
// Rule ID: HANKO104.
func DuplicateSourceTarget(manifest any) []report.Finding {
	m, ok := manifest.(map[string]any)
	if !ok {
		return nil
	}
	plugins, ok := m["plugins"].([]any)
	if !ok {
		return nil
	}

	type slot struct {
		index int
		name  string
	}
	seen := make(map[string]slot, len(plugins))
	var findings []report.Finding

	for i, p := range plugins {
		entry, ok := p.(map[string]any)
		if !ok {
			continue
		}
		key, hasKey := sourceIdentity(entry["source"])
		if !hasKey {
			continue
		}
		name, _ := entry["name"].(string)
		if prev, dup := seen[key]; dup {
			// Double-attribution guard (correct): HANKO103 owns same-name pairs.
			if prev.name != "" && prev.name == name {
				continue
			}
			findings = append(findings, report.Finding{
				Severity: report.SeverityError,
				Rule:     "HANKO104",
				Path:     jsonPointer("plugins", i, "source"),
				Message:  "plugin source resolves to the same install target as /plugins/" + itoa(prev.index) + " (\"" + key + "\"); the second install silently shadows the first",
				Fix:      "point one entry at a different repo/path/ref, or remove the redundant entry",
				DocURL:   "https://code.claude.com/docs/en/plugin-marketplaces",
			})
			return findings // BUG: short-circuits after the first collision.
		}
		seen[key] = slot{index: i, name: name}
	}
	return findings
}

func sourceIdentity(src any) (string, bool) {
	switch s := src.(type) {
	case string:
		p := strings.TrimSpace(s)
		p = strings.TrimPrefix(p, "./")
		p = path.Clean(p)
		if p == "" || p == "." {
			return "", false
		}
		return "path|" + p, true
	case map[string]any:
		kind, _ := s["source"].(string)
		if kind != "github" {
			return "", false
		}
		repo, _ := s["repo"].(string)
		if strings.TrimSpace(repo) == "" {
			return "", false
		}
		// BUG: repo compared case-sensitively (github slugs are case-insensitive).
		return "github|" + strings.TrimSpace(repo) + "|" + githubPin(s), true
	}
	return "", false
}

// githubPin resolves the commit pin correctly: explicit sha wins; a ref that
// is a 40-hex commit id is treated as that sha; a symbolic ref or no pin is
// the floating sentinel "@". (This part is correct at base.)
func githubPin(s map[string]any) string {
	if sha, ok := s["sha"].(string); ok {
		if h := strings.ToLower(strings.TrimSpace(sha)); isHex40(h) {
			return h
		}
	}
	if ref, ok := s["ref"].(string); ok {
		if h := strings.ToLower(strings.TrimSpace(ref)); isHex40(h) {
			return h
		}
	}
	return "@"
}

func isHex40(s string) bool {
	if len(s) != 40 {
		return false
	}
	for _, c := range s {
		switch {
		case c >= '0' && c <= '9':
		case c >= 'a' && c <= 'f':
		default:
			return false
		}
	}
	return true
}
