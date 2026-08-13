package rules

import (
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

	seen := make(map[string]int, len(plugins))
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
		if prev, dup := seen[key]; dup {
			findings = append(findings, report.Finding{
				Severity: report.SeverityError,
				Rule:     "HANKO104",
				Path:     jsonPointer("plugins", i, "source"),
				Message:  "plugin source resolves to the same install target as /plugins/" + itoa(prev) + " (\"" + key + "\"); the second install silently shadows the first",
				Fix:      "point one entry at a different repo/path/ref, or remove the redundant entry",
				DocURL:   "https://code.claude.com/docs/en/plugin-marketplaces",
			})
			return findings
		}
		seen[key] = i
	}
	return findings
}

func sourceIdentity(src any) (string, bool) {
	switch s := src.(type) {
	case string:
		p := strings.TrimSpace(s)
		p = strings.TrimPrefix(p, "./")
		p = strings.TrimSuffix(p, "/")
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
		return "github|" + repo + "|" + githubPin(s), true
	}
	return "", false
}

func githubPin(s map[string]any) string {
	if sha, ok := s["sha"].(string); ok && strings.TrimSpace(sha) != "" {
		return "sha:" + strings.TrimSpace(sha)
	}
	if ref, ok := s["ref"].(string); ok && strings.TrimSpace(ref) != "" {
		return "ref:" + strings.TrimSpace(ref)
	}
	return "@"
}
