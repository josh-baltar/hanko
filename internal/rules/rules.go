// Package rules implements the Go-coded validation rules that layer on
// top of the embedded JSON schemas. These catch the cases that do not
// round-trip cleanly through pure JSON Schema: reserved marketplace
// names, duplicate-hooks declarations, agents-as-bare-directory, and
// missing-recommended-fields warnings.
//
// Every rule has a stable identifier (HANKO001, HANKO002, ...) so CI
// users can pin or ignore specific rules without relying on wording.
// The identifiers are documented in docs/rules.md.
package rules

import "github.com/RoninForge/hanko/internal/report"

// Kind distinguishes plugin-manifest rules from marketplace-manifest rules
// when dispatching the right rule set.
type Kind int

const (
	// KindPlugin applies rules relevant to plugin.json files.
	KindPlugin Kind = iota
	// KindMarketplace applies rules relevant to marketplace.json files.
	KindMarketplace
)

// Rule is the function shape every check implements. It receives the
// decoded manifest (typically a map[string]any) and returns any findings.
// Rules must not mutate the input.
type Rule func(manifest any) []report.Finding

// Set collects rules by kind so the validator can ask for the right set
// by manifest type.
type Set struct {
	Plugin      []Rule
	Marketplace []Rule
}

// Base returns the default rule set applied to every manifest. Marketplace
// overlays (anthropic strict, buildwithclaude, cc-marketplace) add on top.
func Base() Set {
	return Set{
		Plugin: []Rule{
			DuplicateHooksDeclaration,
			AgentsAsBareDirectory,
			AuthorMissing,
			VersionMissing,
		},
		Marketplace: []Rule{
			ReservedMarketplaceName,
			DuplicateSourceTarget,
			ImpersonationPattern,
			DuplicatePluginNames,
		},
	}
}

// StrictAnthropic layers the strict Anthropic submission rules: `author`
// is an error (not warning) because Claude Desktop's listAvailablePlugins
// validator refuses to load catalogs with missing authors (issue #33068).
// The overlay REPLACES the softer AuthorMissing rule rather than appending
// beside it, so a single missing-author manifest produces HANKO003-strict
// only, not both HANKO003 and HANKO003-strict.
func StrictAnthropic() Set {
	return Set{
		Plugin: []Rule{
			DuplicateHooksDeclaration,
			AgentsAsBareDirectory,
			authorMissingStrict,
			VersionMissing,
		},
		Marketplace: Base().Marketplace,
	}
}

// CCMarketplace layers the cc-marketplace rules: version and description
// are required (not optional). Same replace-not-append discipline as
// StrictAnthropic: VersionMissing is swapped for its strict variant so
// HANKO004 and HANKO004-strict cannot both fire.
func CCMarketplace() Set {
	return Set{
		Plugin: []Rule{
			DuplicateHooksDeclaration,
			AgentsAsBareDirectory,
			AuthorMissing,
			versionMissingStrict,
			descriptionMissingStrict,
		},
		Marketplace: Base().Marketplace,
	}
}

// BuildWithClaude is reserved for future rules once their CONTRIBUTING
// conventions stabilise. Currently a pass-through to Base.
func BuildWithClaude() Set {
	return Base()
}

// ClaudeMarketplaces is auto-discovery only and imposes no rules beyond
// the base schema. Declared explicitly so the ForMarketplace switch does
// not rely on fallthrough, and so future rules can land here without
// touching the CLI help strings.
func ClaudeMarketplaces() Set {
	return Base()
}

// ForMarketplace returns the rule set for a given marketplace name. Unknown
// names fall back to Base so `--marketplace anything` is a no-op rather
// than a hard error.
func ForMarketplace(name string) Set {
	switch name {
	case "anthropic":
		return StrictAnthropic()
	case "cc-marketplace":
		return CCMarketplace()
	case "buildwithclaude":
		return BuildWithClaude()
	case "claudemarketplaces":
		return ClaudeMarketplaces()
	default:
		return Base()
	}
}

// MarketplaceNames returns the list of names recognized by ForMarketplace.
// Used by the CLI help text so docs and code cannot drift.
func MarketplaceNames() []string {
	return []string{"anthropic", "buildwithclaude", "cc-marketplace", "claudemarketplaces"}
}

// Apply runs every rule in the list against the manifest and flattens the
// findings in rule order. A convenience so callers do not have to loop.
func Apply(rs []Rule, manifest any) []report.Finding {
	var out []report.Finding
	for _, r := range rs {
		out = append(out, r(manifest)...)
	}
	return out
}
