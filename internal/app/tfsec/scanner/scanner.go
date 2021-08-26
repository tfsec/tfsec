package scanner

import (
	"sort"

	"github.com/aquasecurity/tfsec/pkg/result"
	"github.com/aquasecurity/tfsec/pkg/severity"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/block"

	"github.com/aquasecurity/tfsec/pkg/rule"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/metrics"

	"github.com/aquasecurity/tfsec/internal/app/tfsec/debug"
)

// Scanner scans HCL blocks by running all registered rules against them
type Scanner struct {
	includePassed     bool
	includeIgnored    bool
	excludedRuleIDs   []string
	ignoreCheckErrors bool
	workspaceName     string
}

// New creates a new Scanner
func New(options ...Option) *Scanner {
	s := &Scanner{
		ignoreCheckErrors: true,
	}
	for _, option := range options {
		option(s)
	}
	return s
}

// Find element in list
func checkInList(id string, legacyID string, list []string) bool {
	for _, codeIgnored := range list {
		if codeIgnored == id || (legacyID != "" && codeIgnored == legacyID) {
			return true
		}
	}
	return false
}

func (scanner *Scanner) Scan(modules []block.Module) []result.Result {
	checkTime := metrics.Start(metrics.Check)
	defer checkTime.Stop()
	var results []result.Result
	rules := GetRegisteredRules()
	for _, module := range modules {
		results = append(results, scanner.scanModule(module, rules)...)
	}
	sort.Slice(results, func(i, j int) bool {
		switch {
		case results[i].RuleID < results[j].RuleID:
			return true
		case results[i].RuleID > results[j].RuleID:
			return false
		default:
			return results[i].HashCode() > results[j].HashCode()
		}
	})
	return results
}

func (scanner *Scanner) scanModule(module block.Module, rules []rule.Rule) []result.Result {
	var results []result.Result
	for _, checkBlock := range module.GetBlocks() {
		for _, r := range rules {
			if rule.IsRuleRequiredForBlock(&r, checkBlock) {
				debug.Log("Running rule for %s on %s (%s)...", r.ID(), checkBlock.Reference(), checkBlock.Range().Filename)
				ruleResults := rule.CheckRule(&r, checkBlock, module, scanner.ignoreCheckErrors)
				if ruleResults != nil {
					if scanner.includePassed && ruleResults.All() == nil {
						res := result.New(checkBlock).
							WithLegacyRuleID(r.LegacyID).
							WithRuleID(r.ID()).
							WithDescription("Resource '%s' passed check: %s", checkBlock.FullName(), r.Documentation.Summary).
							WithStatus(result.Passed).
							WithImpact(r.Documentation.Impact).
							WithResolution(r.Documentation.Resolution).
							WithSeverity(r.DefaultSeverity)
						results = append(results, *res)
					} else {
						for _, ruleResult := range ruleResults.All() {
							if ruleResult.Severity == severity.None {
								ruleResult.Severity = r.DefaultSeverity
							}
							if !scanner.includeIgnored && (ruleResult.IsIgnored(scanner.workspaceName) || checkInList(ruleResult.RuleID, ruleResult.LegacyRuleID, scanner.excludedRuleIDs)) {
								// rule was ignored
								metrics.Add(metrics.IgnoredChecks, 1)
								debug.Log("Ignoring '%s'", ruleResult.RuleID)
							} else {
								results = append(results, *ruleResult)

							}
						}
					}
				}
			}
		}
	}
	return results
}
