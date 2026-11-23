package tasks

import (
	"github.com/Armur-Ai/Trishul/internal/config"
	utils "github.com/Armur-Ai/Trishul/pkg"
)

// externalTools lists runners in the simple-scan set that shell out to a
// third-party binary (and, for semgrep --config=auto, the network). The
// built-in scan skips them so it is fast, hermetic and safe to run on
// untrusted pull-request content.
var externalTools = map[string]bool{
	"semgrep": true,
}

// RunBuiltinScan runs only Trishul's built-in, dependency-free analyzers
// (AI agent supply-chain, Vibe Top 10, client secrets, Supabase/Firebase
// rules, exploitability) in-process. It needs no Redis, no server and no
// external tools, and it never executes repository content.
//
// A project config (.trishul.yml) may disable individual analyzers, but its
// plugins are deliberately NOT run: this entry point is used on untrusted PR
// heads (GitHub App, fork PRs), where a config-declared plugin would be
// arbitrary code execution.
func RunBuiltinScan(dirPath string) (map[string]interface{}, []ScanError, error) {
	all, names := buildSimpleScanRunnersNamed(dirPath, "")
	var cfg *config.ArmurConfig
	if c, err := config.LoadProjectConfig(dirPath); err == nil {
		cfg = c
	}

	var runners []func() toolResult
	for i, run := range all {
		name := names[i]
		if externalTools[name] {
			continue
		}
		if cfg != nil && !cfg.IsToolEnabled(name) {
			continue
		}
		runners = append(runners, run)
	}

	categorized, scanErrors := runParallel(dirPath, runners)
	newCatResult := utils.ConvertCategorizedResults(categorized)
	out := utils.ReformatScanResults(newCatResult)
	adv := utils.ReformatAdvancedScanResults(newCatResult)
	out[utils.INFRA_SECURITY] = sortFlatFindings(adv[utils.INFRA_SECURITY])
	out[utils.SECRET_DETECTION] = sortFlatFindings(adv[utils.SECRET_DETECTION])
	out[utils.AGENT_SECURITY] = sortFlatFindings(newCatResult[utils.AGENT_SECURITY])
	out[utils.EXPLOITABILITY] = correlatedExploitability(out, newCatResult)
	out[utils.VIBE_SECURITY] = sortFlatFindings(newCatResult[utils.VIBE_SECURITY])
	return out, scanErrors, nil
}
