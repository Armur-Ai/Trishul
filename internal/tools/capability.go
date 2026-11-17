package internal

// requiredBinary maps a runner tool name to the external executable it needs.
//
// Only tools listed here participate in the pre-run availability check; any
// tool not listed runs exactly as before (no behaviour change). Keep this
// conservative: a wrong mapping here would wrongly skip a working tool, so the
// rule is "only skip a tool when we are confident which binary it needs and
// that binary is genuinely absent".
var requiredBinary = map[string]string{
	// SAST
	"semgrep":     "semgrep",
	"gosec":       "gosec",
	"staticcheck": "staticcheck",
	"bandit":      "bandit",
	"pylint":      "pylint",
	"eslint":      "eslint",
	"spotbugs":    "spotbugs",
	"pmd":         "pmd",
	"brakeman":    "brakeman",
	"cppcheck":    "cppcheck",
	"flawfinder":  "flawfinder",
	"clippy":      "cargo",
	// SCA / dependencies
	"cargo-audit":  "cargo",
	"trivy":        "trivy",
	"osv-scanner":  "osv-scanner",
	"govulncheck":  "govulncheck",
	"grype":        "grype",
	"cargo-geiger": "cargo",
	// Secrets
	"trufflehog": "trufflehog3",
	"gitleaks":   "gitleaks",
	// IaC
	"hadolint":    "hadolint",
	"tfsec":       "tfsec",
	"kics":        "kics",
	"checkov":     "checkov",
	"kube-linter": "kube-linter",
	"kube-score":  "kube-score",
	"terrascan":   "terrascan",
	// Smart-contract (opt-in web3 profile)
	"slither": "slither",
	"mythril": "myth",
	// Quality / misc
	"govet":      "go",
	"gocyclo":    "gocyclo",
	"golint":     "golint",
	"pydocstyle": "pydocstyle",
	"radon":      "radon",
	"jscpd":      "jscpd",
	"deadcode":   "deadcode",
	"vulture":    "vulture",
}

// RequiredBinary returns the executable a tool needs and whether that mapping
// is known. Unknown tools return ("", false).
func RequiredBinary(name string) (string, bool) {
	b, ok := requiredBinary[name]
	return b, ok
}

// IsToolSkippable reports whether a tool's required binary is known and
// confirmed missing from PATH — i.e. we can state with confidence that the tool
// would be skipped. For tools with no known binary mapping it returns false, so
// they are never skipped on a guess.
func IsToolSkippable(name string) bool {
	b, ok := requiredBinary[name]
	if !ok {
		return false
	}
	return !ToolAvailable(b)
}
