package internal

// qualityTools are code-quality / style / complexity tools that are not
// security scanners. They run only under the `quality` or `all` profile; the
// default `security` profile omits them so a security scan is signal, not
// 400 style findings.
var qualityTools = map[string]bool{
	"golint":       true,
	"gocyclo":      true,
	"radon":        true,
	"pydocstyle":   true,
	"vulture":      true,
	"deadcode":     true,
	"godeadcode":   true,
	"jscpd":        true,
	"cargo-geiger": true,
}

// IsQualityTool reports whether a tool is a code-quality tool rather than a
// security scanner.
func IsQualityTool(name string) bool {
	return qualityTools[name]
}
