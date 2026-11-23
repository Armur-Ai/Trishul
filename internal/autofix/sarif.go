package autofix

import "github.com/Armur-Ai/Trishul/pkg/sarif"

// ToSARIFFix converts a Patch into a SARIF fix (fixes[]), so GitHub code
// scanning can offer to apply it. The patch's inclusive line range becomes the
// deleted region and the replacement becomes the inserted content. An insertion
// (EndLine == StartLine-1) deletes nothing and inserts before StartLine.
func ToSARIFFix(p Patch, description string) sarif.Fix {
	var desc *sarif.Message
	if description != "" {
		desc = &sarif.Message{Text: description}
	}
	region := sarif.Region{StartLine: p.StartLine}
	if p.EndLine >= p.StartLine {
		region.EndLine = p.EndLine
	} else {
		// pure insertion before StartLine: empty deleted region
		region.EndLine = p.StartLine - 1
	}
	return sarif.Fix{
		Description: desc,
		ArtifactChanges: []sarif.ArtifactChange{{
			ArtifactLocation: sarif.ArtifactLocation{URI: p.Path},
			Replacements: []sarif.Replacement{{
				DeletedRegion:   region,
				InsertedContent: &sarif.MultiformatMessageString{Text: p.Replacement},
			}},
		}},
	}
}
