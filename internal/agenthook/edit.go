package agenthook

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// editInput is the permissive view of tool_input for the edit tools. Only the
// fields the hook needs are decoded; everything else is ignored.
type editInput struct {
	FilePath     string `json:"file_path"`
	NotebookPath string `json:"notebook_path"`
	Content      string `json:"content"`     // Write
	NewString    string `json:"new_string"`  // Edit
	OldString    string `json:"old_string"`  // Edit
	ReplaceAll   bool   `json:"replace_all"` // Edit
	NewSource    string `json:"new_source"`  // NotebookEdit
	Edits        []struct {
		OldString  string `json:"old_string"`
		NewString  string `json:"new_string"`
		ReplaceAll bool   `json:"replace_all"`
	} `json:"edits"` // MultiEdit
}

// resolvePath returns the workspace-relative and absolute path the edit touched.
// cwd is the hook's reported working directory (the workspace root).
func resolvePath(cwd string, ei editInput) (abs, rel string, ok bool) {
	p := ei.FilePath
	if p == "" {
		p = ei.NotebookPath
	}
	if p == "" {
		return "", "", false
	}
	p = filepath.FromSlash(p)
	if filepath.IsAbs(p) {
		abs = filepath.Clean(p)
	} else if cwd != "" {
		abs = filepath.Join(cwd, p)
	} else {
		abs = filepath.Clean(p)
	}
	rel = abs
	if cwd != "" {
		if r, err := filepath.Rel(cwd, abs); err == nil && !strings.HasPrefix(r, "..") {
			rel = r
		} else {
			rel = filepath.Base(abs)
		}
	}
	return abs, filepath.ToSlash(rel), true
}

// reconstructPre derives the file's pre-edit content from the post-edit content
// and the tool input, by reversing the edit. It returns havePre=false when the
// pre-edit state cannot be reconstructed from the payload alone (a whole-file
// Write or a NotebookEdit), in which case the caller falls back to the session
// baseline.
//
// Reconstruction never executes anything; it is pure text substitution.
func reconstructPre(toolName string, ei editInput, post []byte) (pre []byte, havePre bool) {
	switch toolName {
	case "Edit":
		if ei.NewString == "" && ei.OldString == "" {
			return nil, false
		}
		n := 1
		if ei.ReplaceAll {
			n = -1
		}
		return []byte(strings.Replace(string(post), ei.NewString, ei.OldString, n)), true
	case "MultiEdit":
		if len(ei.Edits) == 0 {
			return nil, false
		}
		s := string(post)
		// Reverse each edit, newest first (edits were applied in order).
		for i := len(ei.Edits) - 1; i >= 0; i-- {
			e := ei.Edits[i]
			n := 1
			if e.ReplaceAll {
				n = -1
			}
			s = strings.Replace(s, e.NewString, e.OldString, n)
		}
		return []byte(s), true
	default:
		// Write / NotebookEdit: no reliable pre-edit text in the payload.
		return nil, false
	}
}

// decodeEditInput unmarshals tool_input permissively.
func decodeEditInput(raw json.RawMessage) editInput {
	var ei editInput
	_ = json.Unmarshal(raw, &ei)
	return ei
}
