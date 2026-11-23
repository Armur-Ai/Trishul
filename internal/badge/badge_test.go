package badge

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestForGrade(t *testing.T) {
	a := ForGrade("A")
	if a.Message != "grade A" || a.Color != "brightgreen" || a.SchemaVersion != 1 {
		t.Errorf("A badge wrong: %+v", a)
	}
	if ForGrade("F").Color != "red" {
		t.Error("F should be red")
	}
	if ForGrade("Z").Color != "lightgrey" {
		t.Error("unknown grade should be lightgrey")
	}
}

func TestForFindings(t *testing.T) {
	if b := ForFindings(0, false); b.Message != "passing" || b.Color != "brightgreen" {
		t.Errorf("clean badge wrong: %+v", b)
	}
	if b := ForFindings(3, false); b.Message != "3 issues" || b.Color != "yellow" {
		t.Errorf("non-blocking badge wrong: %+v", b)
	}
	if b := ForFindings(1, true); b.Message != "1 issue" || b.Color != "red" {
		t.Errorf("blocking badge wrong: %+v", b)
	}
}

func TestJSON_ShieldsSchema(t *testing.T) {
	data, err := ForGrade("B").JSON()
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"schemaVersion", "label", "message", "color"} {
		if _, ok := m[k]; !ok {
			t.Errorf("missing shields field %q in %s", k, data)
		}
	}
	if !strings.Contains(string(data), `"schemaVersion":1`) {
		t.Errorf("schemaVersion not 1: %s", data)
	}
}
