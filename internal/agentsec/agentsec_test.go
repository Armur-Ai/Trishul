package agentsec

import "testing"

func TestRunAnalyzers_AggregatesAndSorts(t *testing.T) {
	a := func(string) ([]AgentFinding, error) {
		return []AgentFinding{{CheckID: "B", File: "z.md", Line: 5}, {CheckID: "A", File: "a.md", Line: 2}}, nil
	}
	b := func(string) ([]AgentFinding, error) {
		return []AgentFinding{{CheckID: "C", File: "a.md", Line: 1}}, nil
	}
	bad := func(string) ([]AgentFinding, error) { return nil, errFake }
	out, err := runAnalyzers(".", []Analyzer{a, b, bad})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 3 {
		t.Fatalf("expected 3 findings (bad analyzer skipped), got %d", len(out))
	}
	// sorted by file, then line
	if !(out[0].File == "a.md" && out[0].Line == 1 && out[1].Line == 2 && out[2].File == "z.md") {
		t.Errorf("findings not sorted: %+v", out)
	}
}

var errFake = &fakeErr{}

type fakeErr struct{}

func (*fakeErr) Error() string { return "boom" }
