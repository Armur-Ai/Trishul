package precision

import (
	"math"
	"strings"
	"testing"
)

func TestLoadLabels(t *testing.T) {
	in := `{"fingerprint_v2":"a","rule_id":"R1","verdict":"tp"}
# a comment

{"fingerprint_v2":"b","rule_id":"R1","verdict":"fp"}`
	ls, err := LoadLabels(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	if len(ls) != 2 {
		t.Fatalf("want 2 labels, got %d", len(ls))
	}
}

func TestCompute_PrecisionAndReproduces76FP(t *testing.T) {
	// 50 labels: 1 tp, 11 fp  -> matches the ~76% FP (2% actionable) shape when
	// we build a representative set. Here: build 49 fp + 1 tp => precision 2%.
	var labels []Label
	labels = append(labels, Label{RuleID: "R", Verdict: TP, FingerprintV2: "tp0"})
	for i := 0; i < 49; i++ {
		labels = append(labels, Label{RuleID: "R", Verdict: FP, FingerprintV2: fpid(i)})
	}
	stats := Compute(labels)
	if len(stats) != 1 {
		t.Fatalf("stats len=%d", len(stats))
	}
	if stats[0].FP != 49 || stats[0].TP != 1 {
		t.Fatalf("counts: %+v", stats[0])
	}
	if math.Abs(stats[0].Precision-0.02) > 0.001 {
		t.Errorf("precision=%.4f want 0.02", stats[0].Precision)
	}
	p, fp, decided := Overall(stats)
	if decided != 50 || math.Abs(fp-0.98) > 0.001 || math.Abs(p-0.02) > 0.001 {
		t.Errorf("overall p=%.3f fp=%.3f decided=%d", p, fp, decided)
	}
}

func TestCompute_BenignCountsAsCorrect(t *testing.T) {
	labels := []Label{
		{RuleID: "R", Verdict: TP},
		{RuleID: "R", Verdict: TPBenign},
		{RuleID: "R", Verdict: FP},
		{RuleID: "R", Verdict: Unclear}, // excluded
	}
	s := Compute(labels)[0]
	if s.Decided != 3 || s.Unclear != 1 {
		t.Errorf("decided/unclear: %+v", s)
	}
	// (tp + benign) / decided = 2/3
	if math.Abs(s.Precision-2.0/3.0) > 0.001 {
		t.Errorf("precision=%.4f want 0.667", s.Precision)
	}
}

func TestWilsonInterval(t *testing.T) {
	low, high := WilsonInterval(0, 0)
	if low != 0 || high != 1 {
		t.Errorf("n=0 should be [0,1], got [%v,%v]", low, high)
	}
	// 8/10 -> Wilson ~ [0.49, 0.94]
	low, high = WilsonInterval(8, 10)
	if low < 0.44 || low > 0.52 || high < 0.92 || high > 0.97 {
		t.Errorf("wilson(8,10)=[%.3f,%.3f] out of expected range", low, high)
	}
	if low < 0 || high > 1 {
		t.Error("interval must be clamped to [0,1]")
	}
}

func TestJoin(t *testing.T) {
	found := map[string][]string{"R": {"fp-labeled", "fp-new"}}
	labels := []Label{{RuleID: "R", Verdict: FP, FingerprintV2: "fp-labeled"}}
	matched, unlabeled := Join(found, labels)
	if len(matched) != 1 || matched[0].FingerprintV2 != "fp-labeled" {
		t.Errorf("matched=%+v", matched)
	}
	if len(unlabeled["R"]) != 1 || unlabeled["R"][0] != "fp-new" {
		t.Errorf("unlabeled=%v", unlabeled)
	}
}

func TestLabelingQueue_FewestFirst(t *testing.T) {
	stats := []RuleStats{
		{RuleID: "well", Decided: 20},
		{RuleID: "under", Decided: 1},
		{RuleID: "mid", Decided: 5},
	}
	q := LabelingQueue(stats)
	if q[0] != "under" || q[2] != "well" {
		t.Errorf("queue order=%v", q)
	}
}

func TestMarkdown(t *testing.T) {
	md := Markdown(Compute([]Label{{RuleID: "R", Verdict: FP}}))
	if !strings.Contains(md, "Rule precision") || !strings.Contains(md, "| R |") {
		t.Errorf("markdown missing content:\n%s", md)
	}
}

func fpid(i int) string { return "fp" + string(rune('a'+i%26)) + string(rune('0'+i/26)) }
