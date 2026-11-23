package feedback

import "testing"

func recs() []Record {
	return []Record{
		{RuleID: "R", Outcome: Dismissed, DismissReason: "fp"},
		{RuleID: "R", Outcome: Dismissed},
		{RuleID: "R", Outcome: Resolved},
		{RuleID: "R", Outcome: Untouched},
		{RuleID: "S", Outcome: Resolved},
		{RuleID: "S", Outcome: Resolved},
	}
}

func TestAggregate(t *testing.T) {
	stats := Aggregate(recs())
	if len(stats) != 2 {
		t.Fatalf("want 2 rules, got %d", len(stats))
	}
	r := stats[0] // "R" sorts first
	if r.RuleID != "R" || r.Total != 4 || r.Dismissed != 2 || r.Resolved != 1 {
		t.Fatalf("R counts wrong: %+v", r)
	}
	if r.DismissRate != 0.5 || r.FixRate != 0.25 {
		t.Errorf("R rates: dismiss=%v fix=%v", r.DismissRate, r.FixRate)
	}
	s := stats[1]
	if s.FixRate != 1.0 {
		t.Errorf("S fix rate should be 1.0, got %v", s.FixRate)
	}
}

func TestAnonymize_DropsIdentifyingFields(t *testing.T) {
	stats := Aggregate([]Record{{RuleID: "R", Repo: "secret/repo", Outcome: Dismissed, DismissReason: "has a secret path"}})
	anon := Anonymize(stats)
	if len(anon) != 1 || anon[0].RuleID != "R" {
		t.Fatalf("anon=%+v", anon)
	}
	// AnonStat has no Repo/Reason/Fingerprint fields by construction — just assert
	// the rate came through.
	if anon[0].DismissRate != 1.0 || anon[0].Total != 1 {
		t.Errorf("anon rate/total wrong: %+v", anon[0])
	}
}

func TestHighDismissRules(t *testing.T) {
	stats := Aggregate(recs())
	// R: dismiss 0.5 over 4; S: 0 over 2. threshold 0.4, minSample 3 -> only R.
	hi := HighDismissRules(stats, 0.4, 3)
	if len(hi) != 1 || hi[0] != "R" {
		t.Errorf("high-dismiss=%v want [R]", hi)
	}
	// minSample 10 -> none qualify
	if len(HighDismissRules(stats, 0.4, 10)) != 0 {
		t.Error("minSample should exclude small samples")
	}
}
