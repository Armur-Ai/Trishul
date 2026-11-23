package gatepolicy

import (
	"testing"

	"github.com/Armur-Ai/Trishul/internal/rules"
)

func TestEffectiveMaturity_AutoDemote(t *testing.T) {
	// stable but low precision -> beta
	if got := EffectiveMaturity(rules.MaturityStable, 0.5, true); got != rules.MaturityBeta {
		t.Errorf("low-precision stable should demote to beta, got %q", got)
	}
	// stable with good precision -> stays stable
	if got := EffectiveMaturity(rules.MaturityStable, 0.85, true); got != rules.MaturityStable {
		t.Errorf("good stable should stay stable, got %q", got)
	}
	// no precision data -> no demotion
	if got := EffectiveMaturity(rules.MaturityStable, 0, false); got != rules.MaturityStable {
		t.Errorf("missing data should not demote, got %q", got)
	}
	// exactly at threshold -> not demoted (below only)
	if got := EffectiveMaturity(rules.MaturityStable, DemotionThreshold, true); got != rules.MaturityStable {
		t.Errorf("at threshold should stay stable, got %q", got)
	}
}

func TestShowInline(t *testing.T) {
	if !ShowInline(rules.MaturityStable, 0.9, true) {
		t.Error("healthy stable should show inline")
	}
	if ShowInline(rules.MaturityStable, 0.4, true) {
		t.Error("auto-demoted stable should NOT show inline")
	}
	if ShowInline(rules.MaturityBeta, 0.99, true) {
		t.Error("beta should never show inline")
	}
	if ShowInline(rules.MaturityExperimental, 0.99, true) {
		t.Error("experimental should never show inline")
	}
}

func TestShowInReport(t *testing.T) {
	if ShowInReport(rules.MaturityExperimental, false) {
		t.Error("experimental hidden by default")
	}
	if !ShowInReport(rules.MaturityExperimental, true) {
		t.Error("experimental shown with opt-in")
	}
	if !ShowInReport(rules.MaturityBeta, false) {
		t.Error("beta always in reports")
	}
}

func TestResolve(t *testing.T) {
	d := Resolve(rules.MaturityStable, 0.4, true, false)
	if !d.AutoDemoted || d.Inline || d.Effective != rules.MaturityBeta {
		t.Errorf("expected auto-demoted beta, not inline: %+v", d)
	}
	if !d.InReport {
		t.Error("demoted-to-beta still in report")
	}
}
