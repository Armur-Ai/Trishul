package diffmap

import "testing"

const sample = `diff --git a/src/app.go b/src/app.go
index 111..222 100644
--- a/src/app.go
+++ b/src/app.go
@@ -10,6 +10,8 @@ func handler() {
 	ctx := r.Context()
 	user := getUser(ctx)
+	// new line 12
+	exec(user.Input)
 	log.Println("done")
 	return
 }
diff --git a/README.md b/README.md
--- a/README.md
+++ b/README.md
@@ -1,2 +1,3 @@
 # Title
+added doc line 2
 text
`

func TestParse_ChangedLines(t *testing.T) {
	m := Parse(sample)
	// hunk starts at new line 10; context 10,11; +12,+13; then context.
	if !m.Changed("src/app.go", 12) || !m.Changed("src/app.go", 13) {
		t.Errorf("added lines 12,13 not detected")
	}
	if m.Changed("src/app.go", 10) || m.Changed("src/app.go", 11) {
		t.Error("context lines wrongly marked changed")
	}
	if m.Changed("src/app.go", 99) {
		t.Error("untouched line marked changed")
	}
	// README added line is new-file line 2
	if !m.Changed("README.md", 2) {
		t.Error("README added line 2 not detected")
	}
}

func TestParse_Files(t *testing.T) {
	m := Parse(sample)
	if len(m.Files()) != 2 {
		t.Errorf("files=%v", m.Files())
	}
}

func TestChanged_NilAndUnknown(t *testing.T) {
	var m *Map
	if m.Changed("x", 1) {
		t.Error("nil map should report not-changed")
	}
	if Parse("").Changed("x", 1) {
		t.Error("empty diff should report not-changed")
	}
}

func TestParse_DeletionOnlyFileDropped(t *testing.T) {
	d := `--- a/gone.go
+++ /dev/null
@@ -1,2 +0,0 @@
-line1
-line2
`
	m := Parse(d)
	if len(m.Files()) != 0 {
		t.Errorf("pure-deletion file should not appear: %v", m.Files())
	}
}
