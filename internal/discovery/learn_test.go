package discovery

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
)

// codebergTraffic replays the exact request stream a live Forgejo served during
// the false-positive assessment: 1035 paths, in the order they were actually
// requested, by a developer reading projects, an indexer walking the estate and
// someone browsing profiles.
//
// Fitting this against invented traffic is how the first attempt got the
// thresholds wrong — synthetic paths had both the wrong cardinality and the
// wrong hit distribution, and the second matters as much as the first.
func codebergTraffic(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "codeberg_paths.txt"))
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}
	var paths []string
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line = strings.TrimSpace(line); line != "" {
			paths = append(paths, line)
		}
	}
	return paths
}

func TestPathLearner_CollapsesRealForgejoTraffic(t *testing.T) {
	traffic := codebergTraffic(t)

	l := NewPathLearner(LearnerConfig{})
	for _, p := range traffic {
		l.Template("default", p)
	}

	// Replay: the templates the catalog would hold once the learner has settled.
	// (Rows written before it settled are folded in separately by
	// retemplateEndpoints; this measures the steady state.)
	templates := map[string]int{}
	for _, p := range traffic {
		templates[l.Template("default", p)]++
	}

	// The bug was 152 catalog rows for 162 requests — an inventory that grew
	// with objects rather than with endpoints. This API has on the order of ten.
	if len(templates) > 15 {
		keys := make([]string, 0, len(templates))
		for k := range templates {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Errorf("%d distinct templates for %d requests, want <= 15:\n  %s",
			len(templates), len(traffic), strings.Join(keys, "\n  "))
	}

	// Both nested identifier positions must be learned — owner and repository.
	for _, want := range []string{
		"/api/v1/repos/{id}/{id}",
		"/api/v1/repos/{id}/{id}/commits",
		"/api/v1/users/{id}",
	} {
		if templates[want] == 0 {
			keys := make([]string, 0, len(templates))
			for k := range templates {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			t.Errorf("expected template %q, got:\n  %s", want, strings.Join(keys, "\n  "))
		}
	}

	// The resource level must survive: /api/v1/repos and /api/v1/users are real
	// names, and merging them would erase the distinction between the two.
	for _, p := range []string{"/api/v1/repos/x/y", "/api/v1/users/x"} {
		if got := l.Template("default", p); strings.HasPrefix(got, "/api/{id}") ||
			strings.HasPrefix(got, "/{id}") {
			t.Errorf("template %q collapsed a fixed prefix", got)
		}
	}
}

func TestPathLearner_KeepsResourceNames(t *testing.T) {
	// A wide API: 20 resources at one level, each genuinely used. This is above
	// MinDistinct on purpose — the distinct count alone must not be enough.
	resources := []string{"users", "repos", "orgs", "teams", "issues", "pulls",
		"releases", "tags", "branches", "commits", "hooks", "keys", "labels",
		"milestones", "notifications", "packages", "runners", "secrets",
		"settings", "webhooks"}

	l := NewPathLearner(LearnerConfig{})
	// Each resource is requested repeatedly, as real resources are.
	for round := 0; round < 10; round++ {
		for _, r := range resources {
			l.Template("default", "/api/v1/"+r)
		}
	}
	for _, r := range resources {
		got := l.Template("default", "/api/v1/"+r)
		if got != "/api/v1/"+r {
			t.Errorf("resource %q collapsed to %q — unrelated endpoints would merge", r, got)
		}
	}
}

func TestPathLearner_NeverUncollapses(t *testing.T) {
	l := NewPathLearner(LearnerConfig{})
	// Above MinDistinct + EvalWindow: a position cannot be judged before it has
	// served that much traffic, by design.
	for i := 0; i < 300; i++ {
		l.Template("default", fmt.Sprintf("/api/things/thing-%d", i))
	}
	first := l.Template("default", "/api/things/thing-0")
	if !strings.HasSuffix(first, "/{id}") {
		t.Fatalf("expected the position to have collapsed, got %q", first)
	}
	// Hammer one value: a template must not flap back to concrete just because
	// one identifier became popular.
	for i := 0; i < 500; i++ {
		if got := l.Template("default", "/api/things/thing-0"); got != first {
			t.Fatalf("template flapped to %q after %d repeats, want stable %q", got, i, first)
		}
	}
}

// Structure below an identifier position must survive the collapse, or
// /repos/{id}/issues and /repos/{id}/pulls become the same endpoint.
func TestPathLearner_PreservesStructureBelowIdentifier(t *testing.T) {
	l := NewPathLearner(LearnerConfig{})
	for i := 0; i < 200; i++ {
		l.Template("default", fmt.Sprintf("/repos/owner-%d/issues", i))
		l.Template("default", fmt.Sprintf("/repos/owner-%d/pulls", i))
		l.Template("default", fmt.Sprintf("/repos/owner-%d/releases", i))
	}
	for _, leaf := range []string{"issues", "pulls", "releases"} {
		got := l.Template("default", "/repos/owner-1/"+leaf)
		want := "/repos/{id}/" + leaf
		if got != want {
			t.Errorf("template = %q, want %q", got, want)
		}
	}
}

func TestPathLearner_ShapeBasedNormalisationStillApplies(t *testing.T) {
	l := NewPathLearner(LearnerConfig{})
	// One request, no learning possible — the regex pass must still work.
	if got := l.Template("default", "/api/v1/orders/42"); got != "/api/v1/orders/{id}" {
		t.Errorf("template = %q, want /api/v1/orders/{id}", got)
	}
	if got := l.Template("default", "/"); got != "/" {
		t.Errorf("root = %q, want /", got)
	}
}

func TestPathLearner_TenantsAreIndependent(t *testing.T) {
	l := NewPathLearner(LearnerConfig{})
	for i := 0; i < 300; i++ {
		l.Template("noisy", fmt.Sprintf("/api/things/thing-%d", i))
	}
	// The quiet tenant has shown one value at that position and must not inherit
	// the noisy tenant's conclusion.
	if got := l.Template("quiet", "/api/things/thing-0"); got != "/api/things/thing-0" {
		t.Errorf("quiet tenant template = %q, want the concrete path", got)
	}
}

// A path flood must cost bounded memory. At the cap the tree stops growing and
// degrades toward coarser templates instead.
func TestPathLearner_BoundedUnderPathFlood(t *testing.T) {
	l := NewPathLearner(LearnerConfig{MaxPositions: 500})
	for i := 0; i < 20000; i++ {
		l.Template("default", fmt.Sprintf("/a/%d-x/b/%d-y/c", i, i))
	}
	if n := l.Positions(); n > 600 {
		t.Errorf("nodes = %d, want bounded near the 500 cap", n)
	}
}

func TestPathLearner_ConcurrentUse(t *testing.T) {
	l := NewPathLearner(LearnerConfig{})
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				l.Template("default", fmt.Sprintf("/api/repos/owner-%d/repo-%d/commits", i%50, i))
			}
		}(w)
	}
	wg.Wait()
	if got := l.Template("default", "/api/repos/owner-1/repo-1/commits"); got != "/api/repos/{id}/{id}/commits" {
		t.Errorf("template = %q, want /api/repos/{id}/{id}/commits", got)
	}
}

func TestPathLearner_NilIsUsable(t *testing.T) {
	var l *PathLearner
	if got := l.Template("default", "/api/v1/orders/42"); got != "/api/v1/orders/{id}" {
		t.Errorf("nil learner = %q, want the shape-based template", got)
	}
	if l.Positions() != 0 {
		t.Error("nil learner should report zero positions")
	}
}
