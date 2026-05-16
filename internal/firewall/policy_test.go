package firewall

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRuleSetAllowed(t *testing.T) {
	rules := RuleSet{
		Allow: []string{"good*"},
		Deny:  []string{"good-bad"},
	}

	if ok, _ := rules.Allowed("good-tool"); !ok {
		t.Fatalf("expected allow for good-tool")
	}
	if ok, _ := rules.Allowed("good-bad"); ok {
		t.Fatalf("expected deny for good-bad")
	}
	if ok, _ := rules.Allowed("other"); ok {
		t.Fatalf("expected deny for other")
	}
}

func TestResourceRulesScheme(t *testing.T) {
	rules := ResourceRules{
		AllowSchemes: []string{"file", "local"},
		DenySchemes:  []string{"http", "https"},
	}

	if ok, _ := rules.Allowed("file:///tmp/test.txt"); !ok {
		t.Fatalf("expected allow for file URI")
	}
	if ok, _ := rules.Allowed("https://example.com"); ok {
		t.Fatalf("expected deny for https URI")
	}
	if ok, _ := rules.Allowed("relative/path"); !ok {
		t.Fatalf("expected allow for local path")
	}
}

func TestInspectorUsesExternalClassifier(t *testing.T) {
	var got struct {
		Provider string `json:"provider"`
		Kind     string `json:"kind"`
		Text     string `json:"text"`
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-EvalOps-Classifier") != "purplellama" {
			t.Fatalf("classifier header = %q", r.Header.Get("X-EvalOps-Classifier"))
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode classifier request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"score":      0.91,
			"label":      "prompt_injection",
			"flags":      []string{"jailbreak"},
			"categories": []string{"tool_control"},
		})
	}))
	t.Cleanup(server.Close)

	inspection := InspectorConfig{
		Enabled:   true,
		Threshold: 5,
		Classifier: ClassifierConfig{
			Provider:  "purplellama",
			URL:       server.URL,
			Headers:   map[string]string{"X-EvalOps-Classifier": "purplellama"},
			Threshold: 0.7,
		},
	}.inspectTexts(context.Background(), "prompt", []string{"ordinary text"})

	if got.Provider != "purplellama" || got.Kind != "prompt" || got.Text != "ordinary text" {
		t.Fatalf("classifier request = %#v", got)
	}
	if inspection.Score < 9 {
		t.Fatalf("inspection score = %d, want classifier contribution", inspection.Score)
	}
	if inspection.ClassifierProvider != "purplellama" || inspection.ClassifierScore != 0.91 || inspection.ClassifierLabel != "prompt_injection" {
		t.Fatalf("classifier fields = %#v", inspection)
	}
	if !containsString(inspection.Flags, "purplellama:prompt_injection") || !containsString(inspection.Flags, "purplellama:jailbreak") || !containsString(inspection.Flags, "purplellama:tool_control") {
		t.Fatalf("classifier flags = %#v", inspection.Flags)
	}
}

func TestClassifierBlockActionUsesFullContribution(t *testing.T) {
	inspection := ClassifierConfig{
		Provider:  "purplellama",
		Threshold: 0.7,
	}.inspectionFromResponse(classifierResponse{
		Action: "block",
	})

	if inspection.Score != 10 {
		t.Fatalf("inspection score = %d, want 10", inspection.Score)
	}
	if inspection.ClassifierProvider != "purplellama" || inspection.ClassifierScore != 0 {
		t.Fatalf("classifier fields = %#v", inspection)
	}
	if !containsString(inspection.Flags, "purplellama:flagged") {
		t.Fatalf("classifier flags = %#v", inspection.Flags)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
