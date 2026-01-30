package firewall

import "testing"

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
