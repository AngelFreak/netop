package firewall

import "testing"

func TestNATRules_WithInternalIface(t *testing.T) {
	rules := natRules("wlan0", "eth0")
	if len(rules) != 3 {
		t.Fatalf("expected 3 rules with an internal iface, got %d", len(rules))
	}

	// MASQUERADE on the outbound interface.
	if rules[0].table != "nat" || rules[0].chain != "POSTROUTING" {
		t.Errorf("rule[0] = %s/%s, want nat/POSTROUTING", rules[0].table, rules[0].chain)
	}
	if !containsPair(rules[0].rule, "-o", "eth0") || !contains(rules[0].rule, "MASQUERADE") {
		t.Errorf("MASQUERADE rule = %v, want -o eth0 ... MASQUERADE", rules[0].rule)
	}

	// FORWARD from the internal interface.
	if !containsPair(rules[1].rule, "-i", "wlan0") {
		t.Errorf("forward-in rule = %v, want -i wlan0", rules[1].rule)
	}
	// FORWARD established/related back to the internal interface.
	if !containsPair(rules[2].rule, "-o", "wlan0") || !contains(rules[2].rule, "RELATED,ESTABLISHED") {
		t.Errorf("forward-established rule = %v, want -o wlan0 ... RELATED,ESTABLISHED", rules[2].rule)
	}
}

// When the internal interface is unknown (empty), only the MASQUERADE rule
// applies — so a teardown with no known internal iface still removes it.
func TestNATRules_EmptyInternalIface(t *testing.T) {
	rules := natRules("", "eth0")
	if len(rules) != 1 {
		t.Fatalf("expected only the MASQUERADE rule with an empty internal iface, got %d", len(rules))
	}
	if rules[0].chain != "POSTROUTING" || !contains(rules[0].rule, "MASQUERADE") {
		t.Errorf("rule = %v, want the MASQUERADE rule", rules[0].rule)
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func containsPair(s []string, a, b string) bool {
	for i := 0; i+1 < len(s); i++ {
		if s[i] == a && s[i+1] == b {
			return true
		}
	}
	return false
}
