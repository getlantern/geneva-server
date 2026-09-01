package nftables

import (
	"strings"
	"testing"
)

// nftCounterJSON is real `nft -j list counters` output, kept verbatim so the
// parser is tested against the format the binary actually emits — including the
// metainfo entry that carries no counter.
const nftCounterJSON = `{"nftables": [{"metainfo": {"version": "1.0.6", "release_name": "Lester Gooch #5", "json_schema_version": 1}}, ` +
	`{"counter": {"family": "inet", "name": "rst", "table": "geneva_server", "handle": 3, "packets": 7, "bytes": 420}}, ` +
	`{"counter": {"family": "inet", "name": "syn", "table": "geneva_server", "handle": 4, "packets": 12, "bytes": 720}}, ` +
	`{"counter": {"family": "inet", "name": "data", "table": "geneva_server", "handle": 6, "packets": 3400, "bytes": 4964000}}]}`

func TestParseCounters(t *testing.T) {
	counts, err := parseCounters([]byte(nftCounterJSON))
	if err != nil {
		t.Fatalf("parseCounters: %v", err)
	}
	for name, want := range map[string]uint64{"rst": 7, "syn": 12, "data": 3400} {
		if counts[name] != want {
			t.Errorf("%s = %d, want %d", name, counts[name], want)
		}
	}
	if _, ok := counts["metainfo"]; ok {
		t.Error("metainfo entry parsed as a counter")
	}
	if len(counts) != 3 {
		t.Errorf("got %d counters, want 3: %v", len(counts), counts)
	}
}

func TestParseCountersRejectsGarbage(t *testing.T) {
	if _, err := parseCounters([]byte("not json")); err == nil {
		t.Error("garbage accepted")
	}
}

// TestCensorRulesetShape pins the classification chain: the counters exist, the
// jump is installed, precedence is the order the userspace classifier uses, and
// every rule returns so a packet lands in exactly one bucket.
func TestCensorRulesetShape(t *testing.T) {
	m := New(Config{
		Table: "geneva_censor", Port: 8080, OutQueue: 100, InQueue: 101, Mark: 0x67656e,
		Outbound: Selector{Flags: []FlagMatch{{Mask: 0xff, Value: 0x02}}},
		Censor:   true,
	})
	rs := m.Ruleset()

	for _, c := range CensorCounters {
		if !strings.Contains(rs, "counter "+c+" {}") {
			t.Errorf("counter %q not declared:\n%s", c, rs)
		}
	}
	if !strings.Contains(rs, "jump "+censorChain) {
		t.Errorf("classification jump missing:\n%s", rs)
	}

	// Precedence: a RST is a RST even though it also has ACK set, so the order
	// of the rules is what makes the buckets disjoint.
	order := []string{`name "rst"`, `name "syn"`, `name "fin"`, `name "data"`, `name "ack_only"`}
	at := -1
	for _, want := range order {
		i := strings.Index(rs, want)
		if i < 0 {
			t.Fatalf("rule %s missing:\n%s", want, rs)
		}
		if i < at {
			t.Errorf("rule %s is out of precedence order:\n%s", want, rs)
		}
		at = i
	}
	// Every counter rule must return, or a packet would fall through and be
	// counted twice.
	for _, line := range strings.Split(rs, "\n") {
		if strings.Contains(line, "counter name") && !strings.Contains(line, "return") {
			t.Errorf("counter rule does not return: %q", strings.TrimSpace(line))
		}
	}
	// And the counters must never queue anything: that is the entire point.
	for _, line := range strings.Split(rs, "\n") {
		if strings.Contains(line, "counter name") && strings.Contains(line, "queue") {
			t.Errorf("counter rule queues a packet: %q", strings.TrimSpace(line))
		}
	}
}

// TestCensorCountersNeverKeepATableAlive pins that counting rides along with a
// table that exists for steering and never keeps one alive on its own — a box
// with no strategy has nothing of ours in the kernel.
func TestCensorCountersNeverKeepATableAlive(t *testing.T) {
	m := New(Config{Table: "geneva_idle_censor", Port: 8080, OutQueue: 100, InQueue: 101, Mark: 0x67656e, Censor: true})
	if !m.Idle() {
		t.Error("a censor-only manager is not idle")
	}
	if rs := m.Ruleset(); rs != "" {
		t.Errorf("censor counters produced a ruleset with nothing to steer:\n%s", rs)
	}
}
