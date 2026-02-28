package coredns_mysql_extend

// Run with the race detector to catch concurrent map access:
//   go test -race ./...

import (
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// newTestMysql returns a minimal Mysql instance suitable for unit tests.
// No database connection is established.
func newTestMysql(t *testing.T) *Mysql {
	t.Helper()
	return &Mysql{
		mysqlConfig: &mysqlConfig{
			dumpFile:     filepath.Join(t.TempDir(), "cache.json"),
			dumpDir:      "",
			dumpInterval: time.Minute,
		},
		degradeCache: make(map[record]dnsRecordInfo),
		zoneMap:      map[string]int{"example.com.": 1, "other.net.": 2},
	}
}

// makeARecord builds a simple A dns.RR for use in tests.
func makeARecord(name, ip string, ttl uint32) dns.RR {
	return &dns.A{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
		A:   net.ParseIP(ip).To4(),
	}
}

// makeNSRecord builds a simple NS dns.RR for use in tests.
func makeNSRecord(name, ns string, ttl uint32) dns.RR {
	return &dns.NS{
		Hdr: dns.RR_Header{Name: name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: ttl},
		Ns:  ns,
	}
}

// ---------------------------------------------------------------------------
// Concurrency tests — intended to be run with: go test -race ./...
// ---------------------------------------------------------------------------

func TestDegradeCacheConcurrentReadWrite(t *testing.T) {
	m := newTestMysql(t)

	rec := record{fqdn: "example.com.", qType: "A"}
	info := dnsRecordInfo{
		rrStrings: []string{"example.com. 3600 IN A 192.0.2.1"},
		answers:   []dns.RR{makeARecord("example.com.", "192.0.2.1", 3600)},
	}

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			m.degradeWrite(rec, info)
		}()
		go func() {
			defer wg.Done()
			m.degradeQuery(rec)
		}()
	}

	wg.Wait()
}

func TestZoneMapConcurrentReadWrite(t *testing.T) {
	m := newTestMysql(t)

	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines * 2)

	// Simulate reGetZone replacing the map while ServeDNS goroutines read it.
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			fresh := map[string]int{"example.com.": 1, "new.zone.": 3}
			m.zoneMu.Lock()
			m.zoneMap = fresh
			m.zoneMu.Unlock()
		}()
		go func() {
			defer wg.Done()
			m.getZoneID("example.com.")
		}()
	}

	wg.Wait()
}

// ---------------------------------------------------------------------------
// Serialisation round-trip — single file
// ---------------------------------------------------------------------------

func TestCacheRoundTripSingleFile(t *testing.T) {
	m := newTestMysql(t)

	answer := makeARecord("example.com.", "192.0.2.1", 3600)
	extra := makeARecord("ns1.example.com.", "192.0.2.10", 3600)

	rec := record{fqdn: "example.com.", qType: "A"}
	m.degradeCache[rec] = dnsRecordInfo{
		answers: []dns.RR{answer},
		extras:  []dns.RR{extra},
	}

	m.dump2LocalData()

	// Load into a fresh instance pointing at the same file.
	m2 := newTestMysql(t)
	m2.mysqlConfig.dumpFile = m.mysqlConfig.dumpFile
	m2.loadLocalData()

	got, ok := m2.degradeQuery(rec)
	if !ok {
		t.Fatal("cache entry not found after reload")
	}
	if len(got.answers) != 1 {
		t.Errorf("answers: want 1, got %d", len(got.answers))
	}
	if len(got.extras) != 1 {
		t.Errorf("extras: want 1, got %d", len(got.extras))
	}
	if got.answers[0].String() != answer.String() {
		t.Errorf("answer mismatch:\n want %s\n  got %s", answer, got.answers[0])
	}
	if got.extras[0].String() != extra.String() {
		t.Errorf("extra mismatch:\n want %s\n  got %s", extra, got.extras[0])
	}
}

// ---------------------------------------------------------------------------
// Serialisation round-trip — per-zone files
// ---------------------------------------------------------------------------

func TestCacheRoundTripPerZone(t *testing.T) {
	dir := t.TempDir()
	m := newTestMysql(t)
	m.mysqlConfig.dumpDir = dir

	recA := record{fqdn: "example.com.", qType: "A"}
	recNS := record{fqdn: "other.net.", qType: "NS"}

	m.degradeCache[recA] = dnsRecordInfo{
		answers: []dns.RR{makeARecord("example.com.", "10.0.0.1", 3600)},
	}
	m.degradeCache[recNS] = dnsRecordInfo{
		answers: []dns.RR{makeNSRecord("other.net.", "ns1.other.net.", 86400)},
	}

	m.dump2LocalData()

	// Expect one file per zone.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading dump dir: %v", err)
	}
	if len(entries) != 2 {
		t.Errorf("want 2 zone files, got %d", len(entries))
	}

	// Reload and verify both entries survive.
	m2 := newTestMysql(t)
	m2.mysqlConfig.dumpDir = dir
	m2.loadLocalData()

	if _, ok := m2.degradeQuery(recA); !ok {
		t.Error("example.com. A record not found after per-zone reload")
	}
	if _, ok := m2.degradeQuery(recNS); !ok {
		t.Error("other.net. NS record not found after per-zone reload")
	}
}

// ---------------------------------------------------------------------------
// Per-zone files are isolated — a bad file doesn't poison other zones
// ---------------------------------------------------------------------------

func TestCachePerZoneIsolation(t *testing.T) {
	dir := t.TempDir()

	// Write a corrupt file for one zone.
	if err := os.WriteFile(filepath.Join(dir, "broken.zone.json"), []byte("not json"), 0640); err != nil {
		t.Fatal(err)
	}

	// Write a valid file for another zone.
	valid := `{"valid.zone.:A":{"answers":["valid.zone. 3600 IN A 1.2.3.4"],"extras":[]}}`
	if err := os.WriteFile(filepath.Join(dir, "valid.zone.json"), []byte(valid), 0640); err != nil {
		t.Fatal(err)
	}

	m := newTestMysql(t)
	m.mysqlConfig.dumpDir = dir
	m.loadLocalData()

	rec := record{fqdn: "valid.zone.", qType: "A"}
	if _, ok := m.degradeQuery(rec); !ok {
		t.Error("valid zone entry should be present despite broken zone file")
	}
}

// ---------------------------------------------------------------------------
// zoneForFQDN
// ---------------------------------------------------------------------------

func TestZoneForFQDN(t *testing.T) {
	m := newTestMysql(t) // zoneMap: example.com.=1, other.net.=2

	cases := []struct {
		fqdn string
		want string
	}{
		{"example.com.", "example.com."},
		{"www.example.com.", "example.com."},
		{"deep.sub.example.com.", "example.com."},
		{"other.net.", "other.net."},
		{"host.other.net.", "other.net."},
		{"unknown.org.", ""},
	}

	for _, tc := range cases {
		got := m.zoneForFQDN(tc.fqdn)
		if got != tc.want {
			t.Errorf("zoneForFQDN(%q) = %q, want %q", tc.fqdn, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// answers/extras split is preserved exactly across dump→load
// ---------------------------------------------------------------------------

func TestAnswersExtrasSplitPreserved(t *testing.T) {
	m := newTestMysql(t)

	answers := []dns.RR{
		makeARecord("example.com.", "10.1.1.1", 3600),
		makeARecord("example.com.", "10.1.1.2", 3600),
	}
	extras := []dns.RR{
		makeARecord("ns1.example.com.", "10.1.1.10", 3600),
	}

	rec := record{fqdn: "example.com.", qType: "A"}
	m.degradeCache[rec] = dnsRecordInfo{answers: answers, extras: extras}

	m.dump2LocalData()

	m2 := newTestMysql(t)
	m2.mysqlConfig.dumpFile = m.mysqlConfig.dumpFile
	m2.loadLocalData()

	got, ok := m2.degradeQuery(rec)
	if !ok {
		t.Fatal("entry missing after reload")
	}
	if len(got.answers) != 2 {
		t.Errorf("answers: want 2, got %d", len(got.answers))
	}
	if len(got.extras) != 1 {
		t.Errorf("extras: want 1, got %d", len(got.extras))
	}
	// ns1 must land in extras, not answers.
	if got.extras[0].(*dns.A).A.String() != "10.1.1.10" {
		t.Errorf("glue IP mismatch: got %s", got.extras[0].(*dns.A).A)
	}
}
