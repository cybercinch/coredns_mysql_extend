package coredns_mysql_extend

// Tests for the self-healing cache repair flow when a zone file is corrupted
// but the MySQL backend is available.
//
// Repair sequence:
//  1. loadLocalData  – corrupt file is skipped → cache miss for affected zone
//  2. ServeDNS       – successful DB query calls degradeWrite → in-memory cache healed
//  3. dump2LocalData – periodic/shutdown flush overwrites the corrupt file
//  4. Next restart   – loadLocalData reads the repaired file successfully

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/miekg/dns"
)

// ---------------------------------------------------------------------------
// Stage 1 – corrupt file produces a cache miss, not a crash or stale data
// ---------------------------------------------------------------------------

func TestCorruptFileProducesCacheMiss(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "example.com.json"), []byte("not json at all"), 0640); err != nil {
		t.Fatal(err)
	}

	m := newTestMysql(t)
	m.mysqlConfig.dumpDir = dir
	m.loadLocalData()

	rec := record{fqdn: "example.com.", qType: "A"}
	if _, ok := m.degradeQuery(rec); ok {
		t.Error("expected cache miss for zone with corrupt file, got a hit")
	}
}

func TestCorruptSingleFileProducesCacheMiss(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(tmp, []byte("{bad json"), 0640); err != nil {
		t.Fatal(err)
	}

	m := newTestMysql(t)
	m.mysqlConfig.dumpFile = tmp
	m.loadLocalData()

	rec := record{fqdn: "example.com.", qType: "A"}
	if _, ok := m.degradeQuery(rec); ok {
		t.Error("expected cache miss after corrupt single file, got a hit")
	}
}

// ---------------------------------------------------------------------------
// Stage 2 – degradeWrite (called by ServeDNS on successful DB query) heals
//            the in-memory cache while the file is still corrupt on disk
// ---------------------------------------------------------------------------

func TestDBRepopulatesInMemoryCache(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "example.com.json"), []byte("corrupted"), 0640); err != nil {
		t.Fatal(err)
	}

	m := newTestMysql(t)
	m.mysqlConfig.dumpDir = dir
	m.loadLocalData()

	rec := record{fqdn: "example.com.", qType: "A"}

	// Simulate a successful DB query: ServeDNS calls degradeWrite.
	fresh := dnsRecordInfo{
		answers: []dns.RR{makeARecord("example.com.", "10.0.0.1", 3600)},
	}
	m.degradeWrite(rec, fresh)

	got, ok := m.degradeQuery(rec)
	if !ok {
		t.Fatal("cache should be populated after degradeWrite (simulated DB success)")
	}
	if len(got.answers) != 1 || got.answers[0].(*dns.A).A.String() != "10.0.0.1" {
		t.Errorf("unexpected answer: %v", got.answers)
	}
}

// ---------------------------------------------------------------------------
// Stage 3 – dump2LocalData overwrites the corrupt file with valid JSON
// ---------------------------------------------------------------------------

func TestDumpOverwritesCorruptZoneFile(t *testing.T) {
	dir := t.TempDir()
	zonePath := filepath.Join(dir, "example.com.json")
	if err := os.WriteFile(zonePath, []byte("corrupted"), 0640); err != nil {
		t.Fatal(err)
	}

	m := newTestMysql(t)
	m.mysqlConfig.dumpDir = dir
	m.loadLocalData() // skips corrupt file

	// DB comes back, ServeDNS heals the in-memory cache.
	rec := record{fqdn: "example.com.", qType: "A"}
	m.degradeWrite(rec, dnsRecordInfo{
		answers: []dns.RR{makeARecord("example.com.", "10.0.0.1", 3600)},
	})

	// Periodic/shutdown dump runs.
	m.dump2LocalData()

	// The file must now be valid JSON.
	content, err := os.ReadFile(zonePath)
	if err != nil {
		t.Fatalf("zone file missing after dump: %v", err)
	}
	var parsed map[string]cacheEntry
	if err := json.Unmarshal(content, &parsed); err != nil {
		t.Fatalf("zone file still invalid JSON after repair dump: %v\ncontent: %s", err, content)
	}
	if len(parsed) == 0 {
		t.Error("zone file is valid JSON but empty after repair dump")
	}
}

func TestDumpOverwritesCorruptSingleFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(tmp, []byte("{bad"), 0640); err != nil {
		t.Fatal(err)
	}

	m := newTestMysql(t)
	m.mysqlConfig.dumpFile = tmp
	m.loadLocalData()

	rec := record{fqdn: "example.com.", qType: "A"}
	m.degradeWrite(rec, dnsRecordInfo{
		answers: []dns.RR{makeARecord("example.com.", "10.0.0.1", 3600)},
	})
	m.dump2LocalData()

	content, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatalf("single cache file missing after dump: %v", err)
	}
	var parsed map[string]cacheEntry
	if err := json.Unmarshal(content, &parsed); err != nil {
		t.Fatalf("single cache file still invalid after repair dump: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Stage 4 – full end-to-end: corrupt → miss → heal → dump → reload → hit
// ---------------------------------------------------------------------------

func TestFullRepairCyclePerZone(t *testing.T) {
	dir := t.TempDir()

	// Start with a corrupt zone file.
	if err := os.WriteFile(filepath.Join(dir, "example.com.json"), []byte("garbage"), 0640); err != nil {
		t.Fatal(err)
	}

	m := newTestMysql(t)
	m.mysqlConfig.dumpDir = dir

	// Stage 1: load — corrupt file skipped.
	m.loadLocalData()
	rec := record{fqdn: "example.com.", qType: "A"}
	if _, ok := m.degradeQuery(rec); ok {
		t.Fatal("stage 1 failed: expected cache miss after corrupt file")
	}

	// Stage 2: DB query succeeds, ServeDNS heals in-memory cache.
	m.degradeWrite(rec, dnsRecordInfo{
		answers: []dns.RR{makeARecord("example.com.", "192.168.1.1", 3600)},
	})
	if _, ok := m.degradeQuery(rec); !ok {
		t.Fatal("stage 2 failed: cache should be populated after degradeWrite")
	}

	// Stage 3: periodic dump overwrites the corrupt file.
	m.dump2LocalData()

	// Stage 4: fresh restart loads the repaired file successfully.
	m2 := newTestMysql(t)
	m2.mysqlConfig.dumpDir = dir
	m2.loadLocalData()

	got, ok := m2.degradeQuery(rec)
	if !ok {
		t.Fatal("stage 4 failed: repaired zone file not loaded on restart")
	}
	if len(got.answers) != 1 {
		t.Errorf("stage 4: want 1 answer, got %d", len(got.answers))
	}
	if got.answers[0].(*dns.A).A.String() != "192.168.1.1" {
		t.Errorf("stage 4: unexpected IP %s", got.answers[0].(*dns.A).A)
	}
}

func TestFullRepairCycleSingleFile(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "cache.json")
	if err := os.WriteFile(tmp, []byte("garbage"), 0640); err != nil {
		t.Fatal(err)
	}

	m := newTestMysql(t)
	m.mysqlConfig.dumpFile = tmp

	m.loadLocalData()
	rec := record{fqdn: "example.com.", qType: "A"}
	if _, ok := m.degradeQuery(rec); ok {
		t.Fatal("stage 1 failed: expected cache miss")
	}

	m.degradeWrite(rec, dnsRecordInfo{
		answers: []dns.RR{makeARecord("example.com.", "192.168.1.1", 3600)},
	})
	m.dump2LocalData()

	m2 := newTestMysql(t)
	m2.mysqlConfig.dumpFile = tmp
	m2.loadLocalData()

	if _, ok := m2.degradeQuery(rec); !ok {
		t.Fatal("stage 4 failed: repaired single file not loaded on restart")
	}
}

// ---------------------------------------------------------------------------
// Partial corruption — only one zone file is corrupt, others survive intact
// ---------------------------------------------------------------------------

func TestPartialCorruptionOnlyAffectsOneZone(t *testing.T) {
	dir := t.TempDir()

	// Corrupt file for one zone.
	if err := os.WriteFile(filepath.Join(dir, "example.com.json"), []byte("garbage"), 0640); err != nil {
		t.Fatal(err)
	}

	// Valid file for another zone.
	valid := map[string]cacheEntry{
		"other.net.:NS": {Answers: []string{"other.net. 86400 IN NS ns1.other.net."}, Extras: []string{}},
	}
	content, _ := json.Marshal(valid)
	if err := os.WriteFile(filepath.Join(dir, "other.net.json"), content, 0640); err != nil {
		t.Fatal(err)
	}

	m := newTestMysql(t)
	m.mysqlConfig.dumpDir = dir
	m.loadLocalData()

	// Corrupt zone: miss.
	recA := record{fqdn: "example.com.", qType: "A"}
	if _, ok := m.degradeQuery(recA); ok {
		t.Error("expected cache miss for corrupt zone")
	}

	// Healthy zone: hit.
	recNS := record{fqdn: "other.net.", qType: "NS"}
	if _, ok := m.degradeQuery(recNS); !ok {
		t.Error("expected cache hit for healthy zone despite other zone being corrupt")
	}
}
