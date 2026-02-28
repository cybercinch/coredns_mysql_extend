package coredns_mysql_extend

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

// cacheEntry is the on-disk representation of a single cache entry.
// Storing answers and extras separately avoids the fragile heuristic
// that previously tried to reconstruct the split from RR strings alone.
type cacheEntry struct {
	Answers []string `json:"answers"`
	Extras  []string `json:"extras"`
}

func (m *Mysql) rePing() {
	for {
		if err := m.db.Ping(); err != nil {
			time.Sleep(m.failHeartbeatTime)
			m.db.Close()
			newDB, err := m.openDB()
			if err == nil {
				m.db = newDB
			}
			logger.Errorf("Failed to ping database: %s", err)
			dbPingCount.With(prometheus.Labels{"status": "fail"}).Inc()
			continue
		}
		time.Sleep(m.successHeartbeatTime)

		logger.Debug("Success to ping database")
		dbPingCount.With(prometheus.Labels{"status": "success"}).Inc()
	}
}

func (m *Mysql) reGetZone() {
	for {
		zoneMap := make(map[string]int, 0)
		rows, err := m.db.Query(m.queryZoneSQL)
		if err != nil {
			logger.Errorf("Failed to query zones: %s", err)
			dbGetZoneCount.With(prometheus.Labels{"status": "fail"}).Inc()

			time.Sleep(m.failHeartbeatTime)
			continue
		}

		for rows.Next() {
			var zoneRecord zoneRecord
			err := rows.Scan(&zoneRecord.id, &zoneRecord.name)
			if err != nil {
				logger.Error(err)
			}
			zoneMap[zoneRecord.name] = zoneRecord.id
		}
		m.zoneMu.Lock()
		m.zoneMap = zoneMap
		m.zoneMu.Unlock()
		logger.Debugf("Success to query zones: %#v", zoneMap)
		dbGetZoneCount.With(prometheus.Labels{"status": "success"}).Inc()

		time.Sleep(m.successHeartbeatTime)
	}
}

// periodicDump flushes the degrade cache to disk on a fixed interval so that
// a crash or hard kill does not lose all accumulated state.
func (m *Mysql) periodicDump() {
	ticker := time.NewTicker(m.dumpInterval)
	defer ticker.Stop()
	for range ticker.C {
		logger.Debugf("Periodic cache flush triggered (interval=%s)", m.dumpInterval)
		m.dump2LocalData()
	}
}

// zoneForFQDN returns the zone name (with trailing dot) that owns fqdn,
// or an empty string when no match is found in zoneMap.
func (m *Mysql) zoneForFQDN(fqdn string) string {
	parts := strings.Split(strings.TrimSuffix(fqdn, "."), ".")
	for i := range parts {
		candidate := strings.Join(parts[i:], ".") + "."
		if _, ok := m.zoneMap[candidate]; ok {
			return candidate
		}
	}
	return ""
}

// zoneFilePath returns the path to the JSON file for a given zone.
// When dump_dir is configured it produces "<dump_dir>/<zone_no_dot>.json",
// otherwise it falls back to dump_file (single-file mode).
func (m *Mysql) zoneFilePath(zone string) string {
	if m.dumpDir == "" {
		return m.dumpFile
	}
	name := strings.TrimSuffix(zone, ".") + ".json"
	return filepath.Join(m.dumpDir, name)
}

// loadLocalData reads the degrade cache from disk.
// In per-zone mode it reads every *.json file under dump_dir.
// In single-file mode it reads dump_file.
func (m *Mysql) loadLocalData() {
	cache := make(map[record]dnsRecordInfo)

	if m.dumpDir != "" {
		entries, err := os.ReadDir(m.dumpDir)
		if err != nil {
			if !os.IsNotExist(err) {
				logger.Errorf("Failed to read dump_dir %s: %s", m.dumpDir, err)
			}
			loadLocalData.With(prometheus.Labels{"status": "fail"}).Inc()
			m.degradeMu.Lock()
			m.degradeCache = cache
			m.degradeMu.Unlock()
			return
		}
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			path := filepath.Join(m.dumpDir, entry.Name())
			m.loadZoneFile(path, cache)
		}
	} else {
		m.loadZoneFile(m.dumpFile, cache)
	}

	logger.Debugf("Loaded %d degrade cache entries from disk", len(cache))
	loadLocalData.With(prometheus.Labels{"status": "success"}).Inc()
	m.degradeMu.Lock()
	m.degradeCache = cache
	m.degradeMu.Unlock()
}

// loadZoneFile deserialises one JSON cache file into the provided cache map.
func (m *Mysql) loadZoneFile(path string, cache map[record]dnsRecordInfo) {
	content, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			logger.Errorf("Failed to read cache file %s: %s", path, err)
		}
		return
	}

	var zoneData map[string]cacheEntry
	if err := json.Unmarshal(content, &zoneData); err != nil {
		logger.Errorf("Failed to parse cache file %s: %s", path, err)
		return
	}

	for key, entry := range zoneData {
		parts := strings.SplitN(key, keySeparator, 2)
		if len(parts) != 2 {
			continue
		}
		fqdn, qType := parts[0], parts[1]
		rec := record{fqdn: fqdn, qType: qType}

		var answers []dns.RR
		for _, s := range entry.Answers {
			rr, err := dns.NewRR(s)
			if err == nil {
				answers = append(answers, rr)
			}
		}
		var extras []dns.RR
		for _, s := range entry.Extras {
			rr, err := dns.NewRR(s)
			if err == nil {
				extras = append(extras, rr)
			}
		}

		// Reconstruct rrStrings from both slices in original order
		allStrings := append(entry.Answers, entry.Extras...)
		cache[rec] = dnsRecordInfo{
			rrStrings: allStrings,
			answers:   answers,
			extras:    extras,
		}
	}
	logger.Debugf("Loaded cache file %s (%d entries)", path, len(zoneData))
}

// dump2LocalData serialises the degrade cache to disk.
// In per-zone mode, entries are grouped by zone and each zone gets its own file.
// In single-file mode, all entries go into dump_file.
func (m *Mysql) dump2LocalData() {
	m.degradeMu.RLock()
	// Snapshot the cache so we hold the lock as briefly as possible.
	snapshot := make(map[record]dnsRecordInfo, len(m.degradeCache))
	for k, v := range m.degradeCache {
		snapshot[k] = v
	}
	m.degradeMu.RUnlock()

	if m.dumpDir != "" {
		m.dumpPerZone(snapshot)
	} else {
		m.dumpSingleFile(snapshot)
	}
}

func (m *Mysql) dumpPerZone(snapshot map[record]dnsRecordInfo) {
	if err := os.MkdirAll(m.dumpDir, 0750); err != nil {
		logger.Errorf("Failed to create dump_dir %s: %s", m.dumpDir, err)
		dumpLocalData.With(prometheus.Labels{"status": "fail"}).Inc()
		return
	}

	// Group entries by zone.
	byZone := make(map[string]map[string]cacheEntry)
	for rec, info := range snapshot {
		zone := m.zoneForFQDN(rec.fqdn)
		if zone == "" {
			zone = "unknown"
		}
		if byZone[zone] == nil {
			byZone[zone] = make(map[string]cacheEntry)
		}
		key := fmt.Sprintf("%s%s%s", rec.fqdn, keySeparator, rec.qType)
		byZone[zone][key] = rrStringsToCacheEntry(info)
	}

	allOk := true
	for zone, zoneData := range byZone {
		path := m.zoneFilePath(zone)
		if err := writeJSON(path, zoneData); err != nil {
			logger.Errorf("Failed to write zone cache %s: %s", path, err)
			allOk = false
		} else {
			logger.Debugf("Wrote zone cache %s (%d entries)", path, len(zoneData))
		}
	}

	if allOk {
		dumpLocalData.With(prometheus.Labels{"status": "success"}).Inc()
	} else {
		dumpLocalData.With(prometheus.Labels{"status": "fail"}).Inc()
	}
}

func (m *Mysql) dumpSingleFile(snapshot map[record]dnsRecordInfo) {
	data := make(map[string]cacheEntry, len(snapshot))
	for rec, info := range snapshot {
		key := fmt.Sprintf("%s%s%s", rec.fqdn, keySeparator, rec.qType)
		data[key] = rrStringsToCacheEntry(info)
	}
	if err := writeJSON(m.dumpFile, data); err != nil {
		logger.Errorf("Failed to dump cache to %s: %s", m.dumpFile, err)
		dumpLocalData.With(prometheus.Labels{"status": "fail"}).Inc()
		return
	}
	logger.Debugf("Wrote single-file cache %s (%d entries)", m.dumpFile, len(data))
	dumpLocalData.With(prometheus.Labels{"status": "success"}).Inc()
}

func rrStringsToCacheEntry(info dnsRecordInfo) cacheEntry {
	answerStrings := make([]string, 0, len(info.answers))
	for _, rr := range info.answers {
		answerStrings = append(answerStrings, rr.String())
	}
	extraStrings := make([]string, 0, len(info.extras))
	for _, rr := range info.extras {
		extraStrings = append(extraStrings, rr.String())
	}
	return cacheEntry{Answers: answerStrings, Extras: extraStrings}
}

func writeJSON(path string, v interface{}) error {
	content, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, content, safeMode)
}

func (m *Mysql) openDB() (*sql.DB, error) {
	db, err := sql.Open("mysql", m.dsn)
	if err != nil {
		openMysqlCount.With(prometheus.Labels{"status": "fail"}).Inc()
		logger.Errorf("Failed to open database: %s", err)
	} else {
		// Config db connection pool
		db.SetConnMaxIdleTime(m.connMaxIdleTime)
		db.SetConnMaxLifetime(m.connMaxLifetime)
		db.SetMaxIdleConns(m.maxIdleConns)
		db.SetMaxOpenConns(m.maxOpenConns)
		openMysqlCount.With(prometheus.Labels{"status": "success"}).Inc()
		logger.Debug("Success to open database")
	}
	return db, err
}

func (m *Mysql) onStartup() error {
	logger.Debug("On start up")
	db, _ := m.openDB()
	m.db = db

	go m.rePing()
	go m.reGetZone()
	m.loadLocalData()
	go m.periodicDump()
	m.createTables()
	return nil
}

func (m *Mysql) onShutdown() error {
	logger.Debug("on shutdown")
	if m.db != nil {
		m.db.Close()
	}
	m.dump2LocalData()
	return nil
}
