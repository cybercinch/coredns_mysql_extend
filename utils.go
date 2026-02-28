package coredns_mysql_extend

import (
	"fmt"
	"strings"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
)

func MakeMysqlPlugin() *Mysql {
	return &Mysql{}
}

func MakeMessage(r *dns.Msg, answers []dns.RR, authority []dns.RR) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetReply(r)
	msg.Answer = answers
	msg.Ns = authority // Add authority section
	msg.Authoritative = true // Set AA flag
	return msg
}

func (m *Mysql) getDomainInfo(fqdn string) (int, string, string, error) {
	var (
		id    int
		host  string
		ok    bool
		zone  = fqdn
		items = strings.Split(zone, zoneSeparator)
	)
	// Only should case once but more. TODO
	for i := range items {
		zone = strings.Join(items[i:], zoneSeparator)
		id, ok = m.getZoneID(zone)
		host = strings.Join(items[:i], zoneSeparator)
		if host == "" {
			host = zoneSelf
		}
		if ok {
			logger.Debugf("Query zone %s in zone cache", zone)
			zoneFindCount.With(prometheus.Labels{"status": "success"}).Inc()
			return id, host, zone, nil
		}
	}
	logger.Warningf("Query zone %s not in zone cache, fqdn: %s", zone, fqdn)
	zoneFindCount.With(prometheus.Labels{"status": "fail"}).Inc()
	return id, host, zone, fmt.Errorf("zone %s not exist", fqdn)
}

func (m *Mysql) getZoneID(zone string) (int, bool) {
	m.zoneMu.RLock()
	id, ok := m.zoneMap[zone]
	m.zoneMu.RUnlock()
	return id, ok
}

func (m *Mysql) getBaseZone(fqdn string) string {
	if strings.Count(fqdn, zoneSeparator) > 1 {
		return strings.Join(strings.Split(fqdn, zoneSeparator)[1:], zoneSeparator)
	}
	return rootZone
}

func (m *Mysql) degradeQuery(record record) (dnsRecordInfo, bool) {
	m.degradeMu.RLock()
	dnsRecordInfo, ok := m.degradeCache[record]
	m.degradeMu.RUnlock()
	if !ok {
		degradeCacheCount.With(prometheus.Labels{"option": "query", "status": "fail", "fqdn": record.fqdn, "qtype": record.qType}).Inc()
	} else {
		degradeCacheCount.With(prometheus.Labels{"option": "query", "status": "success", "fqdn": record.fqdn, "qtype": record.qType}).Inc()
	}
	return dnsRecordInfo, ok
}

func (m *Mysql) degradeWrite(record record, dnsRecordInfo dnsRecordInfo) {
	m.degradeMu.Lock()
	m.degradeCache[record] = dnsRecordInfo
	m.degradeMu.Unlock()
}

func (m *Mysql) getRecords(zoneID int, host, zone, qType string) ([]record, error) {
	var records []record
	rows, err := m.db.Query(m.queryRecordSQL, zoneID, host, qType)
	if err != nil {
		logger.Errorf("Query record error: %s", err)
		return nil, err
	}
	for rows.Next() {
		var record record
		err := rows.Scan(&record.id, &record.zoneID, &record.name, &record.qType, &record.data, &record.ttl)
		if err != nil {
			queryDBCount.With(prometheus.Labels{"status": "fail"}).Inc()
			logger.Debugf("Failed to get records for domain %s from database: %s", record.fqdn, err)
			return nil, err
		}
		record.zoneName = zone
		if host == zoneSelf {
			record.fqdn = record.zoneName
		} else {
			record.fqdn = record.name + zoneSeparator + record.zoneName
		}
		records = append(records, record)
	}
	queryDBCount.With(prometheus.Labels{"status": "success"}).Inc()
	return records, nil
}

func (m *Mysql) makeAnswer(rrString string) (dns.RR, error) {
	rr, err := dns.NewRR(rrString)
	if err != nil {
		makeAnswerCount.With(prometheus.Labels{"status": "fail"}).Inc()
		logger.Errorf("Failed to create DNS record: %s", err)
	} else {
		makeAnswerCount.With(prometheus.Labels{"status": "success"}).Inc()
	}
	return rr, nil
}

// getAuthorityRecords fetches NS records for the zone to include in Authority section
func (m *Mysql) getAuthorityRecords(zoneID int, zone string) []dns.RR {
	var authority []dns.RR
	
	logDebugf("getAuthorityRecords called: zoneID=%d, zone='%s'", zoneID, zone)
	
	if zoneID <= 0 {
		logDebugf("getAuthorityRecords: invalid zoneID %d, returning empty authority", zoneID)
		return authority
	}
	
	// Fetch NS records for this zone (use zoneSelf "@" for apex records)
	nsRecords, err := m.getRecords(zoneID, zoneSelf, zone, "NS")
	if err != nil {
		logDebugf("Failed to fetch NS records for authority section: %v", err)
		return authority
	}
	
	logDebugf("Found %d NS records for authority section in zone %s", len(nsRecords), zone)
	
	for i, nsRecord := range nsRecords {
		nsRRString := fmt.Sprintf("%s %d IN NS %s", nsRecord.zoneName, nsRecord.ttl, nsRecord.data)
		logDebugf("Adding NS authority record %d/%d: %s", i+1, len(nsRecords), nsRRString)
		
		nsRR, err := m.makeAnswer(nsRRString)
		if err != nil {
			logErrorf("Failed to create NS authority record: %v", err)
			continue
		}
		authority = append(authority, nsRR)
	}
	
	logDebugf("getAuthorityRecords returning %d authority records for zone %s", len(authority), zone)
	return authority
}

// getGlueRecords fetches A/AAAA records for nameservers in the authority section
func (m *Mysql) getGlueRecords(authority []dns.RR) []dns.RR {
	var glueRecords []dns.RR
	
	logDebugf("getGlueRecords called with %d authority records", len(authority))
	
	for i, authRR := range authority {
		if authRR.Header().Rrtype != dns.TypeNS {
			continue
		}
		
		ns := authRR.(*dns.NS).Ns
		logDebugf("Looking for glue records for NS %d/%d: %s", i+1, len(authority), ns)
		
		// Try to find the zone that contains this nameserver
		nsZoneID, nsHost, nsZone, err := m.getDomainInfo(ns)
		if err != nil {
			logDebugf("No zone found for NS %s (external): %v", ns, err)
			continue // External nameserver, no glue needed
		}
		
		logDebugf("Found zone for NS %s -> zoneID=%d, host='%s', zone='%s'", ns, nsZoneID, nsHost, nsZone)
		
		// Fetch A records for this nameserver
		aRecords, err := m.getRecords(nsZoneID, nsHost, nsZone, "A")
		if err == nil {
			logDebugf("Found %d A glue records for NS %s", len(aRecords), ns)
			for j, aRecord := range aRecords {
				glueRRString := fmt.Sprintf("%s %d IN A %s", aRecord.fqdn, aRecord.ttl, aRecord.data)
				logDebugf("Adding A glue record %d/%d: %s", j+1, len(aRecords), glueRRString)
				
				glueRR, err := m.makeAnswer(glueRRString)
				if err == nil {
					glueRecords = append(glueRecords, glueRR)
				} else {
					logErrorf("Failed to create A glue record: %v", err)
				}
			}
		} else {
			logDebugf("No A glue records for NS %s: %v", ns, err)
		}
		
		// Fetch AAAA records for this nameserver
		aaaaRecords, err := m.getRecords(nsZoneID, nsHost, nsZone, "AAAA")
		if err == nil {
			logDebugf("Found %d AAAA glue records for NS %s", len(aaaaRecords), ns)
			for j, aaaaRecord := range aaaaRecords {
				glueRRString := fmt.Sprintf("%s %d IN AAAA %s", aaaaRecord.fqdn, aaaaRecord.ttl, aaaaRecord.data)
				logDebugf("Adding AAAA glue record %d/%d: %s", j+1, len(aaaaRecords), glueRRString)
				
				glueRR, err := m.makeAnswer(glueRRString)
				if err == nil {
					glueRecords = append(glueRecords, glueRR)
				} else {
					logErrorf("Failed to create AAAA glue record: %v", err)
				}
			}
		} else {
			logDebugf("No AAAA glue records for NS %s: %v", ns, err)
		}
	}
	
	logDebugf("getGlueRecords returning %d glue records", len(glueRecords))
	return glueRecords
}
