package coredns_mysql_extend

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/coredns/coredns/plugin"
	"github.com/prometheus/client_golang/prometheus"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	_ "github.com/go-sql-driver/mysql"
	"github.com/miekg/dns"
)

var logger = clog.NewWithPlugin(pluginName)

func (m *Mysql) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var records []record
	state := request.Request{W: w, Req: r}
	answers := make([]dns.RR, 0)
	extras := make([]dns.RR, 0) // New slice for glue records
	rrStrings := make([]string, 0)

	// Get domain name
	qName := state.Name()
	qType := state.Type()
	degradeRecord := record{fqdn: qName, qType: qType}

	logger.Debugf("New query: FQDN %s type %s", qName, qType)

	// Query zone cache
	zoneID, host, zone, err := m.getDomainInfo(qName)

	// Zone not exist, maybe db error cause no zone, goto degrade entrypoint
	if err != nil {
		goto DegradeEntrypoint
	}

	// Query DB, full match
	records, err = m.getRecords(zoneID, host, zone, qType)
	if err != nil {
		goto DegradeEntrypoint
	}

	// Try query CNAME type of record
	if len(records) == zero {
		cnameRecords, err := m.getRecords(zoneID, host, zone, cnameQtype)
		if err != nil {
			goto DegradeEntrypoint
		}
		for _, cnameRecord := range cnameRecords {
			cnameZoneID, cnameHost, cnameZone, err := m.getDomainInfo(cnameRecord.data)

			if err != nil {
				goto DegradeEntrypoint
			}

			rrString := fmt.Sprintf("%s %d IN %s %s", qName, cnameRecord.ttl, cnameRecord.qType, cnameRecord.data)
			rrStrings = append(rrStrings, rrString)
			rr, err := m.makeAnswer(rrString)
			if err != nil {
				continue
			}
			answers = append(answers, rr)

			cname2Records, err := m.getRecords(cnameZoneID, cnameHost, cnameZone, qType)

			if err != nil {
				goto DegradeEntrypoint
			}

			for _, cname2Record := range cname2Records {
				rrString := fmt.Sprintf("%s %d IN %s %s", cname2Record.fqdn, cname2Record.ttl, cname2Record.qType, cname2Record.data)
				rrStrings = append(rrStrings, rrString)
				rr, err := m.makeAnswer(rrString)
				if err != nil {
					continue
				}
				answers = append(answers, rr)
			}
		}
	}
	// Process records
	for _, record := range records {
		rrString := fmt.Sprintf("%s %d IN %s %s", record.fqdn, record.ttl, record.qType, record.data)
		rr, err := m.makeAnswer(rrString)
		if err != nil {
			continue
		}
		answers = append(answers, rr)
		rrStrings = append(rrStrings, rrString)

		// Handle NS records
		if rr.Header().Rrtype == dns.TypeNS {
			ns := rr.(*dns.NS).Ns

			// Look up the nameserver's zone
			if nsZoneID, nsHost, nsZone, err := m.getDomainInfo(ns); err == nil {
				// NEW: Get the actual TTL from the nameserver's zone records
				aRecords, err := m.getRecords(nsZoneID, nsHost, nsZone, "A")
				if err == nil {
					for _, aRec := range aRecords {
						// Use the TTL from the nameserver's A record, not the NS record's TTL
						aRRString := fmt.Sprintf("%s %d IN A %s", ns, aRec.ttl, aRec.data)
						aRR, err := m.makeAnswer(aRRString)
						if err == nil {
							extras = append(extras, aRR)
							rrStrings = append(rrStrings, aRRString)
						}
					}
				}

				aaaaRecords, err := m.getRecords(nsZoneID, nsHost, nsZone, "AAAA")
				if err == nil {
					for _, aaaaRec := range aaaaRecords {
						// Use the TTL from the nameserver's AAAA record
						aaaaRRString := fmt.Sprintf("%s %d IN AAAA %s", ns, aaaaRec.ttl, aaaaRec.data)
						aaaaRR, err := m.makeAnswer(aaaaRRString)
						if err == nil {
							extras = append(extras, aaaaRR)
							rrStrings = append(rrStrings, aaaaRRString)
						}
					}
				}
			}
		}
	}

	// Handle wildcard domains
	if len(answers) == zero && strings.Count(qName, zoneSeparator) > 1 {
		baseZone := m.getBaseZone(qName)
		zoneID, ok := m.getZoneID(baseZone)
		wildcardName := wildcard + zoneSeparator + baseZone
		if !ok {
			logger.Debugf("Failed to get zone %s from database: %s", qName, err)
			goto DegradeEntrypoint
		}
		records, err := m.getRecords(zoneID, wildcard, zone, qType)
		if err != nil {
			logger.Debugf("Failed to get records for domain %s from database: %s", wildcardName, err)
			goto DegradeEntrypoint
		}

		for _, record := range records {
			rrString := fmt.Sprintf("%s %d IN %s %s", qName, record.ttl, record.qType, record.data)
			rr, err := m.makeAnswer(rrString)
			rrStrings = append(rrStrings, rrString)
			if err != nil {
				continue
			}
			answers = append(answers, rr)
		}
	}

	// Common Entrypoint
	if len(answers) > zero {
		msg := MakeMessage(r, answers)
		// NEW: Add glue records to the additional section
		msg.Extra = extras
		err = w.WriteMsg(msg)
		if err != nil {
			logger.Error(err)
		}
		dnsRecordInfo := dnsRecordInfo{rrStrings: rrStrings, response: answers}
		if cacheDnsRecordResponse, ok := m.degradeQuery(degradeRecord); !ok || !reflect.DeepEqual(cacheDnsRecordResponse, dnsRecordInfo.response) {
			m.degradeWrite(degradeRecord, dnsRecordInfo)
			logger.Debugf("CommonEntrypoint Add degrade record %#v, dnsRecordInfo %#v", degradeRecord, dnsRecordInfo)
			degradeCacheCount.With(prometheus.Labels{"status": "success", "option": "update", "fqdn": degradeRecord.fqdn, "qtype": degradeRecord.qType}).Inc()
			return dns.RcodeSuccess, nil
		}
		return dns.RcodeSuccess, nil
	}

	logger.Debug("Call next plugin")
	return plugin.NextOrFailure(m.Name(), m.Next, ctx, w, r)

	// Degrade Entrypoint
DegradeEntrypoint:
	if answers, ok := m.degradeQuery(degradeRecord); ok {
		msg := MakeMessage(r, answers)
		err = w.WriteMsg(msg)
		if err != nil {
			logger.Error(err)
		}
		logger.Debugf("DegradeEntrypoint: Query degrade record %#v", degradeRecord)
		return dns.RcodeSuccess, nil
	}
	logger.Debug("Call next plugin")
	callNextPluginCount.With(prometheus.Labels{"fqdn": qName, "qtype": qType}).Inc()
	return plugin.NextOrFailure(m.Name(), m.Next, ctx, w, r)
}
