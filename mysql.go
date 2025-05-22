package coredns_mysql_extend

import (
	"context"
	"fmt"
	"reflect"
	"strings"

	"github.com/coredns/coredns/plugin"

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

	// Process records and collect glue records
	for _, record := range records {
		rrString := fmt.Sprintf("%s %d IN %s %s", record.fqdn, record.ttl, record.qType, record.data)
		rr, err := m.makeAnswer(rrString)
		if err != nil {
			continue
		}
		answers = append(answers, rr)
		rrStrings = append(rrStrings, rrString)

		// Handle NS records - collect glue records
		if rr.Header().Rrtype == dns.TypeNS {
			ns := rr.(*dns.NS).Ns
			logger.Debugf("Looking for glue records for NS: %s", ns)
			if nsZoneID, nsHost, nsZone, err := m.getDomainInfo(ns); err == nil {
				// Query for A and AAAA records specifically
				aRecords, err := m.getRecords(nsZoneID, nsHost, nsZone, "A")
				if err == nil {
					for _, glueRec := range aRecords {
						glueRRString := fmt.Sprintf("%s %d IN %s %s",
							glueRec.fqdn,
							glueRec.ttl,
							glueRec.qType,
							glueRec.data)
						glueRR, err := m.makeAnswer(glueRRString)
						if err == nil {
							extras = append(extras, glueRR)
							rrStrings = append(rrStrings, glueRRString)
							logger.Debugf("Added A glue record: %s", glueRRString)
						}
					}
				}

				// Also check for AAAA records
				aaaaRecords, err := m.getRecords(nsZoneID, nsHost, nsZone, "AAAA")
				if err == nil {
					for _, glueRec := range aaaaRecords {
						glueRRString := fmt.Sprintf("%s %d IN %s %s",
							glueRec.fqdn,
							glueRec.ttl,
							glueRec.qType,
							glueRec.data)
						glueRR, err := m.makeAnswer(glueRRString)
						if err == nil {
							extras = append(extras, glueRR)
							rrStrings = append(rrStrings, glueRRString)
							logger.Debugf("Added AAAA glue record: %s", glueRRString)
						}
					}
				}
			} else {
				logger.Debugf("Could not get domain info for NS %s: %v", ns, err)
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
	if len(answers) > 0 {
		msg := MakeMessage(r, answers)
		msg.Extra = extras // Include glue records

		// Store answers and extras separately in cache
		dnsRecordInfo := dnsRecordInfo{
			rrStrings: rrStrings,
			answers:   answers,
			extras:    extras,
		}

		// Check if cache needs updating
		if cacheDnsRecordResponse, ok := m.degradeQuery(degradeRecord); !ok ||
			!reflect.DeepEqual(cacheDnsRecordResponse.answers, dnsRecordInfo.answers) ||
			!reflect.DeepEqual(cacheDnsRecordResponse.extras, dnsRecordInfo.extras) {
			m.degradeWrite(degradeRecord, dnsRecordInfo)
			logger.Debugf("CommonEntrypoint Add degrade record %#v, answers: %d, extras: %d",
				degradeRecord, len(dnsRecordInfo.answers), len(dnsRecordInfo.extras))
		}

		logger.Debugf("Sending response with %d answers and %d extras", len(answers), len(extras))
		err = w.WriteMsg(msg)
		if err != nil {
			logger.Error(err)
		}
		return dns.RcodeSuccess, nil
	}

	// Degrade Entrypoint
DegradeEntrypoint:
	if cached, ok := m.degradeQuery(degradeRecord); ok {
		msg := MakeMessage(r, cached.answers)
		msg.Extra = cached.extras
		logger.Debugf("Serving from cache: %d answers, %d extras", len(cached.answers), len(cached.extras))
		err = w.WriteMsg(msg)
		if err != nil {
			logger.Error(err)
		}
		return dns.RcodeSuccess, nil
	}
	return plugin.NextOrFailure(m.Name(), m.Next, ctx, w, r)
}
