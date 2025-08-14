package coredns_mysql_extend

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"github.com/coredns/coredns/plugin"

	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	_ "github.com/go-sql-driver/mysql"
	"github.com/miekg/dns"
)

var logger = clog.NewWithPlugin(pluginName)

// Enhanced logging functions with timestamps
func logDebugf(format string, args ...interface{}) {
	// Use both CoreDNS logger and custom timestamp logger
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	message := fmt.Sprintf(format, args...)

	// CoreDNS logger (for integration with CoreDNS logging system)
	logger.Debugf("[%s] %s", timestamp, message)

}

func logErrorf(format string, args ...interface{}) {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	message := fmt.Sprintf(format, args...)

	// CoreDNS logger
	logger.Errorf("[%s] %s", timestamp, message)

}

func logError(err error) {
	timestamp := time.Now().Format("2006-01-02 15:04:05.000")
	message := fmt.Sprintf("%v", err)

	// CoreDNS logger
	logger.Errorf("[%s] %s", timestamp, message)

}

// dnsRecordInfo struct is defined in types.go

func (m *Mysql) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	var records []record
	state := request.Request{W: w, Req: r}
	answers := make([]dns.RR, 0)
	extras := make([]dns.RR, 0) // New slice for glue records
	rrStrings := make([]string, 0)
	foundAnyRecord := false // Track if we found any record for this domain

	// Get domain name
	qName := state.Name()
	qType := state.Type()
	degradeRecord := record{fqdn: qName, qType: qType}

	// ENHANCED: Add client info and query details
	logDebugf("New query: FQDN %s type %s from client %s (via %s), question ID %d",
		qName, qType, state.RemoteAddr(), state.LocalAddr(), r.Id)

	// ENHANCED: Log query flags
	logDebugf("Query flags: RD=%t, AD=%t, CD=%t, DO=%t",
		r.RecursionDesired, r.AuthenticatedData, r.CheckingDisabled,
		state.Do()) // DNSSEC OK bit

	// Query zone cache
	zoneID, host, zone, err := m.getDomainInfo(qName)

	// ENHANCED: Log zone lookup results
	if err != nil {
		logDebugf("Zone lookup failed for %s: %v", qName, err)
		goto DegradeEntrypoint
	}
	logDebugf("Zone lookup success: domain=%s -> zoneID=%d, host='%s', zone='%s'",
		qName, zoneID, host, zone)

	// Special handling for CAA records - they inherit from parent domains
	if qType == "CAA" {
		logDebugf("CAA query for %s - starting parent walk", qName)

		// Try to find CAA records starting from the queried domain and walking up
		currentName := qName
		walkLevel := 0
		for {
			walkLevel++
			// ENHANCED: Log each level of CAA walk
			logDebugf("CAA walk level %d: checking %s", walkLevel, currentName)

			currentZoneID, currentHost, currentZone, err := m.getDomainInfo(currentName)
			if err == nil {
				logDebugf("CAA walk: found zone for %s (zoneID=%d, host='%s')",
					currentName, currentZoneID, currentHost)

				caaRecords, err := m.getRecords(currentZoneID, currentHost, currentZone, "CAA")
				if err == nil && len(caaRecords) > 0 {
					logDebugf("CAA walk: found %d CAA records at %s for query %s",
						len(caaRecords), currentName, qName)
					foundAnyRecord = true

					for i, record := range caaRecords {
						rrString := fmt.Sprintf("%s %d IN %s %s", qName, record.ttl, record.qType, record.data)
						// ENHANCED: Log each CAA record being processed
						logDebugf("Processing CAA record %d/%d: %s", i+1, len(caaRecords), rrString)

						rr, err := m.makeAnswer(rrString)
						if err != nil {
							logErrorf("Failed to make CAA answer for RR string '%s': %v", rrString, err)
							continue
						}
						answers = append(answers, rr)
						rrStrings = append(rrStrings, rrString)
					}
					break
				} else {
					// ENHANCED: Log when no CAA records found at this level
					logDebugf("CAA walk: no CAA records at %s (err=%v)", currentName, err)
				}
			} else {
				logDebugf("CAA walk: no zone found for %s: %v", currentName, err)
			}

			// Move up one level in the domain hierarchy
			parts := strings.Split(strings.TrimSuffix(currentName, "."), ".")
			if len(parts) <= 2 { // Don't go beyond the second-level domain
				logDebugf("CAA walk: reached top level at %s, stopping", currentName)
				break
			}
			currentName = strings.Join(parts[1:], ".") + "."
		}

		// If we found CAA records, send the response
		if foundAnyRecord {
			logDebugf("CAA query completed successfully with %d records", len(answers))
			goto CommonEntrypoint
		}

		// If no CAA records found, return NODATA (empty answer) - this is correct behavior for CAA
		logDebugf("CAA query: no records found after walking %d levels, returning NODATA", walkLevel)
		authority := m.getAuthorityRecords(zoneID, zone)
		authorityGlue := m.getGlueRecords(authority)
		msg := MakeMessage(r, []dns.RR{}, authority)
		msg.Extra = authorityGlue
		err = w.WriteMsg(msg)
		if err != nil {
			logError(err)
		}
		return dns.RcodeSuccess, nil
	}

	// Query DB, full match
	// ENHANCED: Log database query details
	logDebugf("Querying database: zoneID=%d, host='%s', zone='%s', type=%s",
		zoneID, host, zone, qType)

	records, err = m.getRecords(zoneID, host, zone, qType)
	if err != nil {
		logErrorf("Database query failed for %s type %s: %v", qName, qType, err)
		goto DegradeEntrypoint
	}
	logDebugf("Database query returned %d records for %s type %s", len(records), qName, qType)

	// ENHANCED: Log individual records being processed
	for i, record := range records {
		logDebugf("Found record %d/%d: fqdn=%s, ttl=%d, type=%s, data=%s",
			i+1, len(records), record.fqdn, record.ttl, record.qType, record.data)
	}

	// Special handling for DNSKEY queries - they should be at zone apex
	if qType == "DNSKEY" && len(records) == 0 && host != "" {
		logDebugf("DNSKEY query for subdomain %s.%s, trying zone apex %s", host, zone, zone)
		apexRecords, err := m.getRecords(zoneID, "", zone, qType)
		if err == nil && len(apexRecords) > 0 {
			records = apexRecords
			logDebugf("Found %d DNSKEY records at zone apex %s", len(records), zone)
		} else {
			logDebugf("No DNSKEY records at zone apex %s (err=%v)", zone, err)
		}
	}

	// If we found records for the exact query, we have answers
	if len(records) > 0 {
		foundAnyRecord = true
		// ENHANCED: Log DNSSEC processing
		dnssecEnabled := false

		for i, record := range records {
			rrString := fmt.Sprintf("%s %d IN %s %s", record.fqdn, record.ttl, record.qType, record.data)
			logDebugf("Building answer %d/%d: %s", i+1, len(records), rrString)

			rr, err := m.makeAnswer(rrString)
			if err != nil {
				logErrorf("Failed to make answer for RR string '%s': %v", rrString, err)
				continue
			}
			answers = append(answers, rr)
			rrStrings = append(rrStrings, rrString)

			// For DNSSEC-enabled zones, also fetch RRSIG records for this RRset
			if qType != "RRSIG" {
				rrsigRecords, err := m.getRecords(zoneID, host, zone, "RRSIG")
				if err == nil && len(rrsigRecords) > 0 {
					dnssecEnabled = true
					logDebugf("DNSSEC enabled: found %d RRSIG records for %s", len(rrsigRecords), qName)

					for j, rrsigRecord := range rrsigRecords {
						// Check if this RRSIG covers the current record type
						if strings.Contains(rrsigRecord.data, qType) {
							rrsigRRString := fmt.Sprintf("%s %d IN RRSIG %s", record.fqdn, rrsigRecord.ttl, rrsigRecord.data)
							logDebugf("Adding RRSIG %d for %s: %s", j+1, qType, rrsigRRString)

							rrsigRR, err := m.makeAnswer(rrsigRRString)
							if err == nil {
								answers = append(answers, rrsigRR)
								rrStrings = append(rrStrings, rrsigRRString)
							} else {
								logErrorf("Failed to create RRSIG record: %v", err)
							}
						}
					}
				}
			}

			// Handle NS records - collect glue records
			if rr.Header().Rrtype == dns.TypeNS {
				ns := rr.(*dns.NS).Ns
				logDebugf("NS record found: %s, looking for glue records", ns)

				if nsZoneID, nsHost, nsZone, err := m.getDomainInfo(ns); err == nil {
					logDebugf("Glue lookup: NS %s -> zoneID=%d, host='%s', zone='%s'",
						ns, nsZoneID, nsHost, nsZone)

					// Query for A and AAAA records specifically
					aRecords, err := m.getRecords(nsZoneID, nsHost, nsZone, "A")
					if err == nil {
						logDebugf("Found %d A glue records for NS %s", len(aRecords), ns)
						for k, glueRec := range aRecords {
							glueRRString := fmt.Sprintf("%s %d IN %s %s",
								glueRec.fqdn,
								glueRec.ttl,
								glueRec.qType,
								glueRec.data)
							logDebugf("Adding A glue record %d/%d: %s", k+1, len(aRecords), glueRRString)

							glueRR, err := m.makeAnswer(glueRRString)
							if err == nil {
								extras = append(extras, glueRR)
								rrStrings = append(rrStrings, glueRRString)
							}
						}
					} else {
						logDebugf("No A glue records for NS %s: %v", ns, err)
					}

					// Also check for AAAA records
					aaaaRecords, err := m.getRecords(nsZoneID, nsHost, nsZone, "AAAA")
					if err == nil {
						logDebugf("Found %d AAAA glue records for NS %s", len(aaaaRecords), ns)
						for k, glueRec := range aaaaRecords {
							glueRRString := fmt.Sprintf("%s %d IN %s %s",
								glueRec.fqdn,
								glueRec.ttl,
								glueRec.qType,
								glueRec.data)
							logDebugf("Adding AAAA glue record %d/%d: %s", k+1, len(aaaaRecords), glueRRString)

							glueRR, err := m.makeAnswer(glueRRString)
							if err == nil {
								extras = append(extras, glueRR)
								rrStrings = append(rrStrings, glueRRString)
							}
						}
					} else {
						logDebugf("No AAAA glue records for NS %s: %v", ns, err)
					}
				} else {
					logDebugf("Could not get domain info for NS %s: %v", ns, err)
				}
			}
		}

		if dnssecEnabled {
			logDebugf("DNSSEC processing completed for %s", qName)
		}
	} else {
		// Try query CNAME type of record for exact match
		logDebugf("No direct records found, trying CNAME lookup for %s", qName)

		cnameRecords, err := m.getRecords(zoneID, host, zone, cnameQtype)
		if err != nil {
			logErrorf("CNAME lookup failed for %s: %v", qName, err)
			goto DegradeEntrypoint
		}
		logDebugf("CNAME lookup returned %d records for %s", len(cnameRecords), qName)

		if len(cnameRecords) > 0 {
			foundAnyRecord = true
			for i, cnameRecord := range cnameRecords {
				logDebugf("Processing CNAME %d/%d: %s -> %s",
					i+1, len(cnameRecords), qName, cnameRecord.data)

				// Always add the CNAME record itself first
				rrString := fmt.Sprintf("%s %d IN %s %s", qName, cnameRecord.ttl, cnameRecord.qType, cnameRecord.data)
				rrStrings = append(rrStrings, rrString)
				rr, err := m.makeAnswer(rrString)
				if err != nil {
					logErrorf("Failed to create CNAME record: %v", err)
					continue
				}
				answers = append(answers, rr)

				// Only try to resolve CNAME target if it's within our managed zones
				cnameZoneID, cnameHost, cnameZone, err := m.getDomainInfo(cnameRecord.data)
				if err != nil {
					// CNAME target is external - this is perfectly normal
					logDebugf("CNAME target %s is external (not in our zones): %v", cnameRecord.data, err)
					// Don't go to DegradeEntrypoint - this is expected behavior
					continue
				}

				// CNAME target is within our zones, so resolve it
				logDebugf("CNAME target %s is internal -> zoneID=%d, host='%s', zone='%s'",
					cnameRecord.data, cnameZoneID, cnameHost, cnameZone)

				cname2Records, err := m.getRecords(cnameZoneID, cnameHost, cnameZone, qType)
				if err != nil {
					logErrorf("Failed to resolve internal CNAME target records for %s type %s: %v",
						cnameRecord.data, qType, err)
					// Even if we can't resolve the target, we still have the CNAME record
					continue
				}

				logDebugf("CNAME target resolution: found %d %s records for %s",
					len(cname2Records), qType, cnameRecord.data)

				for j, cname2Record := range cname2Records {
					rrString := fmt.Sprintf("%s %d IN %s %s", cname2Record.fqdn, cname2Record.ttl, cname2Record.qType, cname2Record.data)
					logDebugf("Adding CNAME target record %d/%d: %s", j+1, len(cname2Records), rrString)

					rrStrings = append(rrStrings, rrString)
					rr, err := m.makeAnswer(rrString)
					if err != nil {
						logErrorf("Failed to create CNAME target record: %v", err)
						continue
					}
					answers = append(answers, rr)
				}
			}
		}
	}

	// Handle wildcard domains if no exact match found
	if !foundAnyRecord && strings.Count(qName, zoneSeparator) > 1 {
		baseZone := m.getBaseZone(qName)
		logDebugf("No exact match found, trying wildcard lookup: base zone = %s", baseZone)

		wildcardZoneID, ok := m.getZoneID(baseZone)
		if !ok {
			logDebugf("No zone ID found for base zone %s, skipping wildcard", baseZone)
		} else {
			wildcardName := wildcard + zoneSeparator + baseZone
			logDebugf("Wildcard query: %s in zone %s (ID: %d)", wildcardName, baseZone, wildcardZoneID)

			// First try to get wildcard records for the requested type
			wildcardRecords, err := m.getRecords(wildcardZoneID, wildcard, zone, qType)
			if err != nil {
				logErrorf("Wildcard query failed for %s type %s: %v", wildcardName, qType, err)
			} else {
				logDebugf("Wildcard query returned %d records for %s type %s",
					len(wildcardRecords), wildcardName, qType)

				if len(wildcardRecords) > 0 {
					foundAnyRecord = true
					for i, record := range wildcardRecords {
						rrString := fmt.Sprintf("%s %d IN %s %s", qName, record.ttl, record.qType, record.data)
						logDebugf("Adding wildcard record %d/%d: %s", i+1, len(wildcardRecords), rrString)

						rr, err := m.makeAnswer(rrString)
						rrStrings = append(rrStrings, rrString)
						if err != nil {
							logErrorf("Failed to make wildcard answer for RR string '%s': %v", rrString, err)
							continue
						}
						answers = append(answers, rr)
					}
				} else {
					// Try wildcard CNAME records
					logDebugf("No wildcard records for type %s, trying wildcard CNAME", qType)

					wildcardCnameRecords, err := m.getRecords(wildcardZoneID, wildcard, zone, cnameQtype)
					if err != nil {
						logErrorf("Wildcard CNAME query failed for %s: %v", wildcardName, err)
					} else {
						logDebugf("Wildcard CNAME query returned %d records for %s", len(wildcardCnameRecords), wildcardName)

						if len(wildcardCnameRecords) > 0 {
							foundAnyRecord = true
							for i, cnameRecord := range wildcardCnameRecords {
								logDebugf("Processing wildcard CNAME %d/%d: %s -> %s",
									i+1, len(wildcardCnameRecords), qName, cnameRecord.data)

								// Add the CNAME record itself first
								rrString := fmt.Sprintf("%s %d IN %s %s", qName, cnameRecord.ttl, cnameRecord.qType, cnameRecord.data)
								rrStrings = append(rrStrings, rrString)
								rr, err := m.makeAnswer(rrString)
								if err != nil {
									logErrorf("Failed to make wildcard CNAME answer for RR string '%s': %v", rrString, err)
									continue
								}
								answers = append(answers, rr)

								// Only try to resolve CNAME target if it's within our managed zones
								cnameZoneID, cnameHost, cnameZone, err := m.getDomainInfo(cnameRecord.data)
								if err != nil {
									// CNAME target is external - this is perfectly normal
									logDebugf("Wildcard CNAME target %s is external (not in our zones): %v", cnameRecord.data, err)
									// Don't treat this as an error - just continue
									continue
								}

								// CNAME target is within our zones, so try to resolve it
								logDebugf("Wildcard CNAME target %s is internal -> zoneID=%d, host='%s', zone='%s'",
									cnameRecord.data, cnameZoneID, cnameHost, cnameZone)

								cname2Records, err := m.getRecords(cnameZoneID, cnameHost, cnameZone, qType)
								if err != nil {
									logErrorf("Failed to resolve wildcard CNAME target: %v", err)
									// Even if we can't resolve the target, we still have the CNAME record
									continue
								}

								logDebugf("Wildcard CNAME target resolution: found %d %s records for %s",
									len(cname2Records), qType, cnameRecord.data)

								for j, cname2Record := range cname2Records {
									rrString := fmt.Sprintf("%s %d IN %s %s", cname2Record.fqdn, cname2Record.ttl, cname2Record.qType, cname2Record.data)
									logDebugf("Adding wildcard CNAME target record %d/%d: %s", j+1, len(cname2Records), rrString)

									rrStrings = append(rrStrings, rrString)
									rr, err := m.makeAnswer(rrString)
									if err != nil {
										logErrorf("Failed to make CNAME target answer for RR string '%s': %v", rrString, err)
										continue
									}
									answers = append(answers, rr)
								}
							}
						}
					}
				}
			}
		}
	}

CommonEntrypoint:
	// Check if we should fallthrough - only if no records found at all
	// ENHANCED: Log fallthrough decision
	if !foundAnyRecord && m.shouldFallthrough {
		logDebugf("No records found for %s type %s, fallthrough=true -> passing to next plugin", qName, qType)
		return plugin.NextOrFailure(m.Name(), m.Next, ctx, w, r)
	}

	// Common Entrypoint - we found some records for this domain OR we should return NODATA
	// If foundAnyRecord is true, we found records for this domain but maybe not this type
	// If foundAnyRecord is false but we have a valid zone, return NODATA instead of NXDOMAIN
	if foundAnyRecord || (zoneID > 0) {
		// ENHANCED: Log response decision
		responseType := "NODATA"
		if foundAnyRecord {
			responseType = "SUCCESS"
		}

		logDebugf("Response decision: %s (foundAnyRecord=%t, zoneID=%d, answers=%d, extras=%d)",
			responseType, foundAnyRecord, zoneID, len(answers), len(extras))

		// Get NS records for authority section
		authority := m.getAuthorityRecords(zoneID, zone)
		
		// Get glue records for the authority NS records
		authorityGlue := m.getGlueRecords(authority)
		
		// Combine existing extras (from answer section NS records) with authority glue
		allExtras := append(extras, authorityGlue...)
		
		logDebugf("Main response: creating message with %d answers, %d authority records, and %d additional records", 
			len(answers), len(authority), len(allExtras))
		
		// If we found records for this domain but no answers for this specific query type,
		// return NODATA (empty answer section) instead of NXDOMAIN
		msg := MakeMessage(r, answers, authority)
		msg.Extra = allExtras // Include both answer glue and authority glue records

		// Store answers and extras separately in cache
		dnsRecordInfo := dnsRecordInfo{
			rrStrings: rrStrings,
			answers:   answers,
			extras:    extras,
		}

		// Check if cache needs updating
		// ENHANCED: Log cache operations
		if cacheDnsRecordResponse, ok := m.degradeQuery(degradeRecord); !ok ||
			!reflect.DeepEqual(cacheDnsRecordResponse.answers, dnsRecordInfo.answers) ||
			!reflect.DeepEqual(cacheDnsRecordResponse.extras, dnsRecordInfo.extras) {
			m.degradeWrite(degradeRecord, dnsRecordInfo)
			logDebugf("Cache updated: key=%+v, stored %d answers + %d extras",
				degradeRecord, len(dnsRecordInfo.answers), len(dnsRecordInfo.extras))
		} else {
			logDebugf("Cache unchanged: key=%+v", degradeRecord)
		}

		// ENHANCED: Log final response details
		logDebugf("Sending response: ID=%d, answers=%d, extras=%d, rcode=%s",
			msg.Id, len(msg.Answer), len(msg.Extra), dns.RcodeToString[msg.Rcode])

		err = w.WriteMsg(msg)
		if err != nil {
			logError(err)
		}
		return dns.RcodeSuccess, nil
	}

	// Only fallthrough if we haven't found any records for this domain AND no valid zone
	// ENHANCED: Log fallthrough decision
	if m.shouldFallthrough {
		logDebugf("No domain records found for %s and no valid zone, fallthrough=true -> passing to next plugin", qName)
		return plugin.NextOrFailure(m.Name(), m.Next, ctx, w, r)
	}

	// Degrade Entrypoint
DegradeEntrypoint:
	// ENHANCED: Log cache lookup
	logDebugf("Entering degrade mode for %+v", degradeRecord)

	if cached, ok := m.degradeQuery(degradeRecord); ok {
		logDebugf("Cache hit: serving %d answers + %d extras from cache",
			len(cached.answers), len(cached.extras))

		// Get authority records even for cached responses
		authority := m.getAuthorityRecords(zoneID, zone)
		
		// Get glue records for the authority NS records
		authorityGlue := m.getGlueRecords(authority)
		
		// Combine cached extras with authority glue
		allExtras := append(cached.extras, authorityGlue...)
		
		logDebugf("Cached response: creating message with %d cached answers, %d authority records, and %d additional records", 
			len(cached.answers), len(authority), len(allExtras))
		msg := MakeMessage(r, cached.answers, authority)
		msg.Extra = allExtras
		err = w.WriteMsg(msg)
		if err != nil {
			logError(err)
		}
		return dns.RcodeSuccess, nil
	} else {
		logDebugf("Cache miss for %+v", degradeRecord)
	}

	// CRITICAL: For CAA queries, always return NODATA instead of falling through
	// This prevents SERVFAIL responses that break Let's Encrypt
	// ENHANCED: Log special case handling
	if qType == "CAA" {
		logDebugf("CAA degrade: returning NODATA to prevent SERVFAIL for %s", qName)
		authority := m.getAuthorityRecords(zoneID, zone)
		authorityGlue := m.getGlueRecords(authority)
		msg := MakeMessage(r, []dns.RR{}, authority)
		msg.Extra = authorityGlue
		err = w.WriteMsg(msg)
		if err != nil {
			logError(err)
		}
		return dns.RcodeSuccess, nil
	}

	// If we have a valid zone but no cached data, return NODATA instead of falling through
	if zoneID > 0 {
		logDebugf("Zone exists but no records/cache: returning NODATA for %s type %s", qName, qType)
		authority := m.getAuthorityRecords(zoneID, zone)
		authorityGlue := m.getGlueRecords(authority)
		msg := MakeMessage(r, []dns.RR{}, authority)
		msg.Extra = authorityGlue
		err = w.WriteMsg(msg)
		if err != nil {
			logError(err)
		}
		return dns.RcodeSuccess, nil
	}

	// ENHANCED: Log final fallback
	logDebugf("Final fallback: passing to next plugin (no zone, no cache, no fallthrough)")
	return plugin.NextOrFailure(m.Name(), m.Next, ctx, w, r)
}