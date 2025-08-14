package coredns_mysql_extend

import (
	"net"
	"testing"

	"github.com/miekg/dns"
)

func TestMakeMessageWithAuthority(t *testing.T) {
	// Create a test DNS query
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("example.com"), dns.TypeA)

	// Create mock answers (A record)
	answers := []dns.RR{
		&dns.A{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("192.0.2.1").To4(),
		},
	}

	// Create mock authority records (NS records)
	authority := []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns: "ns1.example.com.",
		},
		&dns.NS{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns: "ns2.example.com.",
		},
	}

	// Test the new MakeMessage function
	msg := MakeMessage(req, answers, authority)

	// Verify the message has the expected sections
	if len(msg.Answer) != 1 {
		t.Errorf("Expected 1 answer, got %d", len(msg.Answer))
	}

	if len(msg.Ns) != 2 {
		t.Errorf("Expected 2 authority records, got %d", len(msg.Ns))
	}

	if !msg.Authoritative {
		t.Error("Expected authoritative flag to be set")
	}

	// Verify the authority records are NS records
	for i, ns := range msg.Ns {
		if ns.Header().Rrtype != dns.TypeNS {
			t.Errorf("Authority record %d is not NS type: got %d", i, ns.Header().Rrtype)
		}
	}

	t.Logf("Success! DNS response now includes:")
	t.Logf("- Answer section: %d records", len(msg.Answer))
	t.Logf("- Authority section: %d NS records", len(msg.Ns))
	t.Logf("- Authoritative flag: %t", msg.Authoritative)
}

func TestMakeMessageEmptyWithAuthority(t *testing.T) {
	// Test NODATA response with authority section
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("nonexistent.example.com"), dns.TypeA)

	// No answers (NODATA)
	answers := []dns.RR{}

	// But still include authority (NS records for the zone)
	authority := []dns.RR{
		&dns.NS{
			Hdr: dns.RR_Header{
				Name:   "example.com.",
				Rrtype: dns.TypeNS,
				Class:  dns.ClassINET,
				Ttl:    3600,
			},
			Ns: "ns1.example.com.",
		},
	}

	msg := MakeMessage(req, answers, authority)

	if len(msg.Answer) != 0 {
		t.Errorf("Expected 0 answers for NODATA, got %d", len(msg.Answer))
	}

	if len(msg.Ns) != 1 {
		t.Errorf("Expected 1 authority record for NODATA, got %d", len(msg.Ns))
	}

	if !msg.Authoritative {
		t.Error("Expected authoritative flag to be set even for NODATA")
	}

	t.Logf("Success! NODATA response now includes:")
	t.Logf("- Answer section: %d records (empty for NODATA)", len(msg.Answer))
	t.Logf("- Authority section: %d NS records (proves we're authoritative)", len(msg.Ns))
	t.Logf("- Authoritative flag: %t", msg.Authoritative)
}