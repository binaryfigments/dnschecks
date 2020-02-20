package dnschecks

import (
	"strings"

	"github.com/miekg/dns"
)

func resolveNS(domain string, nameserver string) ([]string, error) {
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.MsgHdr.RecursionDesired = true
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return answer, err
	}
	for _, ain := range in.Answer {
		if a, ok := ain.(*dns.NS); ok {
			answer = append(answer, strings.ToLower(a.Ns))
		}
	}
	return answer, nil
}

func resolveAuthNS(domain string, nameserver string) ([]string, error) {
	var answer []string
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.MsgHdr.RecursionDesired = false
	m.SetEdns0(4096, true)
	c := new(dns.Client)
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return answer, err
	}
	for _, ain := range in.Ns {
		if a, ok := ain.(*dns.NS); ok {
			answer = append(answer, strings.ToLower(a.Ns))
		}
	}
	return answer, nil
}

// SOA struct for SOA information aquired from the nameserver.
type SOA struct {
	Ns      string `json:"ns,omitempty"`
	Mbox    string `json:"mbox,omitempty"`
	Serial  uint32 `json:"serial,omitempty"`
	Refresh uint32 `json:"refresh,omitempty"`
	Retry   uint32 `json:"retry,omitempty"`
	Expire  uint32 `json:"expire,omitempty"`
	Minttl  uint32 `json:"minttl,omitempty"`
}

func resolveSOA(domain string, nameserver string) (*SOA, error) {
	answer := new(SOA)
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return answer, err
	}
	for _, ain := range in.Answer {
		if soa, ok := ain.(*dns.SOA); ok {
			answer.Serial = soa.Serial   // uint32
			answer.Ns = soa.Ns           // string
			answer.Expire = soa.Expire   // uint32
			answer.Mbox = soa.Mbox       // string
			answer.Minttl = soa.Minttl   // uint32
			answer.Refresh = soa.Refresh // uint32
			answer.Retry = soa.Retry     // uint32
		}
	}
	return answer, nil
}

func resolveVersionBind(domain string, nameserver string) (string, error) {
	var version string
	// m := new(dns.Msg)
	m := &dns.Msg{
		Question: make([]dns.Question, 1),
	}
	// m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.Question[0] = dns.Question{"version.bind.", dns.TypeTXT, dns.ClassCHAOS}
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return version, err
	}
	if in != nil && len(in.Answer) > 0 {
		return in.Answer[0].String(), nil
	}
	return version, nil
}

func resolveHostnameBind(domain string, nameserver string) (string, error) {
	var hostname string
	// m := new(dns.Msg)
	m := &dns.Msg{
		Question: make([]dns.Question, 1),
	}
	// m.SetQuestion(dns.Fqdn(domain), dns.TypeSOA)
	m.Question[0] = dns.Question{"hostname.bind.", dns.TypeTXT, dns.ClassCHAOS}
	c := new(dns.Client)
	m.MsgHdr.RecursionDesired = true
	in, _, err := c.Exchange(m, nameserver+":53")
	if err != nil {
		return hostname, err
	}
	if in != nil && len(in.Answer) > 0 {
		return in.Answer[0].String(), nil
	}
	return hostname, nil
}
