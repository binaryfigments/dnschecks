package dnschecks

import (
	"sort"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Data struct with main data
type Data struct {
	Findings       []string  `json:"findings,omitempty"`
	Registry       *Registry `json:"registry,omitempty"`
	Nameservers    []string  `json:"nameservers,omitempty"`
	NameserversTLD []string  `json:"nameservers_tld,omitempty"`
	SOA            *SOA      `json:"soa,omitempty"`
	Serials        []*Serial `json:"serials,omitempty"`
	Chaos          []*Chaos  `json:"chaos,omitempty"`
	DNSSEC         *DNSSEC   `json:"dnssec,omitempty"`
	Error          bool
	ErrorMessage   string `json:"error_message,omitempty"`
}

// Run function for running checks
func Run(domain string, nameserver string) (*Data, error) {
	data := new(Data)

	var findings []string

	// Valid domain name (ASCII or IDN)
	domain = strings.ToLower(domain)
	domain, err := idna.ToASCII(domain)
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}

	// Validate
	domain, err = publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}

	// Check TLD information
	reg, regfindings, err := checkTLD(domain, nameserver)
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}
	data.Registry = reg
	findings = append(findings, regfindings...)

	// Check nameserver from standard DNS.
	ns, nsfindings, err := checkNS(domain, nameserver)
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}
	data.Nameservers = ns
	findings = append(findings, nsfindings...)

	// Check nameservers of domain at TLD.

	tldns := data.Registry.Nameservers[0]
	nstld, err := resolveAuthNS(domain, tldns)
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}
	data.NameserversTLD = nstld

	equeal := Equal(data.Nameservers, data.NameserversTLD)
	if equeal != true {
		finding := "The domain " + domain + " has diferent nameservers in zone and at the TLD."
		findings = append(findings, finding)
	}

	soa, serials, soafindings, err := checkSOA(domain, nameserver, data.Nameservers)
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}
	data.SOA = soa
	data.Serials = serials
	findings = append(findings, soafindings...)

	chaos, chaosfindings, err := checkChaos(domain, nameserver, data.Nameservers)
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}
	data.Chaos = chaos
	findings = append(findings, chaosfindings...)

	dnssec, err := checkDNSSEC(domain, data.Nameservers[0], data.NameserversTLD[0])
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}
	data.DNSSEC = dnssec

	data.Findings = findings
	return data, err
}

func Equal(a, b []string) bool {
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}
