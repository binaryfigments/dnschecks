package dnschecks

import (
	"sort"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// Data struct with main data
type Data struct {
	Registry       *Registry  `json:"registry,omitempty"`
	Nameservers    []string   `json:"nameservers,omitempty"`
	NameserversTLD []string   `json:"nameservers_tld,omitempty"`
	SOA            *SOA       `json:"soa,omitempty"`
	Serials        []*Serial  `json:"serials,omitempty"`
	Chaos          []*Chaos   `json:"chaos,omitempty"`
	DNSSEC         *DNSSEC    `json:"dnssec,omitempty"`
	Error          bool       `json:"error,omitempty"`
	ErrorMessage   string     `json:"error_message,omitempty"`
	Findings       []*Finding `json:"findings,omitempty"`
}

// Finding struct with main data
type Finding struct {
	ID    string `json:"id,omitempty"`
	Text  string `json:"text,omitempty"`
	Score string `json:"score,omitempty"`
}

// Run function for running checks
func Run(domain string, nameserver string) (*Data, error) {
	data := new(Data)

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
	reg, err := checkTLD(domain, nameserver)
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}
	data.Registry = reg

	// Check nameserver from standard DNS.
	ns, err := checkNS(domain, nameserver)
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}
	data.Nameservers = ns
	if len(data.Nameservers) < 1 {
		finding := new(Finding)
		finding.ID = "DNS-000"
		finding.Text = "The domain " + domain + " has no nameservers in zone."
		finding.Score = "FAIL"
		data.Findings = append(data.Findings, finding)
		return data, err
	}

	// Check nameservers of domain at TLD.

	tldns := data.Registry.Nameservers[0]
	nstld, err := resolveAuthNS(domain, tldns)
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}
	data.NameserversTLD = nstld

	soa, serials, err := checkSOA(domain, nameserver, data.Nameservers)
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}
	data.SOA = soa
	data.Serials = serials

	chaos, err := checkChaos(domain, nameserver, data.Nameservers)
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}
	data.Chaos = chaos

	dnssec, err := checkDNSSEC(domain, data.Nameservers[0], data.NameserversTLD[0])
	if err != nil {
		data.Error = true
		data.ErrorMessage = err.Error()
		return data, err
	}
	data.DNSSEC = dnssec

	equeal := isEqual(data.Nameservers, data.NameserversTLD)
	if equeal != true {
		finding := new(Finding)
		finding.ID = "DNS-001"
		finding.Text = "The domain " + domain + " has diferent nameservers in zone and at the TLD."
		finding.Score = "FAIL"
		data.Findings = append(data.Findings, finding)
	} else {
		finding := new(Finding)
		finding.ID = "DNS-001"
		finding.Text = "The domain " + domain + " has the same nameservers in zone and at the TLD."
		finding.Score = "OK"
		data.Findings = append(data.Findings, finding)
	}

	if data.Registry.MemberICANN != true {
		finding := new(Finding)
		finding.ID = "DNS-002"
		finding.Text = "The registry of TLD " + data.Registry.TLD + " of domain name " + domain + " is NOT an ICANN member."
		finding.Score = "FAIL"
		data.Findings = append(data.Findings, finding)
	} else {
		finding := new(Finding)
		finding.ID = "DNS-002"
		finding.Text = "The registry of TLD " + data.Registry.TLD + " of domain name " + domain + " is an ICANN member."
		finding.Score = "OK"
		data.Findings = append(data.Findings, finding)
	}

	if data.DNSSEC.NSEC.Type == "nsec" {
		finding := new(Finding)
		finding.ID = "DNS-003"
		finding.Text = "The domain " + domain + " has an NSEC record. May be vulnerable to zonewaling. Use a NSEC3 with a SALT to mitigate this."
		finding.Score = "FAIL"
		data.Findings = append(data.Findings, finding)
	} else if data.DNSSEC.NSEC.Type == "nsec3" {
		finding := new(Finding)
		finding.ID = "DNS-003"
		finding.Text = "The domain " + domain + " has an NSEC3 record."
		finding.Score = "OK"
		data.Findings = append(data.Findings, finding)
	} else {
		finding := new(Finding)
		finding.ID = "DNS-003"
		finding.Text = "The domain " + domain + " has no NSEC or NSEC3 record."
		finding.Score = "NEUTRAL"
		data.Findings = append(data.Findings, finding)
	}

	if data.DNSSEC.DNSSEC == true {
		finding := new(Finding)
		finding.ID = "DNS-004"
		finding.Text = "The domain " + domain + " uses DNSSEC."
		finding.Score = "OK"
		data.Findings = append(data.Findings, finding)
	} else {
		finding := new(Finding)
		finding.ID = "DNS-004"
		finding.Text = "The domain " + domain + " does NOT use DNSSEC."
		finding.Score = "FAIL"
		data.Findings = append(data.Findings, finding)
	}

	if equalSerial(data.Serials) == true {
		finding := new(Finding)
		finding.ID = "DNS-005"
		finding.Text = "The serials of domain " + domain + " are the same on all nameservers."
		finding.Score = "OK"
		data.Findings = append(data.Findings, finding)
	} else {
		finding := new(Finding)
		finding.ID = "DNS-005"
		finding.Text = "The serials of domain " + domain + " are NOT the same on all nameservers."
		finding.Score = "FAIL"
		data.Findings = append(data.Findings, finding)
	}

	if len(data.Nameservers) < 2 {
		finding := new(Finding)
		finding.ID = "DNS-006"
		finding.Text = "The domain " + domain + " has less then 2 namservers."
		finding.Score = "FAIL"
		data.Findings = append(data.Findings, finding)
	} else {
		finding := new(Finding)
		finding.ID = "DNS-006"
		finding.Text = "The domain " + domain + " has 2 or more namservers."
		finding.Score = "OK"
		data.Findings = append(data.Findings, finding)
	}

	// the last return
	return data, err
}

func isEqual(a, b []string) bool {
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

func equalSerial(a []*Serial) bool {
	for _, v := range a {
		if v.Serial != a[0].Serial {
			return false
		}
	}
	return true
}
