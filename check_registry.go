package dnschecks

import (
	"golang.org/x/net/publicsuffix"
)

// Registry struct for information
type Registry struct {
	TLD         string   `json:"tld,omitempty"`
	MemberICANN bool     `json:"member_icann,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
}

func checkTLD(domain string, nameserver string) (*Registry, []string, error) {
	reg := new(Registry)
	var findings []string

	// TLD and Registry information
	tld, tldicann := publicsuffix.PublicSuffix(domain)
	reg.TLD = tld
	reg.MemberICANN = tldicann

	if tldicann == false {
		finding := "The TLD " + tld + " is not an ICANN member."
		findings = append(findings, finding)
	}

	ns, err := resolveNS(tld, nameserver)
	if err != nil {
		return reg, findings, err
	}
	reg.Nameservers = ns

	return reg, findings, nil
}
