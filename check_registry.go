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

func checkTLD(domain string, nameserver string) (*Registry, error) {
	reg := new(Registry)

	// TLD and Registry information
	tld, tldicann := publicsuffix.PublicSuffix(domain)
	reg.TLD = tld
	reg.MemberICANN = tldicann

	ns, err := resolveNS(tld, nameserver)
	if err != nil {
		return reg, err
	}
	reg.Nameservers = ns

	return reg, nil
}
