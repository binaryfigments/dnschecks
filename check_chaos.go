package dnschecks

// Chaos struct for information
type Chaos struct {
	Nameserver   string `json:"nameserver,omitempty"`
	BindHostname string `json:"hostname,omitempty"`
	BindVersion  string `json:"version,omitempty"`
}

func checkChaos(domain string, nameserver string, nameservers []string) ([]*Chaos, []string, error) {
	data := []*Chaos{}
	var findings []string

	for _, ns := range nameservers {
		chaos := new(Chaos)
		chaos.Nameserver = ns
		version, err := resolveVersionBind(domain, ns)
		if err != nil {
			version = "empty"
		}
		chaos.BindVersion = version

		hostname, err := resolveHostnameBind(domain, ns)
		if err != nil {
			hostname = "empty"
		}
		chaos.BindHostname = hostname

		data = append(data, chaos)
	}

	return data, findings, nil
}
