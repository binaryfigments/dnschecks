package dnschecks

// Serial struct for information
type Serial struct {
	Nameserver string `json:"nameserver,omitempty"`
	Serial     uint32 `json:"serial,omitempty"`
}

func checkSOA(domain string, nameserver string, nameservers []string) (*SOA, []*Serial, []string, error) {
	serials := []*Serial{}
	var findings []string

	soa, err := resolveSOA(domain, nameserver)
	if err != nil {
		return soa, serials, findings, err
	}

	verify := soa.Serial
	same := true

	for _, ns := range nameservers {
		soas, err := resolveSOA(domain, ns)
		if err != nil {
			serial := new(Serial)
			serial.Nameserver = ns
			serial.Serial = 0
			serials = append(serials, serial)
			if soas.Serial != verify {
				same = false
			}
			continue
		}
		serial := new(Serial)
		serial.Nameserver = ns
		serial.Serial = soas.Serial
		serials = append(serials, serial)
		if soas.Serial != verify {
			same = false
		}
	}

	if same != true {
		finding := "The serials in the SOA's of " + domain + " are not OK."
		findings = append(findings, finding)
	}

	return soa, serials, findings, err
}
