package dnschecks

// Serial struct for information
type Serial struct {
	Nameserver string `json:"nameserver,omitempty"`
	Serial     uint32 `json:"serial,omitempty"`
}

func checkSOA(domain string, nameserver string, nameservers []string) (*SOA, []*Serial, error) {
	serials := []*Serial{}

	soa, err := resolveSOA(domain, nameserver)
	if err != nil {
		return soa, serials, err
	}

	for _, ns := range nameservers {
		soas, err := resolveSOA(domain, ns)
		if err != nil {
			serial := new(Serial)
			serial.Nameserver = ns
			serial.Serial = 0
			serials = append(serials, serial)
			continue
		}
		serial := new(Serial)
		serial.Nameserver = ns
		serial.Serial = soas.Serial
		serials = append(serials, serial)
	}

	return soa, serials, err
}
