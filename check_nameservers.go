package dnschecks

func checkNS(domain string, nameserver string) ([]string, error) {
	var nameservers []string

	nameservers, err := resolveNS(domain, nameserver)
	if err != nil {
		return nameservers, err
	}

	return nameservers, nil
}
