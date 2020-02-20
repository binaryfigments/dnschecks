package dnschecks

func checkNS(domain string, nameserver string) ([]string, []string, error) {
	var nameservers []string
	var findings []string

	nameservers, err := resolveNS(domain, nameserver)
	if err != nil {
		return nameservers, findings, err
	}

	if len(nameservers) < 2 {
		finding := "The domain " + domain + " has less then 2 namservers at nameserver " + nameserver + "."
		findings = append(findings, finding)
	}

	return nameservers, findings, nil
}
