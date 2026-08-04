package commands

import "github.com/asm-tool/asm-go/internal/target"

func normalizeDomainList(domains []string) ([]string, error) {
	normalized := make([]string, 0, len(domains))
	for _, domain := range domains {
		canonical, err := target.NormalizeTarget(domain)
		if err != nil {
			return nil, err
		}
		normalized = append(normalized, canonical)
	}
	return normalized, nil
}
