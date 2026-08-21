package dashboard

// JSONOverview is the payload for GET /api/overview.
type JSONOverview struct {
	Status       string            `json:"status"`
	Stats        Stats             `json:"stats"`
	Findings     FindingCounts     `json:"findings"`
	Domains      []DomainStats     `json:"domains"`
	ChangeEvents []ChangeEventView `json:"change_events"`
	Warning      string            `json:"warning,omitempty"`
}

// JSONDomainDetail is the domain detail payload.
type JSONDomainDetail struct {
	Status  string `json:"status"`
	Warning string `json:"warning,omitempty"`
	DomainDetailData
}

// JSONAssetList is a typed list of one finding kind.
type JSONAssetList struct {
	Status string `json:"status"`
	Kind   string `json:"kind"`
	Title  string `json:"title"`
	Count  int    `json:"count"`
	Items  any    `json:"items"`
}

// JSONOperations is the operations dashboard payload.
type JSONOperations struct {
	Status string `json:"status"`
	OperationsData
}

// OverviewJSON converts page data into the overview API payload.
func OverviewJSON(data PageData) JSONOverview {
	status := "ok"
	if data.Error != "" {
		status = "error"
	}
	return JSONOverview{
		Status:       status,
		Stats:        data.Stats,
		Findings:     data.Findings,
		Domains:      orEmpty(data.Domains),
		ChangeEvents: orEmpty(data.ChangeEvents),
		Warning:      firstNonEmpty(data.Warning, data.Error),
	}
}

// DomainDetailJSON converts a domain detail page to JSON.
func DomainDetailJSON(data PageData) JSONDomainDetail {
	status := "ok"
	if data.Error != "" || data.DomainDetail == nil {
		status = "error"
	}
	out := JSONDomainDetail{Status: status, Warning: firstNonEmpty(data.Warning, data.Error)}
	if data.DomainDetail == nil {
		return out
	}
	out.DomainDetailData = data.DomainDetail.withEmptySlices()
	return out
}

// OperationsJSON converts operations page data to JSON.
func OperationsJSON(data *OperationsData) JSONOperations {
	if data == nil {
		return JSONOperations{
			Status: "ok",
			OperationsData: OperationsData{
				Actions: []OperationOption{},
				Runs:    []RunRecord{},
			},
		}
	}
	out := *data
	out.Actions = orEmpty(out.Actions)
	out.Runs = orEmpty(out.Runs)
	return JSONOperations{Status: "ok", OperationsData: out}
}

func (d DomainDetailData) withEmptySlices() DomainDetailData {
	d.Subdomains = orEmpty(d.Subdomains)
	d.Ports = orEmpty(d.Ports)
	d.Certificates = orEmpty(d.Certificates)
	d.Technologies = orEmpty(d.Technologies)
	d.DNSRecords = orEmpty(d.DNSRecords)
	d.Findings = orEmpty(d.Findings)
	d.URLs = orEmpty(d.URLs)
	d.APIs = orEmpty(d.APIs)
	d.Emails = orEmpty(d.Emails)
	d.CloudStorage = orEmpty(d.CloudStorage)
	d.Takeovers = orEmpty(d.Takeovers)
	d.ChangeEvents = orEmpty(d.ChangeEvents)
	return d
}

func orEmpty[T any](items []T) []T {
	if items == nil {
		return []T{}
	}
	return items
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}
