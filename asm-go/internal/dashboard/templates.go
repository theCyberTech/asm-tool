package dashboard

import (
	"embed"
	"html/template"
	"io"
	"sync"
)

//go:embed templates/*.html
var templateFS embed.FS

var (
	templates     *template.Template
	templatesOnce sync.Once
	templateErr   error
)

// PageData represents the data passed to templates
type PageData struct {
	ActivePage string
	Stats      Stats
	Findings   FindingCounts
	Error      string
}

// Stats represents asset counts
type Stats struct {
	Domains      int
	Subdomains   int
	Ports        int
	Certificates int
	URLs         int
	APIs         int
	Emails       int
	CloudBuckets int
	Takeovers    int
}

// FindingCounts represents finding severity counts
type FindingCounts struct {
	Total    int
	Critical int
	High     int
	Medium   int
	Low      int
	Info     int
}

// Templates returns the parsed template collection
func Templates() (*template.Template, error) {
	templatesOnce.Do(func() {
		templates, templateErr = template.ParseFS(templateFS, "templates/*.html")
	})
	return templates, templateErr
}

// RenderPage renders a page using the base template
func RenderPage(w io.Writer, name string, data PageData) error {
	tmpl, err := Templates()
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, name, data)
}

// RenderPartial renders a partial template (for htmx requests)
func RenderPartial(w io.Writer, name string, data interface{}) error {
	tmpl, err := Templates()
	if err != nil {
		return err
	}
	return tmpl.ExecuteTemplate(w, name, data)
}
