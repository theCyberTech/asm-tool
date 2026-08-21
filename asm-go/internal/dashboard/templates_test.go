package dashboard

import (
	"bytes"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestDomainDetailTemplateDoesNotInterpolateScanDataIntoAlpine(t *testing.T) {
	src, err := templateFS.ReadFile("templates/domain_detail.html")
	if err != nil {
		t.Fatalf("reading template: %v", err)
	}
	if regexp.MustCompile(`x-show="[^"]*\{\{`).Match(src) {
		t.Fatal("domain_detail.html still interpolates template data inside Alpine x-show")
	}
	if !bytes.Contains(src, []byte("$el.dataset.search")) {
		t.Fatal("expected Alpine filters to read $el.dataset.search")
	}
}

func TestDomainDetailRenderEscapesScanDataOutsideJSStrings(t *testing.T) {
	payload := "xss');alert(1);//"
	quotedJS := "'" + payload + "'"
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)

	data := PageData{
		ActivePage: "domain",
		DomainDetail: &DomainDetailData{
			Domain:  "example.com",
			AddedAt: now,
			Subdomains: []SubdomainView{{
				Subdomain:    payload,
				DiscoveredAt: now,
				LastSeen:     now,
			}},
			Ports: []PortView{{
				Host: payload, Port: 443, Protocol: "tcp",
				Service: payload, Product: payload, Banner: payload,
				DiscoveredAt: now,
			}},
			Certificates: []CertificateView{{
				Host: payload, Subject: payload, Issuer: payload,
				NotAfter: now,
			}},
			Technologies: []TechnologyView{{
				Host: payload, Title: payload, Server: payload,
				Technologies: payload, CheckedAt: now,
			}},
			DNSRecords: []DNSRecordView{{
				Domain: payload, Records: payload, CheckedAt: now,
			}},
			Findings: []FindingView{{
				Name: payload, Severity: payload, Host: payload,
				MatchedAt: payload, Tags: payload, DiscoveredAt: now,
			}},
			URLs: []URLView{{
				URL: payload, Interesting: true, DiscoveredAt: now,
			}},
			APIs: []APIView{{
				URL:          payload,
				Type:         payload,
				Title:        payload,
				DiscoveredAt: now,
			}},
			CloudStorage: []CloudStorageView{{
				Provider: payload, BucketName: payload, URL: payload,
				Severity: payload, Evidence: payload,
			}},
			Takeovers: []TakeoverView{{
				Subdomain: payload, CNAME: payload, Service: payload,
				Confidence: payload, Evidence: payload, DiscoveredAt: now,
			}},
		},
	}

	var buf bytes.Buffer
	if err := RenderPage(&buf, "domain-base", data); err != nil {
		t.Fatalf("RenderPage: %v", err)
	}
	out := buf.String()

	if strings.Contains(out, quotedJS) {
		t.Fatalf("rendered page still embeds payload as a JS string literal: %q", quotedJS)
	}
	if !strings.Contains(out, "openAssetModal('ports')") {
		t.Fatal("expected domain detail page to open asset modals without Alpine activeModal")
	}
	if !strings.Contains(out, `id="modal-body-ports"`) {
		t.Fatal("expected lazy-loaded ports modal body target")
	}
	if strings.Contains(out, `x-data="{ activeModal: null }"`) {
		t.Fatal("domain detail page still binds all modals to a single Alpine activeModal tree")
	}
	if !strings.Contains(out, "xss&#39;);alert(1);//") {
		t.Fatal("expected HTML-escaped payload in attributes")
	}

	var modal bytes.Buffer
	if err := RenderPartial(&modal, "ports-modal-body", data); err != nil {
		t.Fatalf("RenderPartial ports-modal-body: %v", err)
	}
	modalOut := modal.String()
	if strings.Contains(modalOut, quotedJS) {
		t.Fatalf("ports modal still embeds payload as a JS string literal: %q", quotedJS)
	}
	if !strings.Contains(modalOut, `data-search="`) {
		t.Fatal("expected data-search attributes for Alpine filtering")
	}
	if !strings.Contains(modalOut, "$el.dataset.search") {
		t.Fatal("expected Alpine x-show to read dataset.search")
	}
	if !strings.Contains(modalOut, "xss&#39;);alert(1);//") {
		t.Fatal("expected HTML-escaped payload in modal attributes")
	}
}
