package google

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/costinm/dns-sync/pkg/dns_service"
	"github.com/costinm/dns-sync/provider/webhook"
)

// main starts a barebones webhook for the Google provider.
// Primary goal is to validate the minimal configuration and identify the size of the binary vs exernal-dns.
// Initial test shows 31M versus 138M with all providers (23 vs 98 stripped)

func InitGoogleProvider() (*GoogleProvider, error) {
	cfgs := os.Getenv("CFG")

	edns := &GoogleProviderConfig{}
	json.Unmarshal([]byte(cfgs), edns)

	if edns.GoogleProject == "" {
		edns.GoogleProject = "dmeshgate"
	}

	ctx := context.Background()

	p, err := NewGoogleProvider(ctx, edns)
	if err != nil {
		panic(err)
	}

	return p, nil
}


// TestDnsGoogle is an e2e test that validates the Google Cloud DNS provider implementation
// and the new config model.
func TestDnsGoogle(t *testing.T) {
	ctx := context.Background()

	zp, err := InitGoogleProvider()
	if err != nil {
		if zp.GoogleProviderConfig.GoogleProject == "" {
			t.Skip("Requires GOOGLE_PROJECT_ID")
		}
		t.Fatal(err)
	}
	z, err := zp.Zones(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("Zones:")
	zn := ""
	zd := ""
	for _, ep := range z {
		fmt.Println(ep.Name, ep.DnsName, ep.Description, ep.Labels, ep)
		zn = ep.Name
		zd = ep.DnsName
	}

	zp.GoogleProviderConfig.Zones = map[string]string{zn: zd}

	zp1, err := NewGoogleProvider(ctx, zp.GoogleProviderConfig)
	if err != nil {
		t.Fatal(err)
	}
	_, err = zp1.Records(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// // Try the HTTP-based provider

	dns_service.InitHandlers(zp, http.DefaultServeMux, "/google")
	s := httptest.NewServer(http.DefaultServeMux)
	addr := s.Listener.Addr()

	wp, err := webhook.NewWebhookProvider("http://" + addr.String() + "/google")
	if err != nil {
		t.Fatalf("Failed to create webhook provider: %v", err)
	}
	fmt.Println("Endpoints:")
	r, err := wp.Records(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, ep := range r {
		fmt.Println(ep)
	}

}
