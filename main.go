package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/costinm/dns-sync-gcp/pkg/provider/google"
	"github.com/costinm/dns-sync/pkg/config"
	"github.com/costinm/dns-sync/pkg/dns_service"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Webhook service using the external-dns providers.
// The rest of dns-sync is decoupled - only uses the webhook interface (and may
// use CRDs or other neutral interfaces).
func main() {
	// Load the config file
	ctx := context.Background()
	gcfg, err := config.Get[google.GoogleProviderConfig](ctx, "google-dns")
	if err != nil {
		log.Fatal("Failed to parse config`", err)
	}

	mux := http.NewServeMux()

	Start(mux, gcfg)

	// Start the HTTP server.
	go func() {
		log.Fatal(http.ListenAndServe(":8080", mux))
	}()

	http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	http.Handle("/metrics", promhttp.Handler())
	http.Handle("/stats/prometheus", promhttp.Handler())

	go func() {
		log.Fatal(http.ListenAndServe(":15020", http.DefaultServeMux))
	}()

	// Wait for a signal to stop the server.
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

}

func Start(mux *http.ServeMux, cfg *google.GoogleProviderConfig) *google.GoogleProvider {

	googlep, err := google.NewGoogleProvider(context.Background(), cfg)
	if err != nil {
		log.Fatal("Failed to start google provider", err)
	}

	// DNS sync handler
	mp := &google.MultiProject{}
	dns_service.InitHandlers(googlep, mux, "/google")

	mux.HandleFunc( "/dns/p/{project}/z/{zone}/", mp.Handle)
	//mux.HandleFunc( "/dns/p/{project}/z/{zone}/records", p.RecordsHandler)
	//mux.HandleFunc( "/dns/p/{project}/z/{zone}/adjustendpoints", p.AdjustEndpointsHandler)

	return googlep
}
