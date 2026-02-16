// meshd is the relay/coordination server for the meshnet network.
// Deploy this on a small VPS (e.g. a $5/mo DigitalOcean droplet).
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/bookloverjw/meshnet/internal/relay"
)

func main() {
	var (
		addr     = flag.String("addr", ":443", "listen address (host:port)")
		cert     = flag.String("cert", "", "TLS certificate file (optional, uses HTTP if empty)")
		key      = flag.String("key", "", "TLS private key file (optional)")
		token    = flag.String("token", "", "shared auth token (clients must present this to connect)")
		udpPort  = flag.Int("udp-port", 51820, "UDP relay port for WireGuard packet forwarding")
	)
	flag.Parse()

	if *token == "" {
		// Check env var
		*token = os.Getenv("MESHNET_AUTH_TOKEN")
	}
	if *token == "" {
		fmt.Fprintln(os.Stderr, "warning: no auth token set. Set --token or MESHNET_AUTH_TOKEN env var.")
		fmt.Fprintln(os.Stderr, "         anyone can connect to this relay without authentication.")
	}

	srv := relay.NewServer(*token)

	// Start UDP relay for WireGuard packet forwarding
	go func() {
		if err := srv.StartUDPRelay(*udpPort); err != nil {
			log.Fatalf("UDP relay: %v", err)
		}
	}()

	// Start stale peer cleanup
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go srv.StartCleanup(ctx, 1*time.Minute, 5*time.Minute)

	// Handle shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		log.Println("shutting down...")
		cancel()
		os.Exit(0)
	}()

	log.Printf("meshnet relay server starting on %s", *addr)
	if err := srv.ListenAndServe(*addr, *cert, *key); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
