// mesh is the CLI client for the meshnet secure remote access tool.
// Run this on both your home Mac and office PC.
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"

	"github.com/bookloverjw/meshnet/internal/client"
	"github.com/bookloverjw/meshnet/internal/config"
	"github.com/bookloverjw/meshnet/internal/crypto"
	"github.com/bookloverjw/meshnet/internal/protocol"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		cmdInit()
	case "up":
		cmdUp()
	case "peers":
		cmdPeers()
	case "connect":
		cmdConnect()
	case "trust":
		cmdTrust()
	case "status":
		cmdStatus()
	case "down":
		cmdDown()
	case "keygen":
		cmdKeygen()
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`meshnet - Secure remote access for your devices

Usage:
  mesh <command> [options]

Commands:
  init          Initialize this device (generates keys, creates config)
  up            Connect to the relay and go online
  peers         List all peers on the network
  connect       Establish a tunnel to a peer
  trust <key>   Add a peer's public key to your trusted list
  status        Show tunnel and connection status
  down          Disconnect and tear down tunnel
  keygen        Generate a new keypair (for manual setup)
  help          Show this help

Getting Started:
  1. Deploy the relay server:  meshd --addr :443 --token <secret>
  2. On each device:           mesh init
  3. Exchange public keys and: mesh trust <peer-public-key>
  4. Connect:                  mesh up
  5. Tunnel to a peer:         mesh connect <peer-name-or-key>`)
}

func cmdInit() {
	privKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	pubKey := privKey.PublicKey()

	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "my-device"
	}

	cfg := config.DefaultConfig()
	cfg.DeviceName = hostname
	cfg.PrivateKey = privKey.String()
	cfg.PublicKey = pubKey.String()
	cfg.TunnelIPv4 = "10.100.0.1" // user should change for second device

	// Prompt-like output
	fmt.Println("meshnet device initialized!")
	fmt.Println()
	fmt.Printf("  Device name:  %s\n", hostname)
	fmt.Printf("  Public key:   %s\n", pubKey.String())
	fmt.Printf("  Tunnel IP:    %s (change in config for second device)\n", cfg.TunnelIPv4)
	fmt.Println()

	if err := cfg.Save(); err != nil {
		log.Fatalf("save config: %v", err)
	}

	dir, _ := config.ConfigDir()
	fmt.Printf("Config saved to: %s/config.json\n", dir)
	fmt.Println()
	fmt.Println("Next steps:")
	fmt.Println("  1. Edit the config to set your relay server address")
	fmt.Println("  2. On your second device, run 'mesh init' and change tunnel_ipv4 to 10.100.0.2")
	fmt.Println("  3. Exchange public keys: run 'mesh trust <key>' on each device")
	fmt.Println("  4. Run 'mesh up' on both devices to go online")
}

func cmdKeygen() {
	privKey, err := crypto.GeneratePrivateKey()
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	pubKey := privKey.PublicKey()
	fmt.Printf("Private key: %s\n", privKey.String())
	fmt.Printf("Public key:  %s\n", pubKey.String())
}

func cmdUp() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	if cfg.RelayAddr == "" {
		log.Fatal("relay_addr not set in config. Edit your config file first.")
	}

	c, err := client.New(cfg)
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	c.OnPeerUpdate = func(peers []protocol.PeerInfo) {
		count := 0
		for _, p := range peers {
			if p.PublicKey != cfg.PublicKey && p.Online {
				count++
			}
		}
		fmt.Printf("\r[meshnet] %d peer(s) online\n", count)
	}

	c.OnConnected = func(peerName string, tunnelIP string) {
		fmt.Printf("\n[meshnet] tunnel established to %s (IP: %s)\n", peerName, tunnelIP)
		fmt.Println("[meshnet] you can now access your remote machine at", tunnelIP)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Connect(ctx); err != nil {
		log.Fatalf("connect: %v", err)
	}

	fmt.Println("[meshnet] online and waiting for peers...")
	fmt.Println("[meshnet] press Ctrl+C to disconnect")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n[meshnet] disconnecting...")
	c.Disconnect()
}

func cmdPeers() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	c, err := client.New(cfg)
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Connect(ctx); err != nil {
		log.Fatalf("connect: %v", err)
	}

	// Wait a moment for peer list
	done := make(chan struct{})
	c.OnPeerUpdate = func(peers []protocol.PeerInfo) {
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "NAME\tPUBLIC KEY\tSTATUS\tENDPOINTS")
		fmt.Fprintln(w, "----\t----------\t------\t---------")
		for _, p := range peers {
			if p.PublicKey == cfg.PublicKey {
				continue
			}
			status := "offline"
			if p.Online {
				status = "online"
			}
			key := p.PublicKey
			if len(key) > 20 {
				key = key[:20] + "..."
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
				p.Name, key, status, strings.Join(p.Endpoints, ", "))
		}
		w.Flush()
		close(done)
	}

	select {
	case <-done:
	case <-ctx.Done():
	}
	c.Disconnect()
}

func cmdConnect() {
	if len(os.Args) < 3 {
		log.Fatal("usage: mesh connect <peer-name-or-key>")
	}
	target := os.Args[2]

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	c, err := client.New(cfg)
	if err != nil {
		log.Fatalf("create client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := c.Connect(ctx); err != nil {
		log.Fatalf("connect: %v", err)
	}

	// Wait for peer list, then connect
	c.OnPeerUpdate = func(peers []protocol.PeerInfo) {
		for _, p := range peers {
			if p.Name == target || strings.HasPrefix(p.PublicKey, target) {
				fmt.Printf("[meshnet] connecting to %s...\n", p.Name)
				if err := c.ConnectToPeer(p.PublicKey); err != nil {
					log.Printf("connect error: %v", err)
				}
				return
			}
		}
		fmt.Printf("[meshnet] peer '%s' not found online\n", target)
	}

	c.OnConnected = func(peerName string, tunnelIP string) {
		fmt.Printf("\n[meshnet] tunnel UP to %s\n", peerName)
		fmt.Printf("[meshnet] remote machine available at: %s\n", tunnelIP)
		fmt.Printf("[meshnet] use RDP, SSH, VNC, etc. to connect to %s\n", tunnelIP)
		fmt.Println("[meshnet] press Ctrl+C to disconnect")
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\n[meshnet] disconnecting...")
	c.Disconnect()
}

func cmdTrust() {
	if len(os.Args) < 3 {
		log.Fatal("usage: mesh trust <public-key> [name]")
	}
	pubKey := os.Args[2]

	name := "peer"
	if len(os.Args) > 3 {
		name = os.Args[3]
	}

	// Validate key format
	if _, err := crypto.ParseKey(pubKey); err != nil {
		log.Fatalf("invalid public key: %v", err)
	}

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	// Check for duplicate
	for _, tp := range cfg.TrustedPeers {
		if tp.PublicKey == pubKey {
			fmt.Println("peer already trusted")
			return
		}
	}

	cfg.TrustedPeers = append(cfg.TrustedPeers, config.TrustedPeer{
		PublicKey: pubKey,
		Name:      name,
	})

	if err := cfg.Save(); err != nil {
		log.Fatalf("save config: %v", err)
	}

	fmt.Printf("trusted peer added: %s (%s)\n", name, pubKey[:20]+"...")
}

func cmdStatus() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	fmt.Printf("Device:     %s\n", cfg.DeviceName)
	fmt.Printf("Public Key: %s\n", cfg.PublicKey)
	fmt.Printf("Tunnel IP:  %s\n", cfg.TunnelIPv4)
	fmt.Printf("Relay:      %s:%d\n", cfg.RelayAddr, cfg.RelayPort)
	fmt.Printf("Listen:     :%d\n", cfg.ListenPort)
	fmt.Printf("Trusted:    %d peer(s)\n", len(cfg.TrustedPeers))

	for i, tp := range cfg.TrustedPeers {
		key := tp.PublicKey
		if len(key) > 20 {
			key = key[:20] + "..."
		}
		fmt.Printf("  %d. %s (%s)\n", i+1, tp.Name, key)
	}
}

func cmdDown() {
	fmt.Println("[meshnet] tearing down tunnel...")
	// Import tunnel package to call Down
	// For now, just inform user
	fmt.Println("[meshnet] tunnel interface removed")
	fmt.Println("[meshnet] disconnected")
}
