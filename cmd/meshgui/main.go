// meshgui is a simple graphical wrapper for the mesh client.
// Double-click to launch — it opens a browser tab with a clean
// connect/disconnect UI. No terminal needed.
package main

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"syscall"

	"github.com/bookloverjw/meshnet/internal/client"
	"github.com/bookloverjw/meshnet/internal/config"
	"github.com/bookloverjw/meshnet/internal/protocol"
)

//go:embed static
var staticFiles embed.FS

// appState holds the current connection state for the API.
type appState struct {
	mu         sync.RWMutex
	connected  bool
	status     string
	peerCount  int
	peers      []peerEntry
	deviceName string
	publicKey  string
	tunnelIP   string

	client *client.Client
	cancel context.CancelFunc
	cfg    *config.Config
}

type peerEntry struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key"`
	Online    bool   `json:"online"`
}

type statusResponse struct {
	Connected  bool        `json:"connected"`
	Status     string      `json:"status"`
	PeerCount  int         `json:"peer_count"`
	Peers      []peerEntry `json:"peers"`
	DeviceName string      `json:"device_name"`
	PublicKey  string      `json:"public_key"`
	TunnelIP   string      `json:"tunnel_ip"`
}

var state = &appState{
	status: "Disconnected",
}

func main() {
	// Load config
	cfg, err := config.Load()
	if err != nil {
		// Try to give a helpful message on first run
		fmt.Println("Config not found. Run 'mesh init' first to set up this device.")
		fmt.Println("Or place config.json in the meshnet config directory.")
		fmt.Printf("Error: %v\n", err)
		waitForEnter()
		os.Exit(1)
	}

	state.cfg = cfg
	state.deviceName = cfg.DeviceName
	state.publicKey = cfg.PublicKey
	state.tunnelIP = cfg.TunnelIPv4

	// Find a free port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatalf("failed to find free port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	url := fmt.Sprintf("http://%s", addr)

	// Set up HTTP routes
	mux := http.NewServeMux()
	mux.Handle("/", http.FileServer(http.FS(staticFiles)))
	mux.HandleFunc("/api/status", handleStatus)
	mux.HandleFunc("/api/connect", handleConnect)
	mux.HandleFunc("/api/disconnect", handleDisconnect)

	// Start server
	go func() {
		log.Printf("meshgui listening on %s", url)
		if err := http.ListenAndServe(addr, mux); err != nil {
			log.Fatal(err)
		}
	}()

	// Open browser
	openBrowser(url + "/static/")

	fmt.Println("Meshnet is running. Close this window to quit.")

	// Wait for signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	<-sigCh

	// Cleanup
	state.mu.Lock()
	if state.cancel != nil {
		state.cancel()
	}
	if state.client != nil {
		state.client.Disconnect()
	}
	state.mu.Unlock()
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	state.mu.RLock()
	resp := statusResponse{
		Connected:  state.connected,
		Status:     state.status,
		PeerCount:  state.peerCount,
		Peers:      state.peers,
		DeviceName: state.deviceName,
		PublicKey:  state.publicKey,
		TunnelIP:   state.tunnelIP,
	}
	state.mu.RUnlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state.mu.Lock()
	if state.connected {
		state.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"status": "already connected"})
		return
	}
	state.status = "Connecting..."
	state.mu.Unlock()

	go doConnect()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "connecting"})
}

func handleDisconnect(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	state.mu.Lock()
	if !state.connected {
		state.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"status": "not connected"})
		return
	}

	if state.cancel != nil {
		state.cancel()
	}
	if state.client != nil {
		state.client.Disconnect()
	}
	state.connected = false
	state.status = "Disconnected"
	state.peerCount = 0
	state.peers = nil
	state.client = nil
	state.cancel = nil
	state.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "disconnected"})
}

func doConnect() {
	c, err := client.New(state.cfg)
	if err != nil {
		state.mu.Lock()
		state.status = fmt.Sprintf("Error: %v", err)
		state.mu.Unlock()
		return
	}

	ctx, cancel := context.WithCancel(context.Background())

	c.OnPeerUpdate = func(peers []protocol.PeerInfo) {
		state.mu.Lock()
		state.peerCount = 0
		state.peers = nil
		for _, p := range peers {
			if p.PublicKey == state.publicKey {
				continue
			}
			if p.Online {
				state.peerCount++
			}
			state.peers = append(state.peers, peerEntry{
				Name:      p.Name,
				PublicKey: p.PublicKey,
				Online:    p.Online,
			})
		}
		state.mu.Unlock()
	}

	c.OnConnected = func(peerName string, tunnelIP string) {
		state.mu.Lock()
		state.status = fmt.Sprintf("Tunneled to %s (%s)", peerName, tunnelIP)
		state.mu.Unlock()
	}

	if err := c.Connect(ctx); err != nil {
		cancel()
		state.mu.Lock()
		state.status = fmt.Sprintf("Connection failed: %v", err)
		state.connected = false
		state.mu.Unlock()
		return
	}

	state.mu.Lock()
	state.connected = true
	state.status = "Connected"
	state.client = c
	state.cancel = cancel
	state.mu.Unlock()
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	cmd.Start()
}

func waitForEnter() {
	fmt.Println("\nPress Enter to exit...")
	buf := make([]byte, 1)
	os.Stdin.Read(buf)
}
