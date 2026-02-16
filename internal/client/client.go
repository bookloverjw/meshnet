// Package client implements the mesh network client that connects to the
// relay server, discovers peers, and establishes WireGuard tunnels.
package client

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/bookloverjw/meshnet/internal/config"
	"github.com/bookloverjw/meshnet/internal/crypto"
	"github.com/bookloverjw/meshnet/internal/nat"
	"github.com/bookloverjw/meshnet/internal/protocol"
	"github.com/bookloverjw/meshnet/internal/tunnel"
	"nhooyr.io/websocket"
)

// Client manages the mesh network connection.
type Client struct {
	cfg  *config.Config
	conn *websocket.Conn
	ctx  context.Context

	mu       sync.RWMutex
	peers    map[string]protocol.PeerInfo // keyed by public key
	tunnelUp bool

	privKey crypto.Key
	pubKey  crypto.Key

	OnPeerUpdate func(peers []protocol.PeerInfo)
	OnConnected  func(peerName string, tunnelIP string)
}

// New creates a new mesh client from the given configuration.
func New(cfg *config.Config) (*Client, error) {
	privKey, err := crypto.ParseKey(cfg.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	return &Client{
		cfg:     cfg,
		peers:   make(map[string]protocol.PeerInfo),
		privKey: privKey,
		pubKey:  privKey.PublicKey(),
	}, nil
}

// Connect establishes a connection to the relay server.
func (c *Client) Connect(ctx context.Context) error {
	c.ctx = ctx

	url := fmt.Sprintf("wss://%s:%d/ws", c.cfg.RelayAddr, c.cfg.RelayPort)

	// Set auth token from config or environment
	authToken := c.cfg.AuthToken
	if authToken == "" {
		authToken = os.Getenv("MESHNET_AUTH_TOKEN")
	}
	headers := make(http.Header)
	if authToken != "" {
		headers.Set("Authorization", "Bearer "+authToken)
	}
	opts := &websocket.DialOptions{
		HTTPHeader: headers,
	}

	conn, _, err := websocket.Dial(ctx, url, opts)
	if err != nil {
		// Fall back to non-TLS for local/dev
		url = fmt.Sprintf("ws://%s:%d/ws", c.cfg.RelayAddr, c.cfg.RelayPort)
		conn, _, err = websocket.Dial(ctx, url, opts)
		if err != nil {
			return fmt.Errorf("connect to relay: %w", err)
		}
	}
	c.conn = conn

	// Register with the relay
	if err := c.register(); err != nil {
		conn.Close(websocket.StatusInternalError, "register failed")
		return err
	}

	// Start message handler and heartbeat
	go c.readLoop()
	go c.heartbeatLoop()

	log.Printf("connected to relay at %s", c.cfg.RelayAddr)
	return nil
}

func (c *Client) register() error {
	// Discover our endpoints
	endpoints, _ := nat.LocalEndpoints(c.cfg.ListenPort)

	publicEndpoint, err := nat.DiscoverEndpoint(nil)
	if err == nil {
		endpoints = append(endpoints, publicEndpoint)
	}

	payload := protocol.RegisterPayload{
		PublicKey:  c.pubKey.String(),
		Name:      c.cfg.DeviceName,
		Endpoints: endpoints,
	}

	return c.send(protocol.MsgRegister, "", payload)
}

func (c *Client) send(msgType protocol.MessageType, to string, payload any) error {
	env, err := protocol.MarshalPayload(msgType, c.pubKey.String(), to, payload)
	if err != nil {
		return err
	}
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return c.conn.Write(c.ctx, websocket.MessageText, data)
}

func (c *Client) readLoop() {
	for {
		_, data, err := c.conn.Read(c.ctx)
		if err != nil {
			log.Printf("relay connection lost: %v", err)
			return
		}

		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			continue
		}

		switch env.Type {
		case protocol.MsgPeerList:
			c.handlePeerList(env.Payload)
		case protocol.MsgPunchReply:
			c.handlePunchReply(env.Payload)
		case protocol.MsgConnect:
			c.handleConnect(env)
		case protocol.MsgConnectAck:
			c.handleConnectAck(env)
		case protocol.MsgRelay:
			c.handleRelay(env)
		case protocol.MsgError:
			var errPayload protocol.ErrorPayload
			json.Unmarshal(env.Payload, &errPayload)
			log.Printf("relay error: %s", errPayload.Message)
		}
	}
}

func (c *Client) heartbeatLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-c.ctx.Done():
			return
		case <-ticker.C:
			c.send(protocol.MsgHeartbeat, "", nil)
		}
	}
}

func (c *Client) handlePeerList(data json.RawMessage) {
	var payload protocol.PeerListPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return
	}

	c.mu.Lock()
	c.peers = make(map[string]protocol.PeerInfo)
	for _, p := range payload.Peers {
		if p.PublicKey != c.pubKey.String() {
			c.peers[p.PublicKey] = p
		}
	}
	c.mu.Unlock()

	if c.OnPeerUpdate != nil {
		c.OnPeerUpdate(payload.Peers)
	}

	log.Printf("peer list updated: %d peers online", len(c.peers))
}

func (c *Client) handlePunchReply(data json.RawMessage) {
	var payload protocol.PunchReplyPayload
	if err := json.Unmarshal(data, &payload); err != nil {
		return
	}

	log.Printf("attempting hole punch to %s with %d endpoints",
		payload.PeerKey[:16]+"...", len(payload.Endpoints))

	go func() {
		conn, raddr, err := nat.HolePunch(c.cfg.ListenPort, payload.Endpoints, 10*time.Second)
		if err != nil {
			log.Printf("hole punch failed: %v (will use relay)", err)
			return
		}
		conn.Close()
		log.Printf("hole punch succeeded to %s", raddr.String())
	}()
}

// ConnectToPeer initiates a WireGuard tunnel to the specified peer.
func (c *Client) ConnectToPeer(peerKey string) error {
	c.mu.RLock()
	peer, ok := c.peers[peerKey]
	c.mu.RUnlock()

	if !ok {
		return fmt.Errorf("peer not found: %s", peerKey[:16]+"...")
	}

	// Request hole punch via relay
	c.send(protocol.MsgPunchReq, "", protocol.PunchRequestPayload{
		TargetKey: peerKey,
	})

	// Small delay to let hole punch attempt proceed
	time.Sleep(2 * time.Second)

	// Send connect request
	payload := protocol.ConnectPayload{
		TargetKey:   peerKey,
		WGPublicKey: c.pubKey.String(),
		TunnelIPv4:  c.cfg.TunnelIPv4,
	}

	log.Printf("requesting tunnel to %s...", peer.Name)
	return c.send(protocol.MsgConnect, peerKey, payload)
}

func (c *Client) handleConnect(env protocol.Envelope) {
	var payload protocol.ConnectPayload
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		return
	}

	// Check if peer is trusted
	trusted := false
	for _, tp := range c.cfg.TrustedPeers {
		if tp.PublicKey == payload.WGPublicKey {
			trusted = true
			break
		}
	}
	if !trusted {
		log.Printf("rejected connection from untrusted peer: %s", payload.WGPublicKey[:16]+"...")
		return
	}

	log.Printf("accepted tunnel request from %s", payload.WGPublicKey[:16]+"...")

	// Set up WireGuard tunnel
	peerPubKey, err := crypto.ParseKey(payload.WGPublicKey)
	if err != nil {
		return
	}

	wgCfg := &tunnel.Config{
		PrivateKey: c.privKey,
		ListenPort: c.cfg.ListenPort,
		Address:    c.cfg.TunnelIPv4 + "/24",
		MTU:        c.cfg.MTU,
		Peers: []tunnel.PeerConfig{
			{
				PublicKey:  peerPubKey,
				AllowedIPs: []string{payload.TunnelIPv4 + "/32"},
				KeepAlive:  25,
			},
		},
	}

	if err := tunnel.Up(wgCfg); err != nil {
		log.Printf("failed to bring up tunnel: %v", err)
		return
	}

	c.mu.Lock()
	c.tunnelUp = true
	c.mu.Unlock()

	// Send ack
	ack := protocol.ConnectAckPayload{
		WGPublicKey: c.pubKey.String(),
		TunnelIPv4:  c.cfg.TunnelIPv4,
		UseRelay:    false,
	}
	c.send(protocol.MsgConnectAck, env.From, ack)

	if c.OnConnected != nil {
		c.OnConnected(env.From, payload.TunnelIPv4)
	}
}

func (c *Client) handleConnectAck(env protocol.Envelope) {
	var payload protocol.ConnectAckPayload
	if err := json.Unmarshal(env.Payload, &payload); err != nil {
		return
	}

	peerPubKey, err := crypto.ParseKey(payload.WGPublicKey)
	if err != nil {
		return
	}

	wgCfg := &tunnel.Config{
		PrivateKey: c.privKey,
		ListenPort: c.cfg.ListenPort,
		Address:    c.cfg.TunnelIPv4 + "/24",
		MTU:        c.cfg.MTU,
		Peers: []tunnel.PeerConfig{
			{
				PublicKey:  peerPubKey,
				AllowedIPs: []string{payload.TunnelIPv4 + "/32"},
				KeepAlive:  25,
			},
		},
	}

	if err := tunnel.Up(wgCfg); err != nil {
		log.Printf("failed to bring up tunnel: %v", err)
		return
	}

	c.mu.Lock()
	c.tunnelUp = true
	c.mu.Unlock()

	log.Printf("tunnel established! peer tunnel IP: %s", payload.TunnelIPv4)

	if c.OnConnected != nil {
		c.OnConnected(env.From, payload.TunnelIPv4)
	}
}

func (c *Client) handleRelay(env protocol.Envelope) {
	// Relay messages pass encrypted WireGuard packets through the server
	// when direct P2P isn't possible. This is handled at the transport layer.
	log.Printf("relayed packet from %s", env.From[:16]+"...")
}

// Disconnect tears down the tunnel and disconnects from the relay.
func (c *Client) Disconnect() error {
	c.mu.Lock()
	wasUp := c.tunnelUp
	c.tunnelUp = false
	c.mu.Unlock()

	if wasUp {
		if err := tunnel.Down(); err != nil {
			log.Printf("tunnel down: %v", err)
		}
	}

	if c.conn != nil {
		return c.conn.Close(websocket.StatusNormalClosure, "disconnecting")
	}
	return nil
}

// Peers returns the current list of known peers.
func (c *Client) Peers() []protocol.PeerInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	peers := make([]protocol.PeerInfo, 0, len(c.peers))
	for _, p := range c.peers {
		peers = append(peers, p)
	}
	return peers
}

// IsTunnelUp returns whether a tunnel is currently active.
func (c *Client) IsTunnelUp() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.tunnelUp
}
