// Package relay implements the coordination/relay server that helps
// mesh peers discover each other and relays traffic when direct
// P2P connections aren't possible.
package relay

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/bookloverjw/meshnet/internal/protocol"
	"nhooyr.io/websocket"
)

// Server is the relay/coordination server.
type Server struct {
	mu    sync.RWMutex
	peers map[string]*connectedPeer // keyed by public key

	authToken string // simple shared-secret auth
	udpRelay  *UDPRelay
}

type connectedPeer struct {
	info protocol.PeerInfo
	conn *websocket.Conn
	ctx  context.Context
	last time.Time
}

// NewServer creates a new relay server.
func NewServer(authToken string) *Server {
	return &Server{
		peers:     make(map[string]*connectedPeer),
		authToken: authToken,
		udpRelay:  NewUDPRelay(),
	}
}

// ListenAndServe starts the relay server with TLS.
func (s *Server) ListenAndServe(addr, certFile, keyFile string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", s.handleWebSocket)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	log.Printf("relay server listening on %s", addr)

	if certFile != "" && keyFile != "" {
		return http.ListenAndServeTLS(addr, certFile, keyFile, mux)
	}
	return http.ListenAndServe(addr, mux)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Authenticate
	token := r.Header.Get("Authorization")
	if s.authToken != "" && token != "Bearer "+s.authToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // allows any origin for mesh clients
	})
	if err != nil {
		log.Printf("websocket accept: %v", err)
		return
	}

	ctx := r.Context()
	s.handleConn(ctx, conn)
}

func (s *Server) handleConn(ctx context.Context, conn *websocket.Conn) {
	defer conn.Close(websocket.StatusNormalClosure, "bye")

	var peerKey string
	defer func() {
		if peerKey != "" {
			s.removePeer(peerKey)
			s.broadcastPeerList()
		}
	}()

	for {
		_, data, err := conn.Read(ctx)
		if err != nil {
			return
		}

		var env protocol.Envelope
		if err := json.Unmarshal(data, &env); err != nil {
			s.sendError(ctx, conn, 400, "invalid message format")
			continue
		}

		switch env.Type {
		case protocol.MsgRegister:
			var payload protocol.RegisterPayload
			if err := json.Unmarshal(env.Payload, &payload); err != nil {
				s.sendError(ctx, conn, 400, "invalid register payload")
				continue
			}
			peerKey = payload.PublicKey
			s.addPeer(peerKey, payload, ctx, conn)
			s.broadcastPeerList()

		case protocol.MsgHeartbeat:
			s.mu.Lock()
			if p, ok := s.peers[env.From]; ok {
				p.last = time.Now()
			}
			s.mu.Unlock()

		case protocol.MsgPunchReq:
			var payload protocol.PunchRequestPayload
			if err := json.Unmarshal(env.Payload, &payload); err != nil {
				continue
			}
			s.coordinatePunch(ctx, env.From, payload.TargetKey)

		case protocol.MsgConnect:
			s.udpRelay.AddTunnelPair(env.From, env.To)
			s.forwardTo(ctx, env)

		case protocol.MsgConnectAck:
			s.forwardTo(ctx, env)

		case protocol.MsgRelay:
			s.forwardTo(ctx, env)

		case protocol.MsgDisconnect:
			s.forwardTo(ctx, env)
		}
	}
}

func (s *Server) addPeer(key string, payload protocol.RegisterPayload, ctx context.Context, conn *websocket.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.peers[key] = &connectedPeer{
		info: protocol.PeerInfo{
			PublicKey:  payload.PublicKey,
			Name:      payload.Name,
			Endpoints: payload.Endpoints,
			Online:    true,
		},
		conn: conn,
		ctx:  ctx,
		last: time.Now(),
	}
	log.Printf("peer registered: %s (%s)", payload.Name, key[:16]+"...")
}

func (s *Server) removePeer(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.peers[key]; ok {
		log.Printf("peer disconnected: %s", p.info.Name)
		delete(s.peers, key)
	}
}

func (s *Server) broadcastPeerList() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var peers []protocol.PeerInfo
	for _, p := range s.peers {
		peers = append(peers, p.info)
	}

	payload := protocol.PeerListPayload{Peers: peers}
	data, _ := json.Marshal(payload)

	for key, p := range s.peers {
		env := protocol.Envelope{
			Type:      protocol.MsgPeerList,
			From:      "relay",
			To:        key,
			Timestamp: time.Now().UTC(),
			Payload:   data,
		}
		envData, _ := json.Marshal(env)
		p.conn.Write(p.ctx, websocket.MessageText, envData)
	}
}

func (s *Server) coordinatePunch(ctx context.Context, fromKey, targetKey string) {
	s.mu.RLock()
	fromPeer, fromOK := s.peers[fromKey]
	targetPeer, targetOK := s.peers[targetKey]
	s.mu.RUnlock()

	if !fromOK || !targetOK {
		return
	}

	// Tell each peer about the other's endpoints
	sendPunchReply := func(to *connectedPeer, aboutPeer *connectedPeer) {
		payload := protocol.PunchReplyPayload{
			PeerKey:   aboutPeer.info.PublicKey,
			Endpoints: aboutPeer.info.Endpoints,
		}
		data, _ := json.Marshal(payload)
		env := protocol.Envelope{
			Type:      protocol.MsgPunchReply,
			From:      "relay",
			To:        to.info.PublicKey,
			Timestamp: time.Now().UTC(),
			Payload:   data,
		}
		envData, _ := json.Marshal(env)
		to.conn.Write(to.ctx, websocket.MessageText, envData)
	}

	sendPunchReply(fromPeer, targetPeer)
	sendPunchReply(targetPeer, fromPeer)
}

func (s *Server) forwardTo(ctx context.Context, env protocol.Envelope) {
	s.mu.RLock()
	target, ok := s.peers[env.To]
	s.mu.RUnlock()

	if !ok {
		return
	}

	data, _ := json.Marshal(env)
	target.conn.Write(target.ctx, websocket.MessageText, data)
}

func (s *Server) sendError(ctx context.Context, conn *websocket.Conn, code int, msg string) {
	payload := protocol.ErrorPayload{Code: code, Message: msg}
	env, _ := protocol.MarshalPayload(protocol.MsgError, "relay", "", payload)
	data, _ := json.Marshal(env)
	conn.Write(ctx, websocket.MessageText, data)
}

// StartCleanup periodically removes stale peers.
func (s *Server) StartCleanup(ctx context.Context, interval, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.cleanStalePeers(timeout)
		}
	}
}

func (s *Server) cleanStalePeers(timeout time.Duration) {
	s.mu.Lock()
	var stale []string
	for key, p := range s.peers {
		if time.Since(p.last) > timeout {
			stale = append(stale, key)
		}
	}
	for _, key := range stale {
		log.Printf("removing stale peer: %s", s.peers[key].info.Name)
		s.peers[key].conn.Close(websocket.StatusGoingAway, "timeout")
		delete(s.peers, key)
	}
	s.mu.Unlock()

	if len(stale) > 0 {
		s.broadcastPeerList()
	}
}

// StartUDPRelay starts the UDP relay for forwarding WireGuard packets.
func (s *Server) StartUDPRelay(port int) error {
	return s.udpRelay.ListenAndServe(port)
}

// PeerCount returns the number of connected peers.
func (s *Server) PeerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.peers)
}

// ListPeers returns info about all connected peers (for admin API).
func (s *Server) ListPeers() []protocol.PeerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	peers := make([]protocol.PeerInfo, 0, len(s.peers))
	for _, p := range s.peers {
		info := p.info
		info.Online = time.Since(p.last) < 2*time.Minute
		peers = append(peers, info)
	}
	return peers
}

func init() {
	// Silence unused import
	_ = fmt.Sprintf
}
