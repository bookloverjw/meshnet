// Package protocol defines the wire protocol messages exchanged between
// mesh clients and the relay/coordination server.
package protocol

import (
	"encoding/json"
	"time"
)

// MessageType identifies the kind of protocol message.
type MessageType string

const (
	MsgRegister    MessageType = "register"
	MsgPeerList    MessageType = "peer_list"
	MsgPunchReq    MessageType = "punch_request"
	MsgPunchReply  MessageType = "punch_reply"
	MsgRelay       MessageType = "relay"
	MsgHeartbeat   MessageType = "heartbeat"
	MsgConnect     MessageType = "connect"
	MsgConnectAck  MessageType = "connect_ack"
	MsgDisconnect  MessageType = "disconnect"
	MsgError       MessageType = "error"
)

// Envelope wraps every message on the wire.
type Envelope struct {
	Type      MessageType     `json:"type"`
	From      string          `json:"from"`
	To        string          `json:"to,omitempty"`
	Timestamp time.Time       `json:"ts"`
	Payload   json.RawMessage `json:"payload"`
}

// RegisterPayload is sent by a client when it first connects to the relay.
type RegisterPayload struct {
	PublicKey  string   `json:"public_key"`
	Name      string   `json:"name"`
	Endpoints []string `json:"endpoints"`
}

// PeerInfo describes a connected peer.
type PeerInfo struct {
	PublicKey  string   `json:"public_key"`
	Name      string   `json:"name"`
	Endpoints []string `json:"endpoints"`
	RelayOnly bool     `json:"relay_only"`
	Online    bool     `json:"online"`
}

// PeerListPayload is the relay's response containing all known peers.
type PeerListPayload struct {
	Peers []PeerInfo `json:"peers"`
}

// PunchRequestPayload asks the relay to coordinate a NAT hole-punch.
type PunchRequestPayload struct {
	TargetKey string `json:"target_key"`
}

// PunchReplyPayload tells a peer where to send UDP packets for hole-punching.
type PunchReplyPayload struct {
	PeerKey   string   `json:"peer_key"`
	Endpoints []string `json:"endpoints"`
}

// RelayPayload wraps encrypted WireGuard packets sent through the relay
// when direct P2P connection fails.
type RelayPayload struct {
	Data []byte `json:"data"`
}

// ConnectPayload requests a tunnel to a specific peer.
type ConnectPayload struct {
	TargetKey   string `json:"target_key"`
	WGPublicKey string `json:"wg_public_key"`
	WGEndpoint  string `json:"wg_endpoint,omitempty"`
	TunnelIPv4  string `json:"tunnel_ipv4"`
}

// ConnectAckPayload confirms a tunnel setup.
type ConnectAckPayload struct {
	WGPublicKey string `json:"wg_public_key"`
	WGEndpoint  string `json:"wg_endpoint,omitempty"`
	TunnelIPv4  string `json:"tunnel_ipv4"`
	UseRelay    bool   `json:"use_relay"`
}

// ErrorPayload carries error information.
type ErrorPayload struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// MarshalPayload marshals a payload into JSON and wraps it in an Envelope.
func MarshalPayload(msgType MessageType, from, to string, payload any) (*Envelope, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return &Envelope{
		Type:      msgType,
		From:      from,
		To:        to,
		Timestamp: time.Now().UTC(),
		Payload:   data,
	}, nil
}
