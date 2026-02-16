// UDP relay for forwarding WireGuard packets between peers
// when direct P2P connection isn't possible.
package relay

import (
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
)

const (
	udpRegisterMagic = "MREG"
	udpAckMagic      = "MACK"
)

// UDPRelay forwards WireGuard UDP packets between paired peers
// through the relay server.
type UDPRelay struct {
	mu          sync.RWMutex
	addrToKey   map[string]string      // UDP addr string -> public key
	keyToAddr   map[string]*net.UDPAddr // public key -> last-seen UDP addr
	ipToKey     map[string]string      // IP (no port) -> public key (for NAT remap)
	tunnelPairs map[string]string      // peer key -> partner key (bidirectional)
	conn        *net.UDPConn
}

// NewUDPRelay creates a new UDP relay.
func NewUDPRelay() *UDPRelay {
	return &UDPRelay{
		addrToKey:   make(map[string]string),
		keyToAddr:   make(map[string]*net.UDPAddr),
		ipToKey:     make(map[string]string),
		tunnelPairs: make(map[string]string),
	}
}

// AddTunnelPair registers a bidirectional tunnel between two peers.
func (u *UDPRelay) AddTunnelPair(keyA, keyB string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.tunnelPairs[keyA] = keyB
	u.tunnelPairs[keyB] = keyA

	shortA, shortB := keyA, keyB
	if len(shortA) > 16 {
		shortA = shortA[:16] + "..."
	}
	if len(shortB) > 16 {
		shortB = shortB[:16] + "..."
	}
	log.Printf("UDP relay: tunnel pair %s <-> %s", shortA, shortB)
}

// ListenAndServe starts the UDP relay on the given port.
func (u *UDPRelay) ListenAndServe(port int) error {
	addr := &net.UDPAddr{Port: port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	u.conn = conn
	log.Printf("UDP relay listening on :%d", port)

	pktCount := 0
	buf := make([]byte, 65535)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("UDP relay read: %v", err)
			continue
		}

		data := buf[:n]
		pktCount++
		if pktCount <= 20 {
			log.Printf("UDP relay: pkt #%d from %s (%d bytes)", pktCount, raddr, n)
		}

		// Check for registration packet: "MREG" + pubkey + "|" + wg_port
		// The client sends from an ephemeral port and includes the WireGuard
		// listen port so we can build the correct address mapping.
		if n > len(udpRegisterMagic) && string(data[:len(udpRegisterMagic)]) == udpRegisterMagic {
			payload := string(data[len(udpRegisterMagic):])

			// Parse key and WireGuard port from "pubkey|port" format.
			// Fall back to sender address if no port is specified.
			key := payload
			mappedAddr := raddr
			if idx := strings.LastIndex(payload, "|"); idx > 0 {
				key = payload[:idx]
				if wgPort, err := strconv.Atoi(payload[idx+1:]); err == nil {
					mappedAddr = &net.UDPAddr{IP: raddr.IP, Port: wgPort, Zone: raddr.Zone}
				}
			}

			u.mu.Lock()
			if oldAddr, ok := u.keyToAddr[key]; ok {
				delete(u.addrToKey, oldAddr.String())
			}
			u.addrToKey[mappedAddr.String()] = key
			u.keyToAddr[key] = mappedAddr
			u.ipToKey[raddr.IP.String()] = key
			u.mu.Unlock()

			shortKey := key
			if len(shortKey) > 16 {
				shortKey = shortKey[:16] + "..."
			}
			log.Printf("UDP relay: registered %s from %s (mapped to %s)", shortKey, raddr, mappedAddr)
			conn.WriteToUDP([]byte(udpAckMagic), raddr)
			continue
		}

		// Forward WireGuard packet to tunnel partner.
		// First try exact addr match, then fall back to IP-only match
		// to handle NAT port remapping (e.g. VPN NAT).
		u.mu.RLock()
		senderKey, ok := u.addrToKey[raddr.String()]
		u.mu.RUnlock()

		if !ok {
			// NAT may have changed the source port. Look up by IP and
			// update the mapping so future packets match immediately.
			u.mu.Lock()
			senderKey, ok = u.ipToKey[raddr.IP.String()]
			if ok {
				if oldAddr, exists := u.keyToAddr[senderKey]; exists {
					delete(u.addrToKey, oldAddr.String())
				}
				u.addrToKey[raddr.String()] = senderKey
				u.keyToAddr[senderKey] = raddr
				log.Printf("UDP relay: remapped %s to %s (NAT port change)", senderKey[:min(16, len(senderKey))], raddr)
			}
			u.mu.Unlock()
			if !ok {
				log.Printf("UDP relay: DROP pkt from %s (unknown sender)", raddr)
				continue
			}
		}

		u.mu.RLock()
		partnerKey, ok := u.tunnelPairs[senderKey]
		if !ok {
			u.mu.RUnlock()
			log.Printf("UDP relay: DROP pkt from %s (no tunnel pair for sender)", raddr)
			continue
		}
		partnerAddr, ok := u.keyToAddr[partnerKey]
		u.mu.RUnlock()
		if !ok {
			log.Printf("UDP relay: DROP pkt from %s (partner addr unknown)", raddr)
			continue
		}

		if pktCount <= 20 {
			log.Printf("UDP relay: FWD %d bytes %s -> %s", n, raddr, partnerAddr)
		}
		conn.WriteToUDP(data, partnerAddr)
	}
}
