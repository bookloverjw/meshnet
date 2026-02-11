// Package nat provides NAT traversal utilities including STUN-based
// public endpoint discovery and UDP hole-punching coordination.
package nat

import (
	"fmt"
	"net"
	"time"
)

// Default public STUN servers for discovering our external IP:port.
var DefaultSTUNServers = []string{
	"stun.l.google.com:19302",
	"stun1.l.google.com:19302",
	"stun2.l.google.com:19302",
}

// DiscoverEndpoint uses STUN to discover our public IP and mapped port.
func DiscoverEndpoint(stunServers []string) (string, error) {
	if len(stunServers) == 0 {
		stunServers = DefaultSTUNServers
	}
	for _, server := range stunServers {
		endpoint, err := probeSTUN(server)
		if err == nil {
			return endpoint, nil
		}
	}
	return "", fmt.Errorf("all STUN servers failed")
}

func probeSTUN(server string) (string, error) {
	conn, err := net.DialTimeout("udp", server, 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("dial %s: %w", server, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// STUN Binding Request (RFC 5389)
	req := make([]byte, 20)
	req[0] = 0x00
	req[1] = 0x01
	req[4] = 0x21
	req[5] = 0x12
	req[6] = 0xA4
	req[7] = 0x42
	for i := 8; i < 20; i++ {
		req[i] = byte(i)
	}

	if _, err := conn.Write(req); err != nil {
		return "", fmt.Errorf("write to %s: %w", server, err)
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		return "", fmt.Errorf("read from %s: %w", server, err)
	}

	return parseSTUNResponse(buf[:n])
}

func parseSTUNResponse(data []byte) (string, error) {
	if len(data) < 20 {
		return "", fmt.Errorf("response too short: %d bytes", len(data))
	}
	if data[0] != 0x01 || data[1] != 0x01 {
		return "", fmt.Errorf("not a binding success response: %02x%02x", data[0], data[1])
	}

	offset := 20
	for offset+4 <= len(data) {
		attrType := uint16(data[offset])<<8 | uint16(data[offset+1])
		attrLen := int(uint16(data[offset+2])<<8 | uint16(data[offset+3]))
		offset += 4

		if offset+attrLen > len(data) {
			break
		}

		switch attrType {
		case 0x0020: // XOR-MAPPED-ADDRESS
			return parseXORMappedAddress(data[offset : offset+attrLen])
		case 0x0001: // MAPPED-ADDRESS
			return parseMappedAddress(data[offset : offset+attrLen])
		}

		offset += attrLen
		if attrLen%4 != 0 {
			offset += 4 - (attrLen % 4)
		}
	}

	return "", fmt.Errorf("no mapped address in STUN response")
}

func parseXORMappedAddress(attr []byte) (string, error) {
	if len(attr) < 8 {
		return "", fmt.Errorf("XOR-MAPPED-ADDRESS too short")
	}
	if attr[1] != 0x01 {
		return "", fmt.Errorf("unsupported address family: %d", attr[1])
	}
	port := (uint16(attr[2])<<8 | uint16(attr[3])) ^ 0x2112
	ip := net.IPv4(attr[4]^0x21, attr[5]^0x12, attr[6]^0xA4, attr[7]^0x42)
	return fmt.Sprintf("%s:%d", ip.String(), port), nil
}

func parseMappedAddress(attr []byte) (string, error) {
	if len(attr) < 8 {
		return "", fmt.Errorf("MAPPED-ADDRESS too short")
	}
	if attr[1] != 0x01 {
		return "", fmt.Errorf("unsupported address family: %d", attr[1])
	}
	port := uint16(attr[2])<<8 | uint16(attr[3])
	ip := net.IPv4(attr[4], attr[5], attr[6], attr[7])
	return fmt.Sprintf("%s:%d", ip.String(), port), nil
}

// LocalEndpoints returns all non-loopback local IPv4 addresses with the given port.
func LocalEndpoints(port int) ([]string, error) {
	var endpoints []string
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			continue
		}
		if ip.To4() != nil {
			endpoints = append(endpoints, fmt.Sprintf("%s:%d", ip.String(), port))
		}
	}
	return endpoints, nil
}

// HolePunch attempts to punch through NAT by exchanging UDP packets
// with the remote peer. Returns the connection and remote address if successful.
func HolePunch(localPort int, remoteEndpoints []string, timeout time.Duration) (*net.UDPConn, *net.UDPAddr, error) {
	laddr := &net.UDPAddr{Port: localPort}
	conn, err := net.ListenUDP("udp4", laddr)
	if err != nil {
		return nil, nil, fmt.Errorf("listen UDP: %w", err)
	}

	deadline := time.Now().Add(timeout)
	conn.SetDeadline(deadline)

	punch := []byte("meshnet-punch")
	for _, ep := range remoteEndpoints {
		raddr, err := net.ResolveUDPAddr("udp4", ep)
		if err != nil {
			continue
		}
		conn.WriteToUDP(punch, raddr)
	}

	buf := make([]byte, 1500)
	for time.Now().Before(deadline) {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		if n >= len(punch) && string(buf[:len(punch)]) == "meshnet-punch" {
			conn.WriteToUDP([]byte("meshnet-punch-ack"), raddr)
			return conn, raddr, nil
		}
		if n >= 17 && string(buf[:17]) == "meshnet-punch-ack" {
			return conn, raddr, nil
		}
		for _, ep := range remoteEndpoints {
			raddr, err := net.ResolveUDPAddr("udp4", ep)
			if err != nil {
				continue
			}
			conn.WriteToUDP(punch, raddr)
		}
	}

	conn.Close()
	return nil, nil, fmt.Errorf("hole punch timed out")
}
