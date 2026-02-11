// Package tunnel manages WireGuard tunnel configuration using the
// wireguard-go userspace implementation. This works on macOS and Windows
// without requiring kernel modules.
package tunnel

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"text/template"

	"github.com/bookloverjw/meshnet/internal/crypto"
)

// PeerConfig describes a WireGuard peer to add to the tunnel.
type PeerConfig struct {
	PublicKey    crypto.Key
	PreSharedKey crypto.Key
	Endpoint     string
	AllowedIPs   []string
	KeepAlive    int // seconds, 0 to disable
}

// Config describes a full WireGuard interface configuration.
type Config struct {
	PrivateKey crypto.Key
	ListenPort int
	Address    string // CIDR, e.g. "10.100.0.1/24"
	MTU        int
	DNS        string
	Peers      []PeerConfig
}

// wgConfTmpl is the WireGuard config file format.
var wgConfTmpl = template.Must(template.New("wg").Parse(`[Interface]
PrivateKey = {{.PrivateKey}}
ListenPort = {{.ListenPort}}
{{range .Peers}}
[Peer]
PublicKey = {{.PublicKey}}
{{- if not .PreSharedKey.IsZero}}
PresharedKey = {{.PreSharedKey}}
{{- end}}
{{- if .Endpoint}}
Endpoint = {{.Endpoint}}
{{- end}}
AllowedIPs = {{joinIPs .AllowedIPs}}
{{- if gt .KeepAlive 0}}
PersistentKeepalive = {{.KeepAlive}}
{{- end}}
{{end}}`))

func init() {
	wgConfTmpl.Funcs(template.FuncMap{
		"joinIPs": func(ips []string) string { return strings.Join(ips, ", ") },
	})
}

// GenerateConfig produces a WireGuard configuration string.
func (c *Config) GenerateConfig() (string, error) {
	funcMap := template.FuncMap{
		"joinIPs": func(ips []string) string { return strings.Join(ips, ", ") },
	}
	tmpl, err := template.New("wg").Funcs(funcMap).Parse(`[Interface]
PrivateKey = {{.PrivateKey}}
ListenPort = {{.ListenPort}}
{{range .Peers}}
[Peer]
PublicKey = {{.PublicKey}}
{{- if not .PreSharedKey.IsZero}}
PresharedKey = {{.PreSharedKey}}
{{- end}}
{{- if .Endpoint}}
Endpoint = {{.Endpoint}}
{{- end}}
AllowedIPs = {{joinIPs .AllowedIPs}}
{{- if gt .KeepAlive 0}}
PersistentKeepalive = {{.KeepAlive}}
{{- end}}
{{end}}`)
	if err != nil {
		return "", err
	}
	var buf strings.Builder
	if err := tmpl.Execute(&buf, c); err != nil {
		return "", fmt.Errorf("generate wg config: %w", err)
	}
	return buf.String(), nil
}

// InterfaceName returns the platform-appropriate WireGuard interface name.
func InterfaceName() string {
	switch runtime.GOOS {
	case "darwin":
		return "utun9"
	case "windows":
		return "meshnet"
	default:
		return "wg-meshnet"
	}
}

// Up brings the WireGuard tunnel up using platform-native commands.
// On macOS/Windows, this uses wireguard-go (userspace).
func Up(cfg *Config) error {
	switch runtime.GOOS {
	case "darwin":
		return upDarwin(cfg)
	case "windows":
		return upWindows(cfg)
	default:
		return upLinux(cfg)
	}
}

// Down tears down the WireGuard tunnel.
func Down() error {
	iface := InterfaceName()
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("sudo", "ifconfig", iface, "down").Run()
	case "windows":
		return exec.Command("wireguard.exe", "/uninstalltunnelservice", iface).Run()
	default:
		return exec.Command("sudo", "ip", "link", "delete", iface).Run()
	}
}

func upDarwin(cfg *Config) error {
	iface := InterfaceName()

	confStr, err := cfg.GenerateConfig()
	if err != nil {
		return err
	}

	// Write config to temp file
	confPath := fmt.Sprintf("/tmp/%s.conf", iface)
	if err := writeFile(confPath, confStr); err != nil {
		return err
	}

	// Start wireguard-go in userspace
	cmd := exec.Command("wireguard-go", iface)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start wireguard-go: %w (is wireguard-go installed? brew install wireguard-go)", err)
	}

	// Configure the interface
	if err := exec.Command("wg", "setconf", iface, confPath).Run(); err != nil {
		return fmt.Errorf("wg setconf: %w (is wireguard-tools installed? brew install wireguard-tools)", err)
	}

	// Assign IP address
	ip, ipNet, err := net.ParseCIDR(cfg.Address)
	if err != nil {
		return fmt.Errorf("parse address %s: %w", cfg.Address, err)
	}
	mask := fmt.Sprintf("%d.%d.%d.%d", ipNet.Mask[0], ipNet.Mask[1], ipNet.Mask[2], ipNet.Mask[3])
	if err := exec.Command("sudo", "ifconfig", iface, "inet", ip.String(), ip.String(), "netmask", mask).Run(); err != nil {
		return fmt.Errorf("ifconfig: %w", err)
	}

	// Set MTU
	if cfg.MTU > 0 {
		if err := exec.Command("sudo", "ifconfig", iface, "mtu", fmt.Sprintf("%d", cfg.MTU)).Run(); err != nil {
			return fmt.Errorf("set mtu: %w", err)
		}
	}

	// Add routes for peer AllowedIPs
	for _, peer := range cfg.Peers {
		for _, allowedIP := range peer.AllowedIPs {
			exec.Command("sudo", "route", "-n", "add", "-net", allowedIP, "-interface", iface).Run()
		}
	}

	return nil
}

func upWindows(cfg *Config) error {
	iface := InterfaceName()

	confStr, err := cfg.GenerateConfig()
	if err != nil {
		return err
	}

	confPath := fmt.Sprintf(`C:\Windows\Temp\%s.conf`, iface)
	if err := writeFile(confPath, confStr); err != nil {
		return err
	}

	// Windows uses the wireguard.exe service manager
	if err := exec.Command("wireguard.exe", "/installtunnelservice", confPath).Run(); err != nil {
		return fmt.Errorf("install tunnel service: %w (is WireGuard installed?)", err)
	}

	return nil
}

func upLinux(cfg *Config) error {
	iface := InterfaceName()

	confStr, err := cfg.GenerateConfig()
	if err != nil {
		return err
	}

	confPath := fmt.Sprintf("/tmp/%s.conf", iface)
	if err := writeFile(confPath, confStr); err != nil {
		return err
	}

	// Create interface
	if err := exec.Command("sudo", "ip", "link", "add", "dev", iface, "type", "wireguard").Run(); err != nil {
		return fmt.Errorf("create interface: %w", err)
	}

	// Apply config
	if err := exec.Command("sudo", "wg", "setconf", iface, confPath).Run(); err != nil {
		return fmt.Errorf("wg setconf: %w", err)
	}

	// Assign address
	if err := exec.Command("sudo", "ip", "addr", "add", cfg.Address, "dev", iface).Run(); err != nil {
		return fmt.Errorf("assign address: %w", err)
	}

	// Set MTU and bring up
	if cfg.MTU > 0 {
		exec.Command("sudo", "ip", "link", "set", iface, "mtu", fmt.Sprintf("%d", cfg.MTU)).Run()
	}
	if err := exec.Command("sudo", "ip", "link", "set", iface, "up").Run(); err != nil {
		return fmt.Errorf("bring up interface: %w", err)
	}

	// Add routes
	for _, peer := range cfg.Peers {
		for _, allowedIP := range peer.AllowedIPs {
			exec.Command("sudo", "ip", "route", "add", allowedIP, "dev", iface).Run()
		}
	}

	return nil
}

func writeFile(path, content string) error {
	return exec.Command("bash", "-c", fmt.Sprintf("cat > %s << 'WGEOF'\n%s\nWGEOF", path, content)).Run()
}
