// Package config handles loading and saving mesh network configuration.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

// Config holds all persistent settings for the mesh client.
type Config struct {
	DeviceName string `json:"device_name"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`

	RelayAddr string `json:"relay_addr"`
	RelayPort int    `json:"relay_port"`

	TunnelIPv4 string `json:"tunnel_ipv4,omitempty"`
	ListenPort int    `json:"listen_port"`
	MTU        int    `json:"mtu"`

	TrustedPeers []TrustedPeer `json:"trusted_peers"`
}

// TrustedPeer is a peer we've authorized to connect.
type TrustedPeer struct {
	PublicKey string `json:"public_key"`
	Name      string `json:"name"`
	AllowedIP string `json:"allowed_ip,omitempty"`
}

// DefaultConfig returns a sensible default configuration.
func DefaultConfig() *Config {
	return &Config{
		RelayPort:  443,
		ListenPort: 51820,
		MTU:        1420,
	}
}

// ConfigDir returns the platform-appropriate config directory.
func ConfigDir() (string, error) {
	switch runtime.GOOS {
	case "windows":
		appdata := os.Getenv("APPDATA")
		if appdata == "" {
			appdata = os.Getenv("LOCALAPPDATA")
		}
		if appdata == "" {
			return "", fmt.Errorf("cannot determine config directory on Windows")
		}
		return filepath.Join(appdata, "meshnet"), nil
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(home, "Library", "Application Support", "meshnet"), nil
	default:
		cfgDir := os.Getenv("XDG_CONFIG_HOME")
		if cfgDir == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				return "", err
			}
			cfgDir = filepath.Join(home, ".config")
		}
		return filepath.Join(cfgDir, "meshnet"), nil
	}
}

// Load reads configuration from the default config path.
func Load() (*Config, error) {
	dir, err := ConfigDir()
	if err != nil {
		return nil, err
	}
	return LoadFrom(filepath.Join(dir, "config.json"))
}

// LoadFrom reads configuration from a specific file path.
func LoadFrom(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return &cfg, nil
}

// Save writes configuration to the default config path.
func (c *Config) Save() error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	return c.SaveTo(filepath.Join(dir, "config.json"))
}

// SaveTo writes configuration to a specific file path.
func (c *Config) SaveTo(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}
