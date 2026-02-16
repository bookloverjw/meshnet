// meshgui is a native GUI app for the mesh client.
// Double-click to launch — no terminal needed.
package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/bookloverjw/meshnet/internal/client"
	"github.com/bookloverjw/meshnet/internal/config"
	"github.com/bookloverjw/meshnet/internal/protocol"
)

type meshApp struct {
	mu        sync.RWMutex
	connected bool
	meshClient *client.Client
	cancel    context.CancelFunc
	cfg       *config.Config

	// UI elements
	statusDot   *canvas.Circle
	statusLabel *widget.Label
	peerLabel   *widget.Label
	peerList    *widget.List
	btn         *widget.Button

	peers []peerDisplay
}

type peerDisplay struct {
	Name   string
	Online bool
}

func main() {
	fyneApp := app.New()
	win := fyneApp.NewWindow("Meshnet")
	win.Resize(fyne.NewSize(340, 420))
	win.SetFixedSize(true)

	ma := &meshApp{}

	// Load config
	cfg, err := config.Load()
	if err != nil {
		errLabel := widget.NewLabel("Config not found.\nRun 'mesh init' first to set up this device.")
		errLabel.Wrapping = fyne.TextWrapWord
		win.SetContent(container.NewVBox(
			widget.NewLabel("Meshnet"),
			errLabel,
		))
		win.ShowAndRun()
		return
	}
	ma.cfg = cfg

	// Build UI
	win.SetContent(ma.buildUI())

	// Cleanup on close
	win.SetOnClosed(func() {
		ma.disconnect()
	})

	win.ShowAndRun()
}

func (ma *meshApp) buildUI() fyne.CanvasObject {
	// Title
	title := canvas.NewText("Meshnet", theme.Color(theme.ColorNameForeground))
	title.TextSize = 22
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	// Status indicator
	ma.statusDot = canvas.NewCircle(theme.Color(theme.ColorNameError))
	ma.statusDot.Resize(fyne.NewSize(12, 12))

	ma.statusLabel = widget.NewLabel("Disconnected")

	statusRow := container.NewHBox(
		container.NewStack(
			container.NewWithoutLayout(ma.statusDot),
		),
		ma.statusLabel,
	)

	// Device info
	deviceInfo := widget.NewLabel(fmt.Sprintf("Device: %s\nTunnel IP: %s",
		ma.cfg.DeviceName, ma.cfg.TunnelIPv4))
	deviceInfo.TextStyle = fyne.TextStyle{}

	// Peer count
	ma.peerLabel = widget.NewLabel("Peers online: —")

	// Peer list
	ma.peerList = widget.NewList(
		func() int {
			ma.mu.RLock()
			defer ma.mu.RUnlock()
			return len(ma.peers)
		},
		func() fyne.CanvasObject {
			return container.NewHBox(
				canvas.NewCircle(theme.Color(theme.ColorNameForeground)),
				widget.NewLabel("peer-name"),
			)
		},
		func(id widget.ListItemID, obj fyne.CanvasObject) {
			ma.mu.RLock()
			defer ma.mu.RUnlock()
			if id >= len(ma.peers) {
				return
			}
			p := ma.peers[id]
			items := obj.(*fyne.Container).Objects
			dot := items[0].(*canvas.Circle)
			label := items[1].(*widget.Label)
			label.SetText(p.Name)
			if p.Online {
				dot.FillColor = theme.Color(theme.ColorNameSuccess)
			} else {
				dot.FillColor = theme.Color(theme.ColorNameDisabled)
			}
			dot.Refresh()
		},
	)
	ma.peerList.HideSeparators = true

	// Connect button
	ma.btn = widget.NewButton("Connect", func() {
		ma.mu.RLock()
		isConnected := ma.connected
		ma.mu.RUnlock()

		if isConnected {
			ma.disconnect()
		} else {
			ma.connect()
		}
	})
	ma.btn.Importance = widget.HighImportance

	return container.NewVBox(
		title,
		widget.NewSeparator(),
		layout.NewSpacer(),
		statusRow,
		deviceInfo,
		ma.peerLabel,
		container.NewStack(ma.peerList),
		layout.NewSpacer(),
		ma.btn,
	)
}

func (ma *meshApp) connect() {
	ma.btn.SetText("Connecting...")
	ma.btn.Disable()
	ma.statusLabel.SetText("Connecting...")
	ma.statusDot.FillColor = theme.Color(theme.ColorNameWarning)
	ma.statusDot.Refresh()

	go func() {
		c, err := client.New(ma.cfg)
		if err != nil {
			ma.statusLabel.SetText(fmt.Sprintf("Error: %v", err))
			ma.statusDot.FillColor = theme.Color(theme.ColorNameError)
			ma.statusDot.Refresh()
			ma.btn.SetText("Connect")
			ma.btn.Enable()
			return
		}

		ctx, cancel := context.WithCancel(context.Background())

		c.OnPeerUpdate = func(peers []protocol.PeerInfo) {
			ma.mu.Lock()
			ma.peers = nil
			count := 0
			for _, p := range peers {
				if p.PublicKey == ma.cfg.PublicKey {
					continue
				}
				if p.Online {
					count++
				}
				ma.peers = append(ma.peers, peerDisplay{
					Name:   p.Name,
					Online: p.Online,
				})
			}
			ma.mu.Unlock()
			ma.peerLabel.SetText(fmt.Sprintf("Peers online: %d", count))
			ma.peerList.Refresh()
		}

		c.OnConnected = func(peerName string, tunnelIP string) {
			ma.statusLabel.SetText(fmt.Sprintf("Tunneled to %s", peerName))
		}

		if err := c.Connect(ctx); err != nil {
			cancel()
			ma.statusLabel.SetText("Connection failed")
			ma.statusDot.FillColor = theme.Color(theme.ColorNameError)
			ma.statusDot.Refresh()
			ma.btn.SetText("Connect")
			ma.btn.Enable()
			return
		}

		ma.mu.Lock()
		ma.connected = true
		ma.meshClient = c
		ma.cancel = cancel
		ma.mu.Unlock()

		ma.statusLabel.SetText("Connected")
		ma.statusDot.FillColor = theme.Color(theme.ColorNameSuccess)
		ma.statusDot.Refresh()
		ma.btn.SetText("Disconnect")
		ma.btn.Importance = widget.DangerImportance
		ma.btn.Enable()

		// Keep alive indicator — blink dot to show it's active
		go func() {
			for {
				ma.mu.RLock()
				if !ma.connected {
					ma.mu.RUnlock()
					return
				}
				ma.mu.RUnlock()
				time.Sleep(2 * time.Second)
			}
		}()
	}()
}

func (ma *meshApp) disconnect() {
	ma.mu.Lock()
	if ma.cancel != nil {
		ma.cancel()
	}
	if ma.meshClient != nil {
		ma.meshClient.Disconnect()
	}
	ma.connected = false
	ma.meshClient = nil
	ma.cancel = nil
	ma.peers = nil
	ma.mu.Unlock()

	ma.statusLabel.SetText("Disconnected")
	ma.statusDot.FillColor = theme.Color(theme.ColorNameError)
	ma.statusDot.Refresh()
	ma.peerLabel.SetText("Peers online: —")
	ma.peerList.Refresh()
	ma.btn.SetText("Connect")
	ma.btn.Importance = widget.HighImportance
	ma.btn.Enable()
}
