// Command nhp-relayd is the NHP-Relay daemon (#2208): it bridges browser
// JS-agents (HTTPS POST /relay/{serverId}) to the private NHP-Server over an
// NHP_RLY UDP forward. The forwarding logic lives in package relay; this is the
// thin daemon wrapper (config load -> New -> Start -> graceful Stop), matching
// the server/ac/db daemons' cli shape. See docs/design/NHP_RELAY_TOPOLOGY.md.
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/OpenNHP/opennhp/endpoints/relay"
	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/version"
)

func main() {
	app := cli.NewApp()
	app.Name = "nhp-relayd"
	app.Usage = "NHP-Relay: bridge HTTPS browser agents to the private NHP-Server (#2208)"
	app.Version = version.Version

	runCmd := &cli.Command{
		Name:  "run",
		Usage: "start the NHP-Relay service",
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:  "config",
				Usage: "path to relay.toml (default: <exe dir>/etc/relay.toml)",
			},
		},
		Action: func(c *cli.Context) error {
			return runApp(c.String("config"))
		},
	}

	// keygen mirrors the server/ac daemons: curve25519 only (this fork strips
	// GMSM/SM2). Generate the relay identity key, then paste the private key into
	// relay.toml's private_key and register the public key as the relay's
	// NHP_RELAY peer on each cell server.
	keygenCmd := &cli.Command{
		Name:  "keygen",
		Usage: "generate a curve25519 key pair for the relay identity",
		Action: func(c *cli.Context) error {
			e, err := core.NewECDH(core.ECC_CURVE25519)
			if err != nil {
				return fmt.Errorf("failed to generate key pair: %w", err)
			}
			fmt.Println("Private key: ", e.PrivateKeyBase64())
			fmt.Println("Public key: ", e.PublicKeyBase64())
			return nil
		},
	}

	app.Commands = []*cli.Command{runCmd, keygenCmd}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// runApp loads the config, starts the relay, and blocks until a termination
// signal (or a serve error), then shuts down gracefully within a bounded window.
func runApp(configPath string) error {
	if configPath == "" {
		exe, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate executable: %w", err)
		}
		configPath = filepath.Join(filepath.Dir(exe), "etc", "relay.toml")
	}

	cfg, err := relay.LoadConfig(configPath)
	if err != nil {
		return err
	}

	rs, err := relay.New(cfg)
	if err != nil {
		return err
	}

	printStartup(cfg)

	errCh := make(chan error, 1)
	go func() {
		if err := rs.Start(); err != nil {
			errCh <- err
		}
	}()

	termCh := make(chan os.Signal, 1)
	signal.Notify(termCh, syscall.SIGTERM, os.Interrupt)

	// Both exit paths must Stop: relay.Start's contract is that even on a serve
	// error (e.g. the listen address is in use) the device + recvLoop keep running
	// until Stop releases them. So capture the serve error and fall through to the
	// shared Stop rather than returning early.
	var serveErr error
	select {
	case sig := <-termCh:
		fmt.Printf("nhp-relayd: received %s, shutting down\n", sig)
	case serveErr = <-errCh:
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stopErr := rs.Stop(ctx)

	switch {
	case serveErr != nil:
		return fmt.Errorf("nhp-relayd: serve error: %w", serveErr)
	case stopErr != nil:
		return fmt.Errorf("nhp-relayd: shutdown error: %w", stopErr)
	}
	fmt.Println("nhp-relayd: stopped")
	return nil
}

// printStartup prints the one operator-facing startup line. Per-cell routing
// (each {serverId} fingerprint -> server addr) is logged by relay.New via
// nhp/log, so it is not duplicated here.
func printStartup(cfg *relay.Config) {
	scheme := "http"
	if cfg.EnableTLS {
		scheme = "https"
	}
	fmt.Printf("nhp-relayd %s starting on %s://%s/relay/{serverId} (%d cell server(s))\n",
		version.Version, scheme, cfg.ListenAddr, len(cfg.Servers))
}
