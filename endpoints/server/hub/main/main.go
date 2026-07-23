// Command nhp-hubd serves the native qURL Connector assignment protocol over
// NHP UDP. It has no HTTP or generic NHP-server surface.
package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/OpenNHP/opennhp/endpoints/server/hub"
	"github.com/OpenNHP/opennhp/nhp/version"
)

const healthcheckTimeout = 2 * time.Second

var errHealthcheckFailed = errors.New("connector hub: private health check failed")

func main() {
	app := newApp()
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newApp() *cli.App {
	app := cli.NewApp()
	app.Name = "nhp-hubd"
	app.Usage = "serve native qURL Connector assignment over NHP UDP"
	app.Version = version.Version
	app.Commands = []*cli.Command{
		{
			Name:  "run",
			Usage: "start the Connector Hub UDP service",
			Flags: []cli.Flag{configFlag()},
			Action: func(cliContext *cli.Context) error {
				if err := rejectInitEnvironment(os.LookupEnv); err != nil {
					return err
				}
				ctx, stop := signal.NotifyContext(cliContext.Context, syscall.SIGTERM, os.Interrupt)
				defer stop()
				return runApp(ctx, cliContext.String("config"))
			},
		},
		{
			Name:  "healthcheck",
			Usage: "perform one private TCP-connect liveness check",
			Flags: []cli.Flag{configFlag()},
			Action: func(cliContext *cli.Context) error {
				if err := rejectInitEnvironment(os.LookupEnv); err != nil {
					return err
				}
				return healthcheckApp(
					cliContext.Context,
					cliContext.String("config"),
					(&net.Dialer{}).DialContext,
				)
			},
		},
		{
			Name:  "materialize-config",
			Usage: "install the Hub container config from init-only environment inputs",
			Action: func(_ *cli.Context) error {
				input, err := consumeMaterializeEnvironment(os.LookupEnv, os.Unsetenv)
				if err != nil {
					return err
				}
				digest, err := hub.MaterializeConfig(hub.ContainerConfigPath, input)
				if err != nil {
					return err
				}
				fmt.Printf("config_sha256=%s\n", digest)
				return nil
			},
		},
	}
	return app
}

func configFlag() cli.Flag {
	return &cli.StringFlag{
		Name:  "config",
		Usage: "path to hub.toml (default: <exe dir>/etc/hub.toml)",
	}
}

func runApp(ctx context.Context, configPath string) error {
	configPath, err := resolveConfigPath(configPath)
	if err != nil {
		return err
	}
	config, err := hub.LoadConfig(configPath)
	if err != nil {
		return err
	}
	fmt.Printf("nhp-hubd %s starting UDP=%s private-health-tcp=%s environment=%s\n",
		version.Version, config.UDPListenAddr, config.HealthListenAddr, config.Environment)
	if err := hub.Run(ctx, config); err != nil {
		if ctx.Err() != nil && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
			return nil
		}
		return err
	}
	fmt.Println("nhp-hubd: stopped")
	return nil
}

func healthcheckApp(
	ctx context.Context,
	configPath string,
	dial func(context.Context, string, string) (net.Conn, error),
) error {
	if ctx == nil || dial == nil {
		return errHealthcheckFailed
	}
	configPath, err := resolveConfigPath(configPath)
	if err != nil {
		return err
	}
	config, err := hub.LoadConfig(configPath)
	if err != nil {
		return err
	}
	target, err := healthcheckTarget(config.HealthListenAddr)
	if err != nil {
		return errHealthcheckFailed
	}

	probeCtx, cancel := context.WithTimeout(ctx, healthcheckTimeout)
	defer cancel()
	connection, err := dial(probeCtx, "tcp", target)
	if err != nil {
		return errHealthcheckFailed
	}
	if err := connection.Close(); err != nil {
		return errHealthcheckFailed
	}
	return nil
}

func healthcheckTarget(listenAddr string) (string, error) {
	target, err := netip.ParseAddrPort(listenAddr)
	if err != nil {
		return "", errHealthcheckFailed
	}
	if target.Addr().IsUnspecified() {
		loopback := netip.MustParseAddr("127.0.0.1")
		if target.Addr().Is6() {
			loopback = netip.MustParseAddr("::1")
		}
		target = netip.AddrPortFrom(loopback, target.Port())
	}
	return target.String(), nil
}

func resolveConfigPath(path string) (string, error) {
	if path != "" {
		return path, nil
	}
	executable, err := os.Executable()
	if err != nil {
		return "", fmt.Errorf("connector hub: locate executable: %w", err)
	}
	return filepath.Join(filepath.Dir(executable), "etc", "hub.toml"), nil
}

// materializeEnvNames is the single source of the four init-only environment
// inputs, so the consume path and the long-lived-command rejection stay in
// lockstep when the set changes.
var materializeEnvNames = []string{
	hub.PublicConfigEnv,
	hub.PrivateKeyEnv,
	hub.ActiveCookieKeyEnv,
	hub.PreviousCookieKeyEnv,
}

func consumeMaterializeEnvironment(
	lookup func(string) (string, bool),
	unset func(string) error,
) (hub.MaterializeInput, error) {
	if lookup == nil || unset == nil {
		return hub.MaterializeInput{}, hub.ErrConfigMaterialization
	}
	// Snapshot every value before unsetting any so later unsets cannot erase an
	// input before it has been read.
	publicJSON, _ := lookup(hub.PublicConfigEnv)
	privateKey, _ := lookup(hub.PrivateKeyEnv)
	activeKey, _ := lookup(hub.ActiveCookieKeyEnv)
	previousKey, _ := lookup(hub.PreviousCookieKeyEnv)
	for _, name := range materializeEnvNames {
		if err := unset(name); err != nil {
			return hub.MaterializeInput{}, hub.ErrConfigMaterialization
		}
	}
	return hub.MaterializeInput{
		PublicConfigJSON:        publicJSON,
		PrivateKeyBase64:        privateKey,
		ActiveCookieKeyBase64:   activeKey,
		PreviousCookieKeyBase64: previousKey,
	}, nil
}

func rejectInitEnvironment(lookup func(string) (string, bool)) error {
	if lookup == nil {
		return hub.ErrInvalidConfig
	}
	for _, name := range materializeEnvNames {
		if _, present := lookup(name); present {
			return hub.ErrInvalidConfig
		}
	}
	return nil
}
