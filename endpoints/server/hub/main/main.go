// Command nhp-hubd serves the native qURL Connector assignment protocol over
// NHP UDP. It has no HTTP or generic NHP-server surface.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/urfave/cli/v2"

	"github.com/OpenNHP/opennhp/endpoints/server/hub"
	"github.com/OpenNHP/opennhp/nhp/version"
)

func main() {
	app := cli.NewApp()
	app.Name = "nhp-hubd"
	app.Usage = "serve native qURL Connector assignment over NHP UDP"
	app.Version = version.Version
	app.Commands = []*cli.Command{{
		Name:  "run",
		Usage: "start the Connector Hub UDP service",
		Flags: []cli.Flag{&cli.StringFlag{
			Name:  "config",
			Usage: "path to hub.toml (default: <exe dir>/etc/hub.toml)",
		}},
		Action: func(cliContext *cli.Context) error {
			ctx, stop := signal.NotifyContext(cliContext.Context, syscall.SIGTERM, os.Interrupt)
			defer stop()
			return runApp(ctx, cliContext.String("config"))
		},
	}}

	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runApp(ctx context.Context, configPath string) error {
	if configPath == "" {
		executable, err := os.Executable()
		if err != nil {
			return fmt.Errorf("connector hub: locate executable: %w", err)
		}
		configPath = filepath.Join(filepath.Dir(executable), "etc", "hub.toml")
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
