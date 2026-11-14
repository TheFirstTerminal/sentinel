package main

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"strings"
	"time"

	"sentinel/gateway/internal/config"
)

const usage = `Sentinel: a security gateway that sits in front of your app.

Usage:
  sentinel [--config FILE]       run the gateway
  sentinel init [FILE]           write a commented config file (default sentinel.yaml)
  sentinel check-config [FILE]   check a config file without starting
  sentinel explain "<input>"     show which rules and ML features an input triggers
  sentinel watch                 live view of blocked requests in the terminal
  sentinel bench [--crs DIR]     measure detection and speed on this machine
  sentinel healthcheck           exit 0 if the local gateway answers (for Docker)
  sentinel version

Quick start:
  UPSTREAM_URL=http://localhost:3000 sentinel
  then send traffic to http://localhost:8080 and open /__sentinel/dashboard

The config file is found with --config, then SENTINEL_CONFIG, then
./sentinel.yaml and /etc/sentinel/sentinel.yaml. Environment variables win
over the file.
`

// loadConfigFile finds and applies the config file, if there is one.
func loadConfigFile(args []string) (string, []string, error) {
	path, explicit := "", false
	for i := 0; i < len(args); i++ {
		switch a := args[i]; {
		case a == "--config" || a == "-config" || a == "-c":
			if i+1 >= len(args) {
				return "", nil, errors.New("--config needs a file name")
			}
			path, explicit = args[i+1], true
			i++
		case strings.HasPrefix(a, "--config="):
			path, explicit = strings.TrimPrefix(a, "--config="), true
		default:
			return "", nil, fmt.Errorf("unknown argument %q (try: sentinel help)", a)
		}
	}
	if path == "" {
		if path = os.Getenv("SENTINEL_CONFIG"); path != "" {
			explicit = true
		}
	}
	candidates := []string{path}
	if path == "" {
		candidates = []string{"sentinel.yaml", "/etc/sentinel/sentinel.yaml"}
	}
	for _, c := range candidates {
		set, err := config.ApplyFile(c)
		if errors.Is(err, fs.ErrNotExist) && !explicit {
			continue
		}
		if err != nil {
			return "", nil, err
		}
		return c, set, nil
	}
	return "", nil, nil
}

// healthcheckCmd asks the running gateway for its health (used by Docker's
// HEALTHCHECK, since the image has no shell or curl).
func healthcheckCmd(out io.Writer) int {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	c := &http.Client{Timeout: 2 * time.Second}
	res, err := c.Get("http://" + addr + "/__sentinel/health")
	if err != nil {
		fmt.Fprintln(out, "unhealthy:", err)
		return 1
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		fmt.Fprintln(out, "unhealthy: status", res.StatusCode)
		return 1
	}
	return 0
}

func initCmd(args []string, out io.Writer) int {
	path := "sentinel.yaml"
	if len(args) > 0 {
		path = args[0]
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		fmt.Fprintf(out, "ERROR: %v (an existing file is never overwritten)\n", err)
		return 1
	}
	defer f.Close()
	if _, err := f.Write(config.Example); err != nil {
		fmt.Fprintf(out, "ERROR: %v\n", err)
		return 1
	}
	fmt.Fprintf(out, "Wrote %s. Set `upstream` to your app, then run: sentinel\n", path)
	return 0
}

func checkConfigCmd(args []string, out io.Writer) int {
	var flags []string
	if len(args) > 0 {
		flags = []string{"--config", args[0]}
	}
	file, set, err := loadConfigFile(flags)
	if err != nil {
		fmt.Fprintf(out, "ERROR: %v\n", err)
		return 1
	}
	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(out, "ERROR: %v\n", err)
		return 1
	}
	if file == "" {
		fmt.Fprintln(out, "No config file found; using environment variables and defaults.")
	} else {
		fmt.Fprintf(out, "%s: OK (%d settings)\n", file, len(set))
	}
	fmt.Fprintf(out, "mode: %s, listening on %s, protecting %s\n", cfg.Mode, cfg.ListenAddr, cfg.Upstreams)
	return 0
}
