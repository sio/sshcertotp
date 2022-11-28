package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime/debug"
	"time"
)

const (
	MaxSessionLength = 30 * time.Second
	MaxCertValidity  = 24 * time.Hour
)

// CLI entrypoint
func main() {
	var config string
	flag.StringVar(&config, "c", "config.toml", "Load configuration from file")
	var showVersion bool
	flag.BoolVar(&showVersion, "v", false, "Show version information and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("Revision %s\n", AppVersion)
		os.Exit(2)
	}

	server, err := NewCertServerFromFile(config)
	if err != nil {
		log.Fatal(err)
	}
	err = server.run(nil)
	if err != nil {
		log.Fatal(err)
	}
}

var AppVersion = func() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return "{unknown version}"
	}
	build := map[string]string{
		"vcs.revision": "",
		"vcs.modified": "",
	}
	for _, setting := range info.Settings {
		_, relevant := build[setting.Key]
		if !relevant {
			continue
		}
		build[setting.Key] = setting.Value
	}
	if len(build["vcs.revision"]) == 0 {
		return "{unknown revision}"
	}
	var suffix string
	if build["vcs.modified"] == "true" {
		suffix = " (modified)"
	}
	return build["vcs.revision"] + suffix
}()
