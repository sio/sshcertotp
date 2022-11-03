package main

import (
	"flag"
	"log"
	"time"
)

const (
	MaxSessionLength = 30 * time.Second
	MaxCertValidity  = 24 * time.Hour
)

// CLI entrypoint
func main() {
	var configPath string
	flag.StringVar(&configPath, "c", "config.toml", "Load configuration from file")
	flag.Parse()

	config, err := LoadConfig(configPath)
	if err != nil {
		log.Fatal(err)
	}
	server, err := NewCertServer(config)
	if err != nil {
		log.Fatal(err)
	}
	err = server.run(nil)
	if err != nil {
		log.Fatal(err)
	}
}
