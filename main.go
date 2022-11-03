package main

import (
	"log"
	"time"
)

const (
	MaxSessionLength = 30 * time.Second
	MaxCertValidity  = 24 * time.Hour
)

// CLI entrypoint
func main() {
	config, err := LoadConfig("config.toml")
	if err != nil {
		log.Fatal(err)
	}
	server, err := NewCertServer(config)
	if err != nil {
		log.Fatal(err)
	}
	err = server.run()
	if err != nil {
		log.Fatal(err)
	}
}
