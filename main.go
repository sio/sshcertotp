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
	var config string
	flag.StringVar(&config, "c", "config.toml", "Load configuration from file")
	flag.Parse()

	server, err := NewCertServerFromFile(config)
	if err != nil {
		log.Fatal(err)
	}
	err = server.run(nil)
	if err != nil {
		log.Fatal(err)
	}
}
