package main

import (
	"fmt"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/pkg/errors"
)

type certServerConfig struct {
	Address     string            `toml:"listen"`
	CAPath      string            `toml:"private_key"`
	TOTPSecrets map[string]string `toml:"totp_secrets"`
	Validity    time.Duration     `toml:"validity"`
}

// Read app configuration from file
func LoadConfig(path string) (*certServerConfig, error) {
	conf := &certServerConfig{ // default values
		Address:  "127.0.0.1:2222",
		CAPath:   "/etc/ssh/ssh_host_ed25519_key",
		Validity: 4 * time.Hour,
	}
	_, err := toml.DecodeFile(path, conf)
	if err != nil {
		return nil, errors.Wrap(err, fmt.Sprintf("error while parsing %s", path))
	}
	return conf, nil
}
