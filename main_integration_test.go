//
// Integration tests
//

package main

import (
	"testing"

	"time"

	"github.com/pquerna/otp/totp"
)

func TestStartStop(t *testing.T) {
	server := &testServer{}
	err := server.Start(nil)
	if err != nil {
		t.Fatalf("test server startup error: %v", err)
	}
	defer server.Stop()
}

func TestHappyPath(t *testing.T) {
	config := DefaultServerConfig()
	config.TOTPSecrets = map[string]string{
		"alice": "sampletotpsecret",
		"bob":   "anothertotpsecret",
	}
	server := &testServer{}
	err := server.Start(config)
	if err != nil {
		t.Fatalf("test server startup error: %v", err)
	}
	defer server.Stop()

	shell, err := server.Shell("alice")
	if err != nil {
		t.Fatal(err)
	}
	defer shell.Close()

	_, err = shell.Expect("# ")
	if err != nil {
		t.Errorf("did not receive initial prompt: %v", err)
	}
	code, err := totp.GenerateCode(config.TOTPSecrets["alice"], time.Now())
	if err != nil {
		t.Fatalf("could not generate TOTP code: %v", err)
	}
	err = shell.SendLine(code)
	if err != nil {
		t.Errorf("error after sending number: %v", err)
	}
	output, err := shell.Expect("ssh-ed25519-cert-v01@openssh.com")
	if err != nil {
		t.Errorf("did not receive ssh certificate: %v", err)
		t.Logf("shell output: '%s'", output)
	}
}
