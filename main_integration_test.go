//
// Integration tests
//

package main

import (
	"testing"

	"errors"
	"fmt"
	"io"
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

func setup() (server *testServer, shell *Shell, cleanup func(), err error) {
	config := DefaultServerConfig()
	config.TOTPSecrets = map[string]string{
		"alice": "sampletotpsecret",
		"bob":   "anothertotpsecret",
	}
	server = &testServer{}
	err = server.Start(config)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("test server startup error: %w", err)
	}

	shell, err = server.Shell("alice")
	if err != nil {
		return nil, nil, nil, err
	}

	cleanup = func() {
		shell.Close()
		server.Stop()
	}
	return server, shell, cleanup, nil
}

func TestHappyPath(t *testing.T) {
	server, shell, cleanup, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	_, err = shell.Expect("# ")
	if err != nil {
		t.Errorf("did not receive initial prompt: %v", err)
	}
	code, err := totp.GenerateCode(server.Config.TOTPSecrets["alice"], time.Now())
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

func TestInvalidTOTP(t *testing.T) {
	_, shell, cleanup, err := setup()
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()

	err = shell.SendLine("123123123")
	if err != nil {
		t.Errorf("could not send number: %v", err)
	}
	output, err := shell.Expect("anything")
	if !errors.Is(err, io.EOF) {
		t.Errorf("connection should have been closed on bad input, instead got: %v", err)
		t.Logf("shell output: '%s'", output)
	}

}
