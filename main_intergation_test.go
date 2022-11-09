//
// Integration tests
//

package main

import (
	"testing"
)

func TestStartStop(t *testing.T) {
	var server testServer
	var err error
	err = server.Start(nil)
	if err != nil {
		t.Fatalf("test server startup error: %v", err)
	}
	defer server.Stop()
}

func TestHappyPath(t *testing.T) {
	var server testServer
	var err error
	err = server.Start(nil)
	if err != nil {
		t.Fatalf("test server startup error: %v", err)
	}
	defer server.Stop()

	shell, err := server.Shell("alice")
	if err != nil {
		t.Error(err)
	}
	defer shell.Close()

	_, err = shell.Expect("# ")
	if err != nil {
		t.Errorf("did not receive initial prompt: %v", err)
	}
	err = shell.SendLine("123")
	if err != nil {
		t.Errorf("error after sending number: %v", err)
	}
	output, err := shell.Expect("ssh-")
	if shell.closed {
		t.Fatalf("shell connection closed")
	}
	if err != nil {
		t.Errorf("did not receive ssh certificate: %v", err)
	}
	t.Logf("shell output: '%s'", output)
}
