//
// Integration tests
//

package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"testing"
	"time"

	_ "github.com/pquerna/otp/totp"
	"golang.org/x/crypto/ssh"
)

type testServer struct {
	// CertAuthority instance we're testing against
	CertAuthority *certServer

	// A channel for graceful shutdown on CertAuthority instance
	StopCA chan bool

	// Random SSH key pair for client
	ClientKey ssh.Signer

	// SSH host key validator
	HostKeyChecker ssh.CertChecker
}

func (ts *testServer) Start(config *certServerConfig) error {
	if config == nil {
		config = &certServerConfig{
			Address:  "127.0.0.1:20000",
			CAPath:   "demo/keys/ca-insecure",
			Validity: 1 * time.Hour,
		}
	}

	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	ts.ClientKey, err = ssh.NewSignerFromKey(private)
	if err != nil {
		return err
	}

	ts.StopCA = make(chan bool)
	ts.CertAuthority, err = NewCertServer(config)
	if err != nil {
		return err
	}

	ts.HostKeyChecker = ssh.CertChecker{
		IsHostAuthority: func(auth ssh.PublicKey, address string) bool {
			return bytes.Equal(auth.Marshal(), ts.CertAuthority.signer.PublicKey().Marshal())
		},
		HostKeyFallback: ssh.FixedHostKey(ts.CertAuthority.signer.PublicKey()),
	}

	go ts.CertAuthority.run(ts.StopCA)
	return nil
}

func (ts *testServer) Stop() {
	close(ts.StopCA)
}

type testClient struct {
	config *ssh.ClientConfig
	target string
}

func (ts *testServer) Client(username string) *testClient {
	return &testClient{
		config: &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(ts.ClientKey),
			},
			HostKeyCallback: ts.HostKeyChecker.CheckHostKey,
		},
		target: ts.CertAuthority.addr,
	}
}

func (tc *testClient) Dial() (*ssh.Client, error) {
	return ssh.Dial("tcp", tc.target, tc.config)
}

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

	client := server.Client("alice")
	conn, err := client.Dial()
	if err != nil {
		t.Fatalf("could not dial ssh connection: %v", err)
	}
	defer conn.Close()

	session, err := conn.NewSession()
	if err != nil {
		t.Fatalf("could not start ssh session: %v", err)
	}
	defer session.Close()

	shell, err := NewShell(session)
	if err != nil {
		t.Fatalf("could not open shell: %v", err)
	}

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
	fmt.Printf(output)
}

type Shell struct {
	stdin  io.WriteCloser
	stdout io.Reader
	closed bool
	err    error
	timeout time.Duration
}

func NewShell(session *ssh.Session) (shell *Shell, err error) {
	shell = &Shell{
		timeout: time.Second / 2
	}
	shell.stdin, err = session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("could not attach stdin: %v", err)
	}
	shell.stdout, err = session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("could not attach stdout: %v", err)
	}
	err = session.Shell()
	if err != nil {
		return nil, fmt.Errorf("could not start shell: %v", err)
	}
	go func() {
		defer session.Close()
		shell.err = session.Wait()
		shell.closed = true
	}()
	return shell, nil
}

func (s *Shell) SendLine(line string) error {
	return s.Send(fmt.Sprintf("%s\n", line))
}

func (s *Shell) Send(raw string) (err error) {
	if len(raw) == 0 {
		return nil
	}
	n, err := s.stdin.Write([]byte(raw))
	if n == 0 {
		return fmt.Errorf("zero bytes written")
	}
	return err
}

func (s *Shell) Expect(exact string) (value string, err error) {
	buf := bytes.NewBuffer([]byte{})
	errors := make(chan error)
	go func() {
		received := make([]byte, 64)
		needle := []byte(exact)
		for {
			n, err := s.stdout.Read(received)
			if n > 0 {
				buf.Write(received[:n])
			}
			if bytes.Contains(buf.Bytes(), needle) {
				errors <- nil
				close(errors)
				break
			}
			if err != nil {
				errors <- err
				break
			}
		}
	}()
	select {
	case <-time.After(s.timeout):
		return "", fmt.Errorf("timed out waiting for '%s', got only '%s'", exact, string(buf.Bytes()))
	case err := <-errors:
		if err != nil {
			return "", err
		}
		return string(buf.Bytes()), nil
	}
}
