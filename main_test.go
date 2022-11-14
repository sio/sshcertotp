//
// Helper functions and types for integration tests
//

package main

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
)

//
// Ephemeral CertAuthority instance
//
type testServer struct {
	// CertAuthority instance we're testing against
	CertAuthority *certServer

	// A channel for graceful shutdown on CertAuthority instance
	StopCA chan bool

	// Random SSH key pair for client
	ClientKey ssh.Signer

	// SSH host key validator
	HostKeyChecker ssh.CertChecker

	// Unix socket to use instead of TCP port
	SocketPath string
}

func DefaultServerConfig() (config *certServerConfig) {
	return &certServerConfig{
		Address:  "127.0.0.1:20000",
		CAPath:   "demo/keys/ca-insecure",
		Validity: 1 * time.Hour,
	}
}

func (ts *testServer) Start(config *certServerConfig) error {
	if config == nil {
		config = DefaultServerConfig()
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

	temp, err := os.MkdirTemp("", "sshcertotp_test_*")
	if err != nil {
		return err
	}
	ts.SocketPath = filepath.Join(temp, "socket")
	listener, err := net.Listen("unix", ts.SocketPath)
	if err != nil {
		return err
	}

	go ts.CertAuthority.run(listener, ts.StopCA)
	return nil
}

func (ts *testServer) Stop() {
	ts.StopCA <- true
	if len(ts.SocketPath) > 0 {
		os.Remove(ts.SocketPath)
		os.RemoveAll(filepath.Dir(ts.SocketPath))
	}
	close(ts.StopCA)
}

//
// Simple SSH client
//
type testClient struct {
	config *ssh.ClientConfig
	target string
}

func (tc *testClient) Dial() (*ssh.Client, error) {
	return ssh.Dial("unix", tc.target, tc.config)
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
		target: ts.SocketPath,
	}
}

func (ts *testServer) Shell(username string) (shell *Shell, err error) {
	client := ts.Client(username)

	conn, err := client.Dial()
	if err != nil {
		return nil, fmt.Errorf("could not dial ssh connection: %v", err)
	}

	session, err := conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("could not start ssh session: %v", err)
	}

	return NewShell(session, conn)
}

//
// Expect-inspired shell object (works on Windows too)
//
type Shell struct {
	stdin   io.WriteCloser
	stdout  io.Reader
	timeout time.Duration
	Close   func()
}

func NewShell(session *ssh.Session, client *ssh.Client) (shell *Shell, err error) {
	shell = &Shell{
		timeout: time.Second / 2,
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
	shell.Close = func() {
		session.Close()
		client.Close()
	}
	return shell, nil
}

func (s *Shell) SendLine(line string) error {
	return s.Send(fmt.Sprintf("%s\r\n", line)) // CRLF!
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
