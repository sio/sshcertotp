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

	//"net"
	//"strings"
	//"bufio"
	//"log"
	"strings"
	"sync/atomic"

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
		target: "127.0.0.1:20002", // TODO: remove debug helper
		// target: ts.CertAuthority.addr,
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
	return
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
	time.Sleep(time.Second)
	err = shell.SendLine("123456789")
	if err != nil {
		t.Errorf("error after sending number: %v", err)
	}
	time.Sleep(time.Second)
	output, err := shell.Expect("ssh-")
	if err != nil {
		t.Errorf("did not receive ssh certificate: %v", err)
	}
	fmt.Printf(output)
}

type Shell struct {
	err    error
	input  chan string
	output chan string
}

func NewShell(session *ssh.Session) (shell *Shell, err error) {
	var stdin  io.WriteCloser
	var stdout, stderr io.Reader

	stdin, err = session.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("could not attach stdin: %v", err)
	}
	stdout, err = session.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("could not attach stdout: %v", err)
	}
	stderr, err = session.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("could not attach stderr: %v", err)
	}
	err = session.Shell()
	if err != nil {
		return nil, fmt.Errorf("could not start shell: %v", err)
	}

	shell = &Shell{
		output: make(chan string, 10),
		input: make(chan string, 10),
	}
	go shell.outputHandler(stdout)
	go shell.outputHandler(stderr)

	go func(){
		for {
			data := []byte(<-shell.input)
			n, err := stdin.Write(data)
			if n == 0 {
				shell.err = fmt.Errorf("zero bytes written")
			}
			if n != len(data) {
				shell.err = fmt.Errorf("got %d bytes, written %d bytes", len(data), n)
			}
			if err != nil {
				shell.err = err
			}
		}
	}()
	return shell, nil
}

func (s *Shell) outputHandler(output io.Reader) {
	buf := make([]byte, 80)
	var pos uint32
	go func() {
		var n int
		var err error
		for {
			n, err = output.Read(buf[pos:])
			if err != nil {
				s.err = err
				break
			}
			atomic.AddUint32(&pos, uint32(n))
		}
	}()
	ticker := time.NewTicker(time.Second / 3)
	for range ticker.C {
		have := buf[:pos]
		if len(have) == 0 {
			continue
		}
		atomic.StoreUint32(&pos, 0)
		s.output <- string(have)
	}
}

func (s *Shell) SendLine(line string) error {
	return s.Send(fmt.Sprintf("%s\n", line))
}

func (s *Shell) Send(raw string) (err error) {
	if len(raw) == 0 {
		return nil
	}
	s.input <- raw
	return s.err
}

func (s *Shell) Expect(exact string) (value string, err error) {
	timeout := time.Second / 2
	select {
	case <-time.After(timeout):
		return "", fmt.Errorf("timed out waiting for '%s'", exact)
	case line := <- s.output:
		if strings.HasSuffix(line, exact) {
			return line, nil
		}
		return "", fmt.Errorf("expected '%s', got '%s'", exact, line)
	}
}
