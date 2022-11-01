package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	MaxSessionLength = 30 * time.Second
)

type certServer struct {
	addr string
	key  string
	totp *TotpValidator
}

func (cs *certServer) run() error {
	listener, err := net.Listen("tcp", cs.addr)
	if err != nil {
		return errors.Wrap(err, "failed to listen for connection")
	}
	defer listener.Close()

	sshd, err := newSSHd(cs.key)
	if err != nil {
		return err
	}
	log.Printf("%s is listening on %s", os.Args[0], listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection from %s: %v", conn.RemoteAddr(), err)
			continue
		}
		go handleTCP(conn, sshd)
	}
	return nil
}

func NewCertServer() *certServer { // TODO: this is a stub
	return &certServer{
		addr: "127.0.0.1:20002",
		key:  "ssh_host_ed25519_key",
		totp: NewTotpValidator(map[string]string{
			"meow":   "sampletotpsecret",
			"newbie": "sampletotpsecret",
		}),
	}
}

// CLI entrypoint
func main() {
	server := NewCertServer()
	err := server.run()
	if err != nil {
		log.Fatal(err)
	}
}

// Handle a single TCP connection
func handleTCP(tcp net.Conn, sshd *ssh.ServerConfig) {
	tcp.SetDeadline(time.Now().Add(MaxSessionLength))

	conn, chans, reqs, err := ssh.NewServerConn(tcp, sshd)
	if err != nil {
		log.Printf("failed to handshake with %s: %v", tcp.RemoteAddr(), err)
		return
	}
	log.Printf("ssh connection from %s", logConnection(conn))
	go ssh.DiscardRequests(reqs)
	go handleSSH(conn, chans)
}

// Handle incoming SSH requests
func handleSSH(conn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
	defer conn.Close()
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			newCh.Reject(ssh.UnknownChannelType, fmt.Sprintf("unknown channel type %s", newCh.ChannelType()))
			continue
		}
		channel, requests, err := newCh.Accept()
		if err != nil {
			log.Printf("could not accept channel: %v", err)
			continue
		}
		term := terminal.NewTerminal(channel, "> ")
		go func() {
			defer channel.Close()

			// Read a single line from SSH session
			line, err := term.ReadLine()
			if err != nil {
				return
			}
			fmt.Println(line)
		}()
		go func() {
			allowed := map[string]bool{
				"shell":   true,
				"pty-req": true,
			}
			for r := range requests {
				r.Reply(allowed[r.Type], nil)
			}
		}()
	}
}

// Configure ssh server
func newSSHd(hostKeyPath string) (*ssh.ServerConfig, error) {
	server := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubkey ssh.PublicKey) (*ssh.Permissions, error) {
			if pubkey.Type() != ssh.KeyAlgoED25519 {
				return nil, fmt.Errorf("key type not supported: %s", pubkey.Type())
			}
			return &ssh.Permissions{
				Extensions: map[string]string{
					"pubkey":      base64.StdEncoding.EncodeToString(pubkey.Marshal()),
					"pubkey-type": pubkey.Type(),
				},
			}, nil
		},
	}
	hostKeyBytes, err := os.ReadFile(hostKeyPath)
	if err != nil {
		return nil, errors.Wrap(err, "failed to read the host key")
	}
	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse the host key")
	}
	server.AddHostKey(hostKey)
	return server, nil
}

// Format ssh connection information for including in logs
func logConnection(conn *ssh.ServerConn) string {
	ext := conn.Permissions.Extensions
	return fmt.Sprintf("%s@%s (%s %s)", conn.User(), conn.RemoteAddr(), ext["pubkey-type"], ext["pubkey"])
}
