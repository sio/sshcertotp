package main

import (
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	ListenAddr       = "127.0.0.1:20002"
	HostKeyPath      = "ssh_host_ed25519_key"
	MaxSessionLength = 30 * time.Second
)

// CLI entrypoint
func main() {
	listener, err := net.Listen("tcp", ListenAddr)
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	defer listener.Close()

	sshd := newSSHd(HostKeyPath)
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection from %s: %v", conn.RemoteAddr(), err)
			continue
		}
		go handleTCP(conn, sshd)
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
			return
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
func newSSHd(hostKeyPath string) *ssh.ServerConfig {
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
		log.Fatal("failed to read the host key: ", err)
	}
	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		log.Fatal("failed to parse the host key: ", err)
	}
	server.AddHostKey(hostKey)
	return server
}

// Format ssh connection information for including in logs
func logConnection(conn *ssh.ServerConn) string {
	ext := conn.Permissions.Extensions
	return fmt.Sprintf("%s@%s (%s %s)", conn.User(), conn.RemoteAddr(), ext["pubkey-type"], ext["pubkey"])
}
