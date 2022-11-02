package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"time"
	"unicode"

	"github.com/pkg/errors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	MaxSessionLength    = 30 * time.Second
	CertificateLifetime = 4 * time.Hour
)

// CLI entrypoint
func main() {
	server, err := NewCertServer(
		"127.0.0.1:20002",
		"ssh_host_ed25519_key",
		map[string]string{
			"meow":   "sampletotpsecret",
			"newbie": "sampletotpsecret",
		},
	)
	if err != nil {
		log.Fatal(err)
	}
	err = server.run()
	if err != nil {
		log.Fatal(err)
	}
}

// This struct holds all application state
type certServer struct {
	addr   string
	totp   *TotpValidator
	sshd   *ssh.ServerConfig
	signer *ssh.Signer
}

func NewCertServer(addr string, hostkey string, secrets map[string]string) (*certServer, error) { // TODO: this is a stub
	sshd, signer, err := sshdConfig(hostkey)
	if err != nil {
		return nil, err
	}
	server := &certServer{
		addr:   addr,
		totp:   NewTotpValidator(secrets),
		sshd:   sshd,
		signer: signer,
	}
	return server, nil
}

func (cs *certServer) run() error {
	listener, err := net.Listen("tcp", cs.addr)
	if err != nil {
		return errors.Wrap(err, "failed to listen for connection")
	}
	defer listener.Close()

	log.Printf("%s is listening on %s", os.Args[0], listener.Addr())
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("failed to accept connection from %s: %v", conn.RemoteAddr(), err)
			continue
		}
		go cs.handleTCP(conn)
	}
	return nil
}

// Handle a single TCP connection
func (cs *certServer) handleTCP(tcp net.Conn) {
	tcp.SetDeadline(time.Now().Add(MaxSessionLength))

	conn, chans, reqs, err := ssh.NewServerConn(tcp, cs.sshd)
	if err != nil {
		log.Printf("failed to handshake with %s: %v", tcp.RemoteAddr(), err)
		tcp.Close()
		return
	}
	if !safeUsername(conn.User()) {
		log.Printf("unsafe username from %s", tcp.RemoteAddr())
		tcp.Close()
		return
	}
	log.Printf("ssh connection from %s", logConnection(conn))
	go ssh.DiscardRequests(reqs)
	go cs.handleSSH(conn, chans)
}

// Handle incoming SSH requests
func (cs *certServer) handleSSH(conn *ssh.ServerConn, chans <-chan ssh.NewChannel) {
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
		go func() {
			defer channel.Close()

			// Read a single line from SSH session
			term := terminal.NewTerminal(channel, "> ")
			line, err := term.ReadPassword("# ")
			if err != nil {
				return
			}
			if !cs.totp.Check(conn.User(), line) {
				log.Printf("TOTP check failed for %s", conn.User())
				return
			}
			log.Printf("TOTP check successful for %s", conn.User())
			cert := cs.Sign(conn)
			term.Write([]byte(fmt.Sprintf("# TOTP accepted. User certificate printed below:\n#\n%s\n", cert)))
			log.Printf("New certificate: %s", cert)
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

// Issue new certificate for the public key of incoming connection
func (cs *certServer) Sign(conn *ssh.ServerConn) string {
	nocert := ""
	pubKeyB64, ok := conn.Permissions.Extensions["pubkey"]
	if !ok {
		return nocert
	}
	pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
	if err != nil {
		return nocert
	}
	pubkey, err := ssh.ParsePublicKey(pubKeyBytes)
	if err != nil {
		return nocert
	}
	now := time.Now()
	comment := fmt.Sprintf("%s/%d", conn.User(), now.UnixNano())
	cert := ssh.Certificate{
		Key:             pubkey,
		KeyId:           comment,
		CertType:        ssh.UserCert,
		Serial:          uint64(now.UnixNano()), // 1ns granularity is enough for revocation
		ValidPrincipals: []string{conn.User()},
		ValidAfter:      uint64(now.Unix()),
		ValidBefore:     uint64(now.Add(CertificateLifetime).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
			},
		},
	}
	err = cert.SignCert(rand.Reader, *cs.signer)
	if err != nil {
		return nocert
	}
	return fmt.Sprintf(
		"%s %s %s",
		cert.Type(),
		base64.StdEncoding.EncodeToString(cert.Marshal()),
		comment,
	)
}

// Configure ssh server
func sshdConfig(hostKeyPath string) (*ssh.ServerConfig, *ssh.Signer, error) {
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
		return nil, nil, errors.Wrap(err, "failed to read the host key")
	}
	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to parse the host key")
	}
	hostKeyAlgo := hostKey.PublicKey().Type()
	if hostKeyAlgo != ssh.KeyAlgoED25519 {
		return nil, nil, fmt.Errorf("host key algorithm not supported: %s", hostKeyAlgo)
	}
	server.AddHostKey(hostKey)
	return server, &hostKey, nil
}

// Format ssh connection information for including in logs
func logConnection(conn *ssh.ServerConn) string {
	ext := conn.Permissions.Extensions
	return fmt.Sprintf("%s@%s (%s %s)", conn.User(), conn.RemoteAddr(), ext["pubkey-type"], ext["pubkey"])
}

// Check if username is safe
func safeUsername(name string) bool {
	for _, r := range name {
		if !unicode.In(r, unicode.Letter, unicode.Number) {
			return false
		}
	}
	return true
}
