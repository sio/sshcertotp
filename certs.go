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

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/terminal"
)

// This struct holds all application state
type certServer struct {
	addr       string
	totp       *TotpValidator
	sshd       *ssh.ServerConfig
	signer     ssh.Signer
	validity   time.Duration
	tcpTimeout time.Duration
	ready      bool
}

// Initialize certServer instance
func NewCertServer(config *certServerConfig) (*certServer, error) {
	sshd, signer, err := sshdConfig(config.CAPath)
	if err != nil {
		return nil, err
	}
	validity := config.Validity
	var zero time.Duration
	if validity == zero || validity > MaxCertValidity {
		validity = MaxCertValidity
	}
	server := &certServer{
		addr:       config.Address,
		totp:       NewTotpValidator(config.TOTPSecrets),
		sshd:       sshd,
		signer:     signer,
		validity:   validity,
		tcpTimeout: MaxSessionLength,
	}
	return server, nil
}

// Initialize certServer from configuration file
func NewCertServerFromFile(path string) (*certServer, error) {
	config, err := LoadConfig(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config (%s): %w", path, err)
	}
	server, err := NewCertServer(config)
	if err != nil {
		return nil, err
	}
	return server, nil
}

// Loop forever; service incoming connections
func (cs *certServer) run(stop <-chan bool) error {
	listener, err := net.Listen("tcp", cs.addr)
	if err != nil {
		return fmt.Errorf("failed to listen for connection: %w", err)
	}
	defer listener.Close()

	go func() {
		<-stop
		cs.ready = false
		log.Printf("received a signal to stop")
		listener.Close()
	}()

	log.Printf("%s is listening on %s", os.Args[0], listener.Addr())
	cs.ready = true
	for {
		conn, err := listener.Accept()
		if err != nil {
			if conn != nil {
				log.Printf("failed to accept connection from %s: %v", conn.RemoteAddr(), err)
			} else {
				log.Printf("failed to accept connection: %v", err)
			}
			opErr, ok := err.(*net.OpError)
			if ok && opErr.Op == "accept" {
				break
			}
			continue
		}
		go cs.handleTCP(conn)
	}
	return nil
}

// Handle a single TCP connection
func (cs *certServer) handleTCP(tcp net.Conn) {
	tcp.SetDeadline(time.Now().Add(cs.tcpTimeout))

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
		ValidBefore:     uint64(now.Add(cs.validity).Unix()),
		Permissions: ssh.Permissions{
			Extensions: map[string]string{
				"permit-agent-forwarding": "",
				"permit-port-forwarding":  "",
				"permit-pty":              "",
			},
		},
	}
	err = cert.SignCert(rand.Reader, cs.signer)
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
func sshdConfig(hostKeyPath string) (*ssh.ServerConfig, ssh.Signer, error) {
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
	stat, err := os.Stat(hostKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("could not stat %s: %w", hostKeyPath, err)
	}
	if stat.Mode().Perm()&0b000111111 != 0 {
		log.Printf("CA private key is accessible to other users: %s (%s)", hostKeyPath, stat.Mode())
	}
	hostKeyBytes, err := os.ReadFile(hostKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to read the host key: %w", err)
	}
	hostKey, err := ssh.ParsePrivateKey(hostKeyBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse the host key: %w", err)
	}
	hostKeyAlgo := hostKey.PublicKey().Type()
	if hostKeyAlgo != ssh.KeyAlgoED25519 {
		return nil, nil, fmt.Errorf("host key algorithm not supported: %s", hostKeyAlgo)
	}
	server.AddHostKey(hostKey)

	year, month, _ := time.Now().Date()
	startOfMonth := time.Date(year, month, 1, 0, 0, 0, 0, time.FixedZone("UTC", 0))
	hostCert := ssh.Certificate{
		Key:         hostKey.PublicKey(),
		KeyId:       "sshcertotp",
		CertType:    ssh.HostCert,
		Serial:      uint64(startOfMonth.Unix()),
		ValidAfter:  uint64(startOfMonth.Unix()),
		ValidBefore: uint64(startOfMonth.Add(time.Hour * 24 * 365).Unix()), // if you don't restart a process for 11+ months you have a problem
	}
	err = hostCert.SignCert(rand.Reader, hostKey)
	if err != nil {
		return nil, nil, err
	}
	hostCertSigner, err := ssh.NewCertSigner(&hostCert, hostKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to initialize cert signer: %w", err)
	}
	server.AddHostKey(hostCertSigner)
	return server, hostKey, nil
}

// Format ssh connection information for including in logs
func logConnection(conn *ssh.ServerConn) string {
	ext := conn.Permissions.Extensions
	return fmt.Sprintf("%s@%s (%s %s)", conn.User(), conn.RemoteAddr(), ext["pubkey-type"], ext["pubkey"])
}

// Check if username is safe
func safeUsername(name string) bool {
	extra := &unicode.RangeTable{
		R16: []unicode.Range16{
			{0x2d, 0x2d, 1}, // dash "-"
			{0x5f, 0x5f, 1}, // underscore "_"
		},
	}
	for _, r := range name {
		if !unicode.In(r, unicode.Letter, unicode.Number, extra) {
			return false
		}
	}
	return true
}
