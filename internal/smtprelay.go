package smtprelay

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/chrj/smtpd"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"smtprelay/internal/config"
	"smtprelay/internal/logger"
)

var (
	cfg *config.Config
	log *logrus.Logger
)

func connectionChecker(peer smtpd.Peer) error {
	// This can't panic because we only have TCP listeners
	peerIP := peer.Addr.(*net.TCPAddr).IP

	if len(cfg.AllowedNets) == 0 {
		// Special case: empty string means allow everything
		return nil
	}

	for _, allowedNet := range cfg.AllowedNets {
		if allowedNet.Contains(peerIP) {
			return nil
		}
	}

	log.WithFields(
		logrus.Fields{
			"ip": peerIP,
		},
	).Warn("Connection refused from address outside of allowed_nets")
	return smtpd.Error{Code: 421, Message: "Denied"}
}

func addrAllowed(addr string, allowedAddrs []string) bool {
	if allowedAddrs == nil {
		// If absent, all addresses are allowed
		return true
	}

	addr = strings.ToLower(addr)

	// Extract optional domain part
	domain := ""
	if idx := strings.LastIndex(addr, "@"); idx != -1 {
		domain = strings.ToLower(addr[idx+1:])
	}

	// Test each address from allowedUsers file
	for _, allowedAddr := range allowedAddrs {
		allowedAddr = strings.ToLower(allowedAddr)

		// Three cases for allowedAddr format:
		if idx := strings.Index(allowedAddr, "@"); idx == -1 {
			// 1. local address (no @) -- must match exactly
			if allowedAddr == addr {
				return true
			}
		} else {
			if idx != 0 {
				// 2. email address (user@domain.com) -- must match exactly
				if allowedAddr == addr {
					return true
				}
			} else {
				// 3. domain (@domain.com) -- must match addr domain
				allowedDomain := allowedAddr[idx+1:]
				if allowedDomain == domain {
					return true
				}
			}
		}
	}

	return false
}

func senderChecker(peer smtpd.Peer, addr string) error {
	account, ok := cfg.Accounts[peer.Username]
	if !ok {
		// Shouldn't happen: authChecker already validated username+password
		log.WithFields(
			logrus.Fields{
				"username": peer.Username,
			},
		).Warn("could not find account")
		return smtpd.Error{Code: 451, Message: "Bad sender address"}
	}

	if !addrAllowed(addr, account.AllowedFrom) {
		log.WithFields(
			logrus.Fields{
				"username":       peer.Username,
				"sender_address": addr,
			},
		).Warn("sender address not allowed for authenticated user")
		return smtpd.Error{Code: 451, Message: "Bad sender address"}
	}

	if cfg.AllowedSender == nil {
		// Any sender is permitted
		return nil
	}

	if cfg.AllowedSender.MatchString(addr) {
		// Permitted by regex
		return nil
	}

	log.WithFields(
		logrus.Fields{
			"sender_address": addr,
		},
	).Warn("sender address not allowed by allowed_sender pattern")
	return smtpd.Error{Code: 451, Message: "Bad sender address"}
}

func recipientChecker(peer smtpd.Peer, addr string) error {
	if cfg.AllowedRecipients == nil {
		// Any recipient is permitted
		return nil
	}

	if cfg.AllowedRecipients.MatchString(addr) {
		// Permitted by regex
		return nil
	}

	log.WithFields(
		logrus.Fields{
			"recipient_address": addr,
		},
	).Warn("recipient address not allowed by allowed_recipients pattern")
	return smtpd.Error{Code: 451, Message: "Bad recipient address"}
}

func authChecker(peer smtpd.Peer, username string, password string) error {
	account, ok := cfg.Accounts[username]
	if !ok {
		log.WithFields(
			logrus.Fields{
				"username": username,
			},
		).Warn("could not find account")
		return smtpd.Error{Code: 535, Message: "Authentication credentials invalid"}
	}

	if bcrypt.CompareHashAndPassword(account.PasswordHash, []byte(password)) != nil {
		log.WithFields(
			logrus.Fields{
				"username": username,
			},
		).Warn("invalid password")
		return smtpd.Error{Code: 535, Message: "Authentication credentials invalid"}
	}

	return nil
}

func mailHandler(peer smtpd.Peer, env smtpd.Envelope) error {
	peerIP := ""
	if addr, ok := peer.Addr.(*net.TCPAddr); ok {
		peerIP = addr.IP.String()
	}

	logger := log.WithFields(
		logrus.Fields{
			"account": peer.Username,
			"from":    env.Sender,
			"to":      env.Recipients,
			"uuid":    generateUUID(),
		},
	)

	env.AddReceivedLine(peer)

	if *cfg.Command != "" {
		cmdLogger := logger.WithField("command", *cfg.Command)

		var stdout bytes.Buffer
		var stderr bytes.Buffer

		environ := os.Environ()
		environ = append(environ, fmt.Sprintf("%s=%s", "SMTPRELAY_FROM", env.Sender))
		environ = append(environ, fmt.Sprintf("%s=%s", "SMTPRELAY_TO", env.Recipients))
		environ = append(environ, fmt.Sprintf("%s=%s", "SMTPRELAY_PEER", peerIP))

		cmd := exec.Cmd{
			Env:  environ,
			Path: *cfg.Command,
		}

		cmd.Stdin = bytes.NewReader(env.Data)
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		if err != nil {
			cmdLogger.WithError(err).Error(stderr.String())
			return smtpd.Error{Code: 554, Message: "External command failed"}
		}

		cmdLogger.Info("pipe command successful: " + stdout.String())
	}

	account, ok := cfg.Accounts[peer.Username]
	if !ok {
		logger.Warning("invalid user", peer.Username)
		return nil
	}

	logger = logger.WithField("host", account.Remote.Addr)
	logger.Info("delivering mail from peer using smarthost")

	err := SendMail(
		&account,
		env.Sender,
		env.Recipients,
		env.Data,
	)
	if err != nil {
		var smtpError smtpd.Error

		switch err := err.(type) {
		case *textproto.Error:
			smtpError = smtpd.Error{Code: err.Code, Message: err.Msg}

			logger.WithFields(
				logrus.Fields{
					"err_code": err.Code,
					"err_msg":  err.Msg,
				},
			).Error("delivery failed")
		default:
			smtpError = smtpd.Error{Code: 554, Message: "Forwarding failed"}

			logger.WithError(err).
				Error("delivery failed")
		}

		return smtpError
	}

	logger.Debug("delivery successful")

	return nil
}

func generateUUID() string {
	uniqueID, err := uuid.NewRandom()

	if err != nil {
		log.WithError(err).
			Error("could not generate UUIDv4")

		return ""
	}

	return uniqueID.String()
}

func getTLSConfig() *tls.Config {
	// Ciphersuites as defined in stock Go but without 3DES and RC4
	// https://golang.org/src/crypto/tls/cipher_suites.go
	var tlsCipherSuites = []uint16{
		tls.TLS_AES_128_GCM_SHA256,
		tls.TLS_AES_256_GCM_SHA384,
		tls.TLS_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
		tls.TLS_RSA_WITH_AES_128_GCM_SHA256, // does not provide PFS
		tls.TLS_RSA_WITH_AES_256_GCM_SHA384, // does not provide PFS
	}

	if *cfg.LocalCert == "" || *cfg.LocalKey == "" {
		log.WithFields(
			logrus.Fields{
				"cert_file": *cfg.LocalCert,
				"key_file":  *cfg.LocalKey,
			},
		).Fatal("TLS certificate/key file not defined in config")
	}

	cert, err := tls.LoadX509KeyPair(*cfg.LocalCert, *cfg.LocalKey)
	if err != nil {
		log.WithField("error", err).
			Fatal("cannot load X509 keypair")
	}

	return &tls.Config{
		PreferServerCipherSuites: true,
		MinVersion:               tls.VersionTLS12,
		CipherSuites:             tlsCipherSuites,
		Certificates:             []tls.Certificate{cert},
	}
}

func Run() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: smtprelay <config_file>")
		os.Exit(1)
	}

	cfg = config.Load(os.Args[1])
	log = logger.SetupLogger(cfg.LogFile, *cfg.LogLevel, *cfg.LogFormat)

	log.Debug("starting smtprelay")

	var servers []*smtpd.Server

	// Create a server for each desired listen address
	for _, listen := range cfg.ListenAddrs {
		logger := log.WithField("address", listen.Address)

		server := &smtpd.Server{
			Hostname:          *cfg.Hostname,
			WelcomeMessage:    *cfg.WelcomeMsg,
			ReadTimeout:       cfg.ReadTimeout,
			WriteTimeout:      cfg.WriteTimeout,
			DataTimeout:       cfg.DataTimeout,
			MaxConnections:    *cfg.MaxConnections,
			MaxMessageSize:    *cfg.MaxMessageSize,
			MaxRecipients:     *cfg.MaxRecipients,
			ConnectionChecker: connectionChecker,
			SenderChecker:     senderChecker,
			RecipientChecker:  recipientChecker,
			Authenticator:     authChecker,
			Handler:           mailHandler,
		}

		var lsnr net.Listener
		var err error

		switch listen.Protocol {
		case "":
			logger.Info("listening on address")
			lsnr, err = net.Listen("tcp", listen.Address)

		case "starttls":
			server.TLSConfig = getTLSConfig()
			server.ForceTLS = cfg.LocalForceTLS

			logger.Info("listening on address (STARTTLS)")
			lsnr, err = net.Listen("tcp", listen.Address)

		case "tls":
			server.TLSConfig = getTLSConfig()

			logger.Info("listening on address (TLS)")
			lsnr, err = tls.Listen("tcp", listen.Address, server.TLSConfig)

		default:
			logger.WithField("protocol", listen.Protocol).
				Fatal("unknown protocol in listen address")
		}

		if err != nil {
			logger.WithError(err).Fatal("error starting listener")
		}
		servers = append(servers, server)

		go func() {
			server.Serve(lsnr)
		}()
	}

	handleSignals()

	// First close the listeners
	for _, server := range servers {
		logger := log.WithField("address", server.Address())
		logger.Debug("Shutting down server")
		err := server.Shutdown(false)
		if err != nil {
			logger.WithError(err).
				Warning("Shutdown failed")
		}
	}

	// Then wait for the clients to exit
	for _, server := range servers {
		logger := log.WithField("address", server.Address())
		logger.Debug("Waiting for server")
		err := server.Wait()
		if err != nil {
			logger.WithError(err).
				Warning("Wait failed")
		}
	}

	log.Debug("done")
}

func handleSignals() {
	// Wait for SIGINT, SIGQUIT, or SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	sig := <-sigs

	log.WithField("signal", sig).
		Info("shutting down in response to received signal")
}
