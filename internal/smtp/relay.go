package smtp

import (
	"bytes"
	"fmt"
	"net"
	"net/textproto"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/chrj/smtpd"
	"github.com/sirupsen/logrus"
	"golang.org/x/crypto/bcrypt"
	"smtprelay/internal/config"
)

func CreateRelayServer(cfg *config.Config, log *logrus.Logger) *smtpd.Server {
	return &smtpd.Server{
		Hostname:          *cfg.Hostname,
		WelcomeMessage:    *cfg.WelcomeMsg,
		ReadTimeout:       cfg.ReadTimeout,
		WriteTimeout:      cfg.WriteTimeout,
		DataTimeout:       cfg.DataTimeout,
		MaxConnections:    *cfg.MaxConnections,
		MaxMessageSize:    *cfg.MaxMessageSize,
		MaxRecipients:     *cfg.MaxRecipients,
		Authenticator:     authChecker(cfg, log),
		ConnectionChecker: connectionChecker(cfg, log),
		SenderChecker:     senderChecker(cfg, log),
		RecipientChecker:  recipientChecker(cfg, log),
		Handler:           mailHandler(cfg, log),
	}
}

func authChecker(cfg *config.Config, log *logrus.Logger) func(peer smtpd.Peer, username string, password string) error {
	return func(peer smtpd.Peer, username string, password string) error {
		account, ok := cfg.Accounts[username]
		if !ok {
			return missingAccountError(log, username)
		}

		if bcrypt.CompareHashAndPassword([]byte(account.PasswordHash), []byte(password)) != nil {
			log.WithField("username", username).
				Warn("invalid password")

			return smtpd.Error{Code: 535, Message: "Authentication credentials invalid"}
		}

		return nil
	}
}

func missingAccountError(log *logrus.Logger, username string) error {
	log.WithField("username", username).
		Warn("could not find account")

	return smtpd.Error{Code: 535, Message: "Authentication credentials invalid"}
}

func connectionChecker(cfg *config.Config, log *logrus.Logger) func(smtpd.Peer) error {
	return func(peer smtpd.Peer) error {
		// Special case: empty string means allow everything
		if len(cfg.AllowedNets) == 0 {
			return nil
		}

		// This can't panic because we only have TCP listeners
		peerIP := peer.Addr.(*net.TCPAddr).IP

		for _, allowedNet := range cfg.AllowedNets {
			if allowedNet.Contains(peerIP) {
				return nil
			}
		}

		log.WithField("ip", peerIP).
			Warn("Connection refused from address outside of allowed_nets")

		return smtpd.Error{Code: 421, Message: "Denied"}
	}
}

func senderChecker(cfg *config.Config, log *logrus.Logger) func(peer smtpd.Peer, addr string) error {
	return func(peer smtpd.Peer, addr string) error {
		account, ok := cfg.Accounts[peer.Username]
		if !ok {
			// Shouldn't happen: authChecker already validated username+password
			return missingAccountError(log, peer.Username)
		}

		log := log.WithField("account", peer.Username)

		if !addressAllowedByRegex(account.Rules.AllowedSendersRegex, addr) {
			log.WithField("sender_address", addr).
				Warn("sender address not allowed by allowed_senders pattern")

			return smtpd.Error{Code: 451, Message: "Bad sender address"}
		}

		return nil
	}
}

func recipientChecker(cfg *config.Config, log *logrus.Logger) func(peer smtpd.Peer, addr string) error {
	return func(peer smtpd.Peer, addr string) error {
		account, ok := cfg.Accounts[peer.Username]
		if !ok {
			// Shouldn't happen: authChecker already validated username+password
			return missingAccountError(log, peer.Username)
		}

		log := log.WithField("account", peer.Username)

		if !addressAllowedByRegex(account.Rules.AllowedRecipientsRegex, addr) {
			log.WithField("recipient_address", addr).
				Warn("recipient address not allowed by allowed_recipients pattern")

			return smtpd.Error{Code: 451, Message: "Bad recipient address"}
		}

		return nil
	}
}

func mailHandler(cfg *config.Config, log *logrus.Logger) func(peer smtpd.Peer, env smtpd.Envelope) error {
	return func(peer smtpd.Peer, env smtpd.Envelope) error {
		account, ok := cfg.Accounts[peer.Username]
		if !ok {
			// Shouldn't happen: authChecker already validated username+password
			return missingAccountError(log, peer.Username)
		}

		peerIP := ""
		if addr, ok := peer.Addr.(*net.TCPAddr); ok {
			peerIP = addr.IP.String()
		}

		env.AddReceivedLine(peer)

		sender := env.Sender
		recipients := env.Recipients

		fromHeader := account.Rules.OverrideFrom
		if fromHeader == "" {
			fromHeader = fmt.Sprintf("%s <%s>", peer.Username, sender)
		} else {
			fromHeader = strings.NewReplacer(
				"%s", sender,
				"%u", peer.Username,
			).Replace(account.Rules.OverrideFrom)
		}

		message := []byte(replaceHeaders(string(env.Data), fromHeader, recipients))

		logger := log.WithFields(
			logrus.Fields{
				"account": peer.Username,
				"from":    sender,
				"to":      recipients,
				"uuid":    generateUUID(log),
			},
		)

		if *cfg.Command != "" {
			cmdLogger := logger.WithField("command", *cfg.Command)

			var stdout bytes.Buffer
			var stderr bytes.Buffer

			environ := os.Environ()
			environ = append(environ, fmt.Sprintf("%s=%s", "SMTPRELAY_FROM", sender))
			environ = append(environ, fmt.Sprintf("%s=%s", "SMTPRELAY_TO", recipients))
			environ = append(environ, fmt.Sprintf("%s=%s", "SMTPRELAY_PEER", peerIP))

			cmd := exec.Cmd{
				Env:  environ,
				Path: *cfg.Command,
			}

			cmd.Stdin = bytes.NewReader(message)
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			if err != nil {
				cmdLogger.WithError(err).Error(stderr.String())
				return smtpd.Error{Code: 554, Message: "External command failed"}
			}

			cmdLogger.Info("pipe command successful: " + stdout.String())
		}

		logger = logger.WithField("host", account.Remote.Addr)
		logger.Info("delivering mail from peer using smarthost")

		err := SendMail(&account.Remote, *cfg.Hostname, sender, recipients, message)
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
}

func addressAllowedByRegex(allowedRegex *regexp.Regexp, addr string) bool {
	// If not set, allow all addresses
	return allowedRegex == nil || allowedRegex.MatchString(addr)
}

func replaceHeaders(data string, sender string, recipients []string) string {
	lines := strings.Split(data, "\n")

	isReadingHeader := true
	hasFromHeader := false
	hasToHeader := false

	var builder strings.Builder
	for index, line := range lines {
		line = strings.TrimRight(line, "\r")

		if isReadingHeader {
			if strings.HasPrefix(line, "From:") {
				writeFromHeader(&builder, sender)
				hasFromHeader = true
				continue
			} else if strings.HasPrefix(line, "To:") {
				writeToHeader(&builder, recipients)
				hasToHeader = true
				continue
			} else if line == "" {
				isReadingHeader = false

				if !hasFromHeader {
					writeFromHeader(&builder, sender)
				}

				if !hasToHeader {
					writeToHeader(&builder, recipients)
				}
			}
		}

		builder.WriteString(line)
		if index < len(lines)-1 {
			builder.WriteString("\r\n")
		}
	}

	return builder.String()
}

func writeFromHeader(builder *strings.Builder, from string) {
	builder.WriteString("From: ")
	builder.WriteString(from)
	builder.WriteString("\r\n")
}

func writeToHeader(builder *strings.Builder, recipients []string) {
	builder.WriteString("To: ")
	builder.WriteString(strings.Join(recipients, ", "))
	builder.WriteString("\r\n")
}
