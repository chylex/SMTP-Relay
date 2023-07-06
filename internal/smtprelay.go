package smtprelay

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/chrj/smtpd"
	"github.com/sirupsen/logrus"
	"smtprelay/internal/config"
	"smtprelay/internal/logger"
	"smtprelay/internal/smtp"
)

var (
	cfg *config.Config
	log *logrus.Logger
)

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
		server := smtp.CreateRelayServer(cfg, log)
		listener := createListener(log.WithField("address", listen.Address), listen, server)
		servers = append(servers, server)

		go func() {
			server.Serve(listener)
		}()
	}

	handleSignals()

	// First close the listeners
	for _, server := range servers {
		shutdownServer(log.WithField("address", server.Address()), server)
	}

	// Then wait for the clients to exit
	for _, server := range servers {
		waitForServer(log.WithField("address", server.Address()), server)
	}

	log.Debug("done")
}

func createListener(log *logrus.Entry, listen config.ProtoAddr, server *smtpd.Server) net.Listener {
	var listener net.Listener
	var err error

	switch listen.Protocol {
	case "":
		log.Info("listening on address")
		listener, err = net.Listen("tcp", listen.Address)

	case "starttls":
		server.TLSConfig = getTlsConfig()
		server.ForceTLS = cfg.LocalForceTLS

		log.Info("listening on address (STARTTLS)")
		listener, err = net.Listen("tcp", listen.Address)

	case "tls":
		server.TLSConfig = getTlsConfig()

		log.Info("listening on address (TLS)")
		listener, err = tls.Listen("tcp", listen.Address, server.TLSConfig)

	default:
		log.WithField("protocol", listen.Protocol).Fatal("unknown protocol in listen address")
		return nil
	}

	if err != nil {
		log.WithError(err).Fatal("error starting listener")
		return nil
	}

	return listener
}

func getTlsConfig() *tls.Config {
	tlsConfig, err := smtp.GetTlsConfig(cfg.LocalCert, cfg.LocalKey)

	if err != nil {
		log.WithFields(
			logrus.Fields{
				"cert_file": *cfg.LocalCert,
				"key_file":  *cfg.LocalKey,
			},
		).WithError(err).Fatal("could not set up TLS")
	}

	return tlsConfig
}

func handleSignals() {
	// Wait for SIGINT, SIGQUIT, or SIGTERM
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	sig := <-sigs

	log.WithField("signal", sig).
		Info("shutting down in response to received signal")
}

func shutdownServer(logger *logrus.Entry, server *smtpd.Server) {
	logger.Debug("Shutting down server")
	err := server.Shutdown(false)
	if err != nil {
		logger.WithError(err).Warning("Shutdown failed")
	}
}

func waitForServer(logger *logrus.Entry, server *smtpd.Server) {
	logger.Debug("Waiting for server")
	err := server.Wait()
	if err != nil {
		logger.WithError(err).Warning("Wait failed")
	}
}
