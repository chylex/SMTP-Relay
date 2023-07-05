package config

import (
	"flag"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/peterbourgon/ff/v3"
)

type Config struct {
	LogFile           *string
	LogFormat         *string
	LogLevel          *string
	Accounts          map[string]Account
	AllowedNets       []*net.IPNet
	AllowedSender     *regexp.Regexp
	AllowedRecipients *regexp.Regexp
	ListenAddrs       []ProtoAddr
	Hostname          *string
	WelcomeMsg        *string
	LocalCert         *string
	LocalKey          *string
	LocalForceTLS     bool
	ReadTimeout       time.Duration
	WriteTimeout      time.Duration
	DataTimeout       time.Duration
	MaxConnections    *int
	MaxMessageSize    *int
	MaxRecipients     *int
	Command           *string
}

var (
	flagset = flag.NewFlagSet("smtprelay", flag.ContinueOnError)

	// config flags
	logFile              = flagset.String("logfile", "", "Path to logfile")
	logFormat            = flagset.String("log_format", "default", "Log output format")
	logLevel             = flagset.String("log_level", "info", "Minimum log level to output")
	accountFile          = flagset.String("account_file", "", "Path to file with user accounts")
	allowedNetsStr       = flagset.String("allowed_nets", "127.0.0.0/8 ::1/128", "Networks allowed to send mails")
	allowedSenderStr     = flagset.String("allowed_sender", "", "Regular expression for valid FROM EMail addresses")
	allowedRecipientsStr = flagset.String("allowed_recipients", "", "Regular expression for valid TO EMail addresses")
	listenStr            = flagset.String("listen", "127.0.0.1:25 [::1]:25", "Address and port to listen for incoming SMTP")
	hostName             = flagset.String("hostname", "localhost.localdomain", "Server hostname")
	welcomeMsg           = flagset.String("welcome_msg", "", "Welcome message for SMTP session")
	localCert            = flagset.String("local_cert", "", "SSL certificate for STARTTLS/TLS")
	localKey             = flagset.String("local_key", "", "SSL private key for STARTTLS/TLS")
	localForceTLS        = flagset.Bool("local_forcetls", false, "Force STARTTLS (needs local_cert and local_key)")
	readTimeoutStr       = flagset.String("read_timeout", "60s", "Socket timeout for read operations")
	writeTimeoutStr      = flagset.String("write_timeout", "60s", "Socket timeout for write operations")
	dataTimeoutStr       = flagset.String("data_timeout", "5m", "Socket timeout for DATA command")
	maxConnections       = flagset.Int("max_connections", 100, "Max concurrent connections, use -1 to disable")
	maxMessageSize       = flagset.Int("max_message_size", 10240000, "Max message size in bytes")
	maxRecipients        = flagset.Int("max_recipients", 100, "Max RCPT TO calls for each envelope")
	command              = flagset.String("command", "", "Path to pipe command")

	// additional flags
	_ = flagset.String("config", "", "Path to config file (ini format)")
)

func Load() *Config {
	// use .env file if it exists
	if _, err := os.Stat(".env"); err == nil {
		err := ff.Parse(
			flagset, os.Args[1:],
			ff.WithEnvVarPrefix("smtprelay"),
			ff.WithConfigFile(".env"),
			ff.WithConfigFileParser(ff.EnvParser),
		)
		handleInvalidConfiguration(err)
	} else {
		// use env variables and smtprelay.ini file
		err := ff.Parse(
			flagset, os.Args[1:],
			ff.WithEnvVarPrefix("smtprelay"),
			ff.WithConfigFileFlag("config"),
			ff.WithConfigFileParser(IniParser),
		)
		handleInvalidConfiguration(err)
	}

	allowedNets, err := parseAllowedNetworks(*allowedNetsStr)
	handleInvalidConfiguration(err)

	allowedSender, err := parseRegex("allowed_sender", *allowedSenderStr)
	handleInvalidConfiguration(err)

	allowedRecipients, err := parseRegex("allowed_recipients", *allowedRecipientsStr)
	handleInvalidConfiguration(err)

	listenAddrs, err := parseListeners(*listenStr)
	handleInvalidConfiguration(err)

	readTimeout, err := parseDuration("read_timeout", *readTimeoutStr)
	handleInvalidConfiguration(err)

	writeTimeout, err := parseDuration("write_timeout", *writeTimeoutStr)
	handleInvalidConfiguration(err)

	dataTimeout, err := parseDuration("data_timeout", *dataTimeoutStr)
	handleInvalidConfiguration(err)

	accounts, err := ReadAccountsFromFile(*accountFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Could not load account file: %s\n", err)
		os.Exit(1)
	}

	return &Config{
		LogFile:           logFile,
		LogFormat:         logFormat,
		LogLevel:          logLevel,
		Accounts:          accounts,
		AllowedNets:       allowedNets,
		AllowedSender:     allowedSender,
		AllowedRecipients: allowedRecipients,
		ListenAddrs:       listenAddrs,
		Hostname:          hostName,
		WelcomeMsg:        welcomeMsg,
		LocalCert:         localCert,
		LocalKey:          localKey,
		LocalForceTLS:     *localForceTLS,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		DataTimeout:       dataTimeout,
		MaxConnections:    maxConnections,
		MaxMessageSize:    maxMessageSize,
		MaxRecipients:     maxRecipients,
		Command:           command,
	}
}

func handleInvalidConfiguration(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
		os.Exit(1)
	}
}

// Split a string and ignore empty results
// https://stackoverflow.com/a/46798310/119527
func splitstr(s string, sep rune) []string {
	return strings.FieldsFunc(s, func(c rune) bool { return c == sep })
}

func parseAllowedNetworks(allowedNetsStr string) ([]*net.IPNet, error) {
	var allowedNets []*net.IPNet

	for _, netstr := range splitstr(allowedNetsStr, ' ') {
		baseIP, allowedNet, err := net.ParseCIDR(netstr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR notation in allowed_nets: %s\nError: %s", netstr, err)
		}

		// Reject any network specification where any host bits are set,
		// meaning the address refers to a host and not a network.
		if !allowedNet.IP.Equal(baseIP) {
			return nil, fmt.Errorf("invalid network in allowed_nets (host bits set): %s\nAllowed net: %s", netstr, allowedNet)
		}

		allowedNets = append(allowedNets, allowedNet)
	}

	return allowedNets, nil
}

func parseListeners(listenStr string) ([]ProtoAddr, error) {
	var listenAddrs []ProtoAddr

	for _, listenAddr := range strings.Split(listenStr, " ") {
		pa := splitProto(listenAddr)

		if pa.Protocol == "" {
			return nil, fmt.Errorf("local authentication not allowed with non-TLS listener")
		}

		listenAddrs = append(listenAddrs, pa)
	}

	return listenAddrs, nil
}

func parseRegex(configKey string, pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid pattern in %s: %s\nError: %w", configKey, pattern, err)
	} else {
		return regex, nil
	}
}

func parseDuration(configurationKey string, timeoutStr string) (time.Duration, error) {
	timeout, err := time.ParseDuration(timeoutStr)
	if err != nil {
		return timeout, fmt.Errorf("invalid duration string in %s: %s\nError: %w", configurationKey, timeoutStr, err)
	} else if timeout.Seconds() < 1 {
		return timeout, fmt.Errorf("duration of %s must be at least one second", configurationKey)
	} else {
		return timeout, nil
	}
}
