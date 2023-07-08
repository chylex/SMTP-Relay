package config

import (
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

type yamlAccountFile struct {
	Accounts []Account `yaml:"accounts"`
}

type Account struct {
	Username     string `yaml:"username"`
	PasswordHash string `yaml:"password_hash"`
	Remote       Remote `yaml:"remote"`
	Rules        Rules  `yaml:"rules"`
}

type Remote struct {
	Protocol string `yaml:"protocol"`
	Hostname string `yaml:"hostname"`
	Port     uint16 `yaml:"port"`
	Addr     string `yaml:"-"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

//goland:noinspection IdentifierGrammar
type Rules struct {
	AllowedSendersPattern    string         `yaml:"allowed_senders"`
	AllowedSendersRegex      *regexp.Regexp `yaml:"-"`
	AllowedRecipientsPattern string         `yaml:"allowed_recipients"`
	AllowedRecipientsRegex   *regexp.Regexp `yaml:"-"`
	OverrideFrom             string         `yaml:"override_from"`
}

func ReadAccountsFromFile(filePath string) (map[string]Account, error) {
	var accountList yamlAccountFile

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	err = yaml.NewDecoder(file).Decode(&accountList)
	_ = file.Close()
	if err != nil {
		return nil, err
	}

	accounts := make(map[string]Account)
	for _, account := range accountList.Accounts {
		err := validateAndProcessAccount(&account)
		if err != nil {
			return nil, err
		} else {
			accounts[account.Username] = account
		}
	}

	return accounts, nil
}

func validateAndProcessAccount(account *Account) error {
	if account.Username == "" {
		return fmt.Errorf("username must not be empty")
	}

	if account.PasswordHash == "" {
		return fmt.Errorf("password_hash must not be empty")
	}

	err := validateAndProcessRemote(&account.Remote)
	if err != nil {
		return err
	}

	err = validateAndProcessRules(&account.Rules)
	if err != nil {
		return err
	}

	return nil
}

func validateAndProcessRemote(remote *Remote) error {
	if remote.Hostname == "" {
		return fmt.Errorf("remote hostname must not be empty")
	}

	if remote.Username == "" {
		return fmt.Errorf("remote username must not be empty")
	}

	if remote.Password == "" {
		return fmt.Errorf("remote password must not be empty")
	}

	defaultPort, err := validateProtocolAndGetDefaultPort(remote.Protocol)
	if err != nil {
		return err
	}

	if remote.Port == 0 {
		remote.Port = defaultPort
	}

	remote.Addr = fmt.Sprintf("%s:%d", remote.Hostname, remote.Port)
	return nil
}

func validateProtocolAndGetDefaultPort(protocol string) (uint16, error) {
	switch protocol {
	case "smtp":
		return 25, nil
	case "smtps":
		return 465, nil
	case "starttls":
		return 587, nil
	default:
		return 0, fmt.Errorf("unknown remote protocol: %s", protocol)
	}
}

func validateAndProcessRules(rules *Rules) error {
	regex, err := parseRegex("allowed_senders", rules.AllowedSendersPattern)
	if err != nil {
		return err
	} else {
		rules.AllowedSendersRegex = regex
	}

	regex, err = parseRegex("allowed_recipients", rules.AllowedRecipientsPattern)
	if err != nil {
		return err
	} else {
		rules.AllowedRecipientsRegex = regex
	}

	return nil
}

func parseRegex(key string, pattern string) (*regexp.Regexp, error) {
	if pattern == "" {
		return nil, nil
	}

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("invalid regex in %s: %s\nError: %w", key, pattern, err)
	} else {
		return regex, nil
	}
}
