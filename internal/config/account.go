package config

import (
	"fmt"
	"os"

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

type Rules struct {
	AllowedFrom []string `yaml:"allowed_from"`
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
	if len(rules.AllowedFrom) == 0 {
		return fmt.Errorf("rule allowed_from must not be empty")
	}
	return nil
}
