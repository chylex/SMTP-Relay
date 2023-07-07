package config

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
)

type Account struct {
	Username     string
	PasswordHash []byte
	AllowedFrom  []string
	Remote       Remote
}

type Remote struct {
	Scheme   string
	Hostname string
	Port     string
	Addr     string
	Username string
	Password string
}

type AccountJson struct {
	LocalUsername     string   `json:"localUsername"`
	LocalPasswordHash string   `json:"localPasswordHash"`
	RemoteHostname    string   `json:"remoteHostname"`
	RemoteUsername    string   `json:"remoteUsername"`
	RemotePassword    string   `json:"remotePassword"`
	AllowedFrom       []string `json:"allowedFrom"`
}

func ReadAccountsFromFile(filePath string) (map[string]Account, error) {
	var accountList []AccountJson

	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}

	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()

	err = decoder.Decode(&accountList)
	_ = file.Close()
	if err != nil {
		return nil, err
	}

	accounts := make(map[string]Account)
	for _, account := range accountList {
		remote, err := parseRemote(account.RemoteHostname, account.RemoteUsername, account.RemotePassword)
		if err != nil {
			return nil, err
		}

		accounts[account.LocalUsername] = Account{
			Username:     account.LocalUsername,
			PasswordHash: []byte(account.LocalPasswordHash),
			AllowedFrom:  account.AllowedFrom,
			Remote:       *remote,
		}
	}

	return accounts, nil
}

// parseRemote creates a remote from a given url in the following format:
//
// smtp://[host][:port]
// smtps://[host][:port]
// starttls://[host][:port]
func parseRemote(remoteURL string, username string, password string) (*Remote, error) {
	u, err := url.Parse(remoteURL)
	if err != nil {
		return nil, err
	}

	if u.Scheme != "smtp" && u.Scheme != "smtps" && u.Scheme != "starttls" {
		return nil, fmt.Errorf("'%s' is not a supported relay scheme", u.Scheme)
	}

	if u.User != nil {
		return nil, fmt.Errorf("user in URL is not supported")
	}

	if u.Path != "" {
		return nil, fmt.Errorf("path in URL is not supported")
	}

	hostname, port := u.Hostname(), u.Port()

	if port == "" {
		switch u.Scheme {
		case "smtp":
			port = "25"
		case "smtps":
			port = "465"
		case "starttls":
			port = "587"
		}
	}

	r := &Remote{
		Scheme:   u.Scheme,
		Hostname: hostname,
		Port:     port,
		Addr:     fmt.Sprintf("%s:%s", hostname, port),
		Username: username,
		Password: password,
	}

	return r, nil
}
