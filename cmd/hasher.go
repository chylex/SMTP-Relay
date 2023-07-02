package main

import (
	"bufio"
	"fmt"
	"os"

	"golang.org/x/crypto/bcrypt"
)

func main() {
	scanner := bufio.NewScanner(os.Stdin)

	for scanner.Scan() {
		password := scanner.Text()
		if len(password) == 0 {
			break
		}

		hash, err := hash(password)
		if err != nil {
			fmt.Printf("Error generating hash: %s\n", err)
		} else {
			fmt.Printf("%s: %s\n", password, hash)
		}
	}
}

func hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	} else {
		return string(hash), nil
	}
}
