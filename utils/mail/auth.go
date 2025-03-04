package mail

// modified by unixman

import (
	"bytes"
	"errors"
	"fmt"
	"net/smtp"
)

// loginAuth is an smtp.Auth that implements the LOGIN authentication mechanism.
type loginAuth struct {
	username string
	password string
	host     string
}

//-- unixman
func LoginAuth(username string, password string, host string) smtp.Auth { // export the login auth to can be selected outside this package
	return &loginAuth{username, password, host}
}
//-- #unixman

func (a *loginAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
//	if !server.TLS {
	advertised := false
	for _, mechanism := range server.Auth {
		if mechanism == "LOGIN" {
			advertised = true
			break
		}
	}
	if !advertised {
		return "", nil, errors.New("gomail: AUTH LOGIN is missing")
	}
//	}
	if server.Name != a.host {
		return "", nil, errors.New("gomail: wrong host name")
	}
	return "LOGIN", nil, nil
}

func (a *loginAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if !more {
		return nil, nil
	}
	switch {
		case bytes.Equal(fromServer, []byte("Username:")):
			return []byte(a.username), nil
		case bytes.Equal(fromServer, []byte("Password:")):
			return []byte(a.password), nil
		default:
			return nil, fmt.Errorf("gomail: unexpected server challenge: %s", fromServer)
	}
}
