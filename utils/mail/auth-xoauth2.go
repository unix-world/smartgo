package mail

// added by unixman
// (c) 2024 unix-world.org

import (
	"errors"
	"fmt"
	"net/smtp"
)

// loginXOauth2 is an smtp.Auth that implements the LOGIN authentication mechanism.
type loginXOauth2 struct {
	username string
	token    string
	host     string
}


func LoginXOauth2(username string, token string, host string) smtp.Auth {
	return &loginXOauth2{username, token, host}
}


func isLocalhost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}

func (a *loginXOauth2) Start(server *smtp.ServerInfo) (string, []byte, error) {
	advertised := false
	for _, mechanism := range server.Auth {
		if mechanism == "XOAUTH2" {
			advertised = true
			break
		}
	}
	if !advertised {
		return "", nil, errors.New("gomail: AUTH XOAUTH2 is missing")
	}
	// Must have TLS, or else localhost server.
	// Note: If TLS is not true, then we can't trust ANYTHING in ServerInfo.
	// In particular, it doesn't matter if the server advertises PLAIN auth.
	// That might just be the attacker saying
	// "it's ok, you can trust me with your password."
	if !server.TLS && !isLocalhost(server.Name) {
		return "", nil, errors.New("gomail: unencrypted connection")
	}
	if server.Name != a.host {
		return "", nil, errors.New("gomail: wrong host name")
	}
//	data := fmt.Sprint("user=", a.username, "\001auth=Bearer ", a.token, "\001\001")
	data := "user=" + a.username + "\x01" + "auth=Bearer " + a.token + "\x01" + "\x01" // base64 will be applied inside net/smtp, don't do it here
	resp := []byte(data)
	return "XOAUTH2", resp, nil
}

func (a *loginXOauth2) Next(fromServer []byte, more bool) ([]byte, error) {
	if more { // We've already sent everything.
		return nil, fmt.Errorf("gomail: unexpected server challenge # %s", fromServer)
	}
	return nil, nil
}

