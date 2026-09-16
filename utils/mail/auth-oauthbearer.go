
package mail

// added by unixman # r.20260915
// (c) 2024-present unix-world.org

import (
	"fmt"
	"errors"
	"strconv"
	"net/smtp"
)


// loginOAuthBearer is an smtp.Auth that implements the LOGIN authentication mechanism.
type loginOAuthBearer struct {
	username string
	token    string
	host     string
	port     int
}


func LoginOAuthBearer(username string, token string, host string, port int) smtp.Auth {
	//--
	defer panicHandler()
	//--
	return &loginOAuthBearer{username, token, host, port}
}


func (a *loginOAuthBearer) Start(server *smtp.ServerInfo) (string, []byte, error) {
	//--
	defer panicHandler()
	//--
	advertised := false
	for _, mechanism := range server.Auth {
		if mechanism == "OAUTHBEARER" {
			advertised = true
			break
		}
	}
	if !advertised {
		return "", nil, errors.New("gomail: auth OAUTHBEARER is missing")
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
	var resp string = "n,a=" + a.username + "," + "\x01" + "host=" + a.host + "\x01" + "port=" + strconv.Itoa(a.port) + "\x01" + "auth=Bearer " + a.token + "\x01" + "\x01" // base64 will be applied inside net/smtp, don't do it here
	return "OAUTHBEARER", []byte(resp), nil
}


func (a *loginOAuthBearer) Next(fromServer []byte, more bool) ([]byte, error) {
	//--
	defer panicHandler()
	//--
	if more { // We've already sent everything.
		return nil, fmt.Errorf("gomail: unexpected server challenge # %s", fromServer)
	}
	return nil, nil
}


// #end
