
package mail

// modified by unixman # r.20260915

import (
	"fmt"
	"log"

	"errors"
	"time"

	"strings"
	"bytes"

	"io"

	"net"
	"net/smtp"
	"crypto/tls"

	dkim "github.com/unix-world/smartgo/mx/dkim"
)

const ( // smtp dial (connect) timeout ; the amount of time the function waits for a connection to be accepted ; includes also the DNS resolution
	DefaultTimeOutSeconds uint8 = 15
	MinTimeOutSeconds     uint8 =  5
	MaxTimeOutSeconds     uint8 = 60
)

var SmtpDebug bool = false


//-- unixman, allow just explicit auth for dialer
func NewDialer(dkimOpts *dkim.SignOptions, dkimVfyOpts *dkim.VerifyOptions, msgXtraEpilogueFn MessageXtraEpilogueFn, mxDomain string, timeOutSec uint8, host string, port uint16, retryFailure bool, authType string, authUser string, authPass string, useSSL bool, tlsPolicy StartTLSPolicy) (*Dialer, error) {
	host = strings.TrimSpace(host)
	if(host == "") {
		return nil, errors.New("gomail: HostName is Empty")
	}
	if(port <= 0) {
		return nil, errors.New("gomail: Invalid Port Number: Zero")
	}
	if((timeOutSec < MinTimeOutSeconds) || (timeOutSec > MaxTimeOutSeconds)) {
		timeOutSec = DefaultTimeOutSeconds // default
	}
	if(useSSL) {
		tlsPolicy = NoStartTLS
	}
	return &Dialer{
		DkimSignOptions:   dkimOpts,
		DkimVerifyOptions: dkimVfyOpts,
		MsgXtraEpilogueFn: msgXtraEpilogueFn,
		LocalName:         mxDomain,
		Host:              host,
		Port:              int(port),
		SSL:               useSSL,
		StartTLSPolicy:    tlsPolicy,
		Auth:              nil, // unixman: must be init as null, will be set later based on AuthType to avoid mismatch or security issues !
		AuthType:          strings.ToUpper(strings.TrimSpace(authType)),
		Username:          authUser,
		Password:          authPass,
		Timeout:           time.Duration(timeOutSec) * time.Second,
		RetryFailure:      retryFailure,
	}, nil
}
//-- #


// NetDialTimeout specifies the DialTimeout function to establish a connection to the SMTP server. This can be used to override dialing in the case that a proxy or other special behavior is needed.
var NetDialTimeout = net.DialTimeout


type smtpClient interface {
	Hello(string) error
	Extension(string) (bool, string)
	StartTLS(*tls.Config) error
	Auth(smtp.Auth) error
	Mail(string) error
	Rcpt(string) error
	Data() (io.WriteCloser, error)
	Quit() error
	Close() error
}


// StartTLSPolicy constants are valid values for Dialer.StartTLSPolicy.
type StartTLSPolicy int


const (
	// OpportunisticStartTLS means that SMTP transactions are encrypted if
	// STARTTLS is supported by the SMTP server. Otherwise, messages are
	// sent in the clear. This is the default setting.
	OpportunisticStartTLS StartTLSPolicy = iota
	// MandatoryStartTLS means that SMTP transactions must be encrypted.
	// SMTP transactions are aborted unless STARTTLS is supported by the
	// SMTP server.
	MandatoryStartTLS
	// NoStartTLS means encryption is disabled and messages are sent in the
	// clear.
	NoStartTLS = -1
)


// A Dialer is a dialer to an SMTP server.
type Dialer struct {
	DkimSignOptions *dkim.SignOptions // by unixman
	DkimVerifyOptions *dkim.VerifyOptions // by unixman
	MsgXtraEpilogueFn MessageXtraEpilogueFn // by unixman
	// Host represents the host of the SMTP server.
	Host string
	// Port represents the port of the SMTP server.
	Port int
	// Username is the username to use to authenticate to the SMTP server.
	Username string
	// Password is the password to use to authenticate to the SMTP server.
	Password string
	// Auth represents the authentication mechanism used to authenticate to the
	// SMTP server.
	Auth smtp.Auth
	AuthType string // unixman
	// SSL defines whether an SSL connection is used. It should be false in
	// most cases since the authentication mechanism should use the STARTTLS
	// extension instead.
	SSL bool
	// TLSConfig represents the TLS configuration used for the TLS (when the
	// STARTTLS extension is used) or SSL connection.
	TLSConfig *tls.Config
	// StartTLSPolicy represents the TLS security level required to
	// communicate with the SMTP server.
	//
	// This defaults to OpportunisticStartTLS for backwards compatibility,
	// but we recommend MandatoryStartTLS for all modern SMTP servers.
	//
	// This option has no effect if SSL is set to true.
	StartTLSPolicy StartTLSPolicy
	// LocalName is the hostname sent to the SMTP server with the HELO command.
	// By default, "localhost" is sent.
	LocalName string
	// Timeout to use for read/write operations. Defaults to 10 seconds, can
	// be set to 0 to disable timeouts.
	Timeout time.Duration
	// Whether we should retry mailing if the connection returned an error,
	// defaults to true.
	RetryFailure bool
	//--
	SentMessages []MimeSentMessage // unixman
	//--
}


// Dial dials and authenticates to an SMTP server. The returned SendCloser
// should be closed when done using it.
func (d *Dialer) Dial() (SendCloser, error) {
	//--
	defer panicHandler()
	//--
	conn, err := NetDialTimeout("tcp", addr(d.Host, d.Port), d.Timeout)
	if err != nil {
		return nil, err
	}

	var tlsClient = tls.Client
	if d.SSL {
		if(SmtpDebug) {
			log.Println("[DEBUG]", "gomail:", "SMTP using SSL")
		}
		conn = tlsClient(conn, d.tlsConfig())
	}

	var smtpNewClient  = func(conn net.Conn, host string) (smtpClient, error) {
		return smtp.NewClient(conn, host)
	}
	c, err := smtpNewClient(conn, d.Host)
	if err != nil {
		return nil, err
	}

	if d.Timeout > 0 {
		if(SmtpDebug) {
			log.Println("[DEBUG]", "gomail:", "SMTP using connection TimeOut:", d.Timeout)
		}
		conn.SetDeadline(time.Now().Add(d.Timeout))
	}

	if d.LocalName != "" {
		if err := c.Hello(d.LocalName); err != nil {
			c.Close()
			return nil, err
		}
	}

	var tlsStarted bool = false
	if !d.SSL && d.StartTLSPolicy != NoStartTLS {
		ok, _ := c.Extension("STARTTLS")
		if !ok && d.StartTLSPolicy == MandatoryStartTLS {
			err := StartTLSUnsupportedError{
				Policy: d.StartTLSPolicy,
			}
			c.Close()
			return nil, err
		}
		if ok {
			if err := c.StartTLS(d.tlsConfig()); err != nil {
				if(SmtpDebug) {
					log.Println("[DEBUG]", "gomail:", "SMTP TLS Failed: `" + err.Error() + "`")
				}
				c.Close()
				return nil, err
			}
			tlsStarted = true
			if(SmtpDebug) {
				log.Println("[DEBUG]", "gomail:", "SMTP TLS Started")
			}
		}
	}

	if d.Username != "" || d.Password != "" {
		if(SmtpDebug) {
			log.Println("[DEBUG]", "gomail:", "Using SMTP Auth: `" + d.AuthType + "` ; UserName: `" + d.Username + "` ; Pass(masked): `" + strings.Repeat("*", len(d.Password)) + "`")
		}
		if d.Auth != nil { // unixman: must be init as null, will be set later based on AuthType to avoid mismatch or security issues !
			c.Close()
			return nil, errors.New("gomail: the SMTP Auth Provider must not be set via other methods (security check)")
		}
		if d.AuthType == "" {
			c.Close()
			return nil, errors.New("gomail: the SMTP Auth Type or Method is Empty / Null") // unixman: disallow autoselect the method
		} else {
			if ok, auths := c.Extension("AUTH"); ok {
				if(SmtpDebug) {
					log.Println("[DEBUG]", "gomail:", "the SMTP Server supports the following Auth Methods: `" + auths + "`")
				}
				if !strings.Contains(auths, d.AuthType) {
					c.Close()
					return nil, errors.New("gomail: the SMTP server does not support the selected Auth Method: " + d.AuthType)
				}
			} else {
				c.Close()
				return nil, errors.New("gomail: the SMTP server does not support Auth")
			}
		}
		switch(d.AuthType) { // unixman: d.Auth will be set just here based on AuthType to avoid mismatch or security issues !
			case "OAUTHBEARER":
				if !d.SSL && !tlsStarted && !isLocalhost(d.Host) {
					c.Close()
					return nil, errors.New("gomail: the selected SMTP Auth Method is unsafe over unencrypted connections, Disallow ; OAUTHBEARER Bearer Token is sensitive information")
				}
				d.Auth = LoginOAuthBearer(d.Username, d.Password, d.Host, d.Port)
				if(SmtpDebug) {
					log.Println("[DEBUG]", "gomail:", "the SMTP Client selected OAUTHBEARER Auth Method")
				}
			case "XOAUTH2": // std with google by unixman
				if !d.SSL && !tlsStarted && !isLocalhost(d.Host) {
					c.Close()
					return nil, errors.New("gomail: the selected SMTP Auth Method is unsafe over unencrypted connections, Disallow ; XOAUTH2 Bearer Token is sensitive information")
				}
				d.Auth = LoginXOauth2(d.Username, d.Password, d.Host)
				if(SmtpDebug) {
					log.Println("[DEBUG]", "gomail:", "the SMTP Client selected XOAUTH2 Auth Method")
				}
				break
			case "PLAIN":
				if !d.SSL && !tlsStarted && !isLocalhost(d.Host) {
					c.Close()
					return nil, errors.New("gomail: the selected SMTP Auth Method is unsafe over unencrypted connections, Disallow ; PLAIN Password is sensitive information")
				}
				d.Auth = smtp.PlainAuth("", d.Username, d.Password, d.Host)
				if(SmtpDebug) {
					log.Println("[DEBUG]", "gomail:", "the SMTP Client selected PLAIN Auth Method")
				}
				break
			case "LOGIN":
				if !d.SSL && !tlsStarted && !isLocalhost(d.Host) {
					c.Close()
					return nil, errors.New("gomail: the selected SMTP Auth Method is unsafe over unencrypted connections, Disallow ; LOGIN Password is sensitive information")
				}
				d.Auth = LoginAuth(d.Username, d.Password, d.Host)
				if(SmtpDebug) {
					log.Println("[DEBUG]", "gomail:", "the SMTP Client selected LOGIN Auth Method")
				}
				break
			case "CRAM-MD5":
				// for unencrypted connections the only one that is safe is CRAM-MD5, this would not reveal the password or the bearer token ...
				d.Auth = smtp.CRAMMD5Auth(d.Username, d.Password)
				if(SmtpDebug) {
					log.Println("[DEBUG]", "gomail:", "the SMTP Client selected CRAM-MD5 Auth Method")
				}
				break
			default:
				c.Close()
				return nil, errors.New("gomail: the SMTP server does not support this Auth Method: " + d.AuthType)
		}
	} else {
		if d.AuthType != "NONE" { // expects explicit NONE
			c.Close()
			return nil, errors.New("gomail: the SMTP server Auth must be set to explicit NONE when no credentials are set, but was set to: " + d.AuthType)
		}
		if(SmtpDebug) {
			log.Println("[DEBUG]", "gomail:", "Using No SMTP Auth: `" + d.AuthType + "`")
		}
	}

	if d.Auth != nil {
		if(SmtpDebug) {
			log.Println("[DEBUG]", "gomail:", "Sending Auth data to the SMTP Server")
		}
		if err = c.Auth(d.Auth); err != nil {
			if(SmtpDebug) {
				log.Println("[DEBUG]", "gomail:", "SMTP Auth Failed:", err)
			}
			c.Close()
			return nil, err
		}
	}

	return &smtpSender{c, conn, d}, nil
}


func (d *Dialer) tlsConfig() *tls.Config {
	if d.TLSConfig == nil {
		return &tls.Config{ServerName: d.Host}
	}
	return d.TLSConfig
}


func (policy *StartTLSPolicy) String() string {
	switch *policy {
		case OpportunisticStartTLS:
			return "OpportunisticStartTLS"
		case MandatoryStartTLS:
			return "MandatoryStartTLS"
		case NoStartTLS:
			return "NoStartTLS"
		default:
			return fmt.Sprintf("StartTLSPolicy:%v", *policy)
	}
}


// StartTLSUnsupportedError is returned by Dial when connecting to an SMTP
// server that does not support STARTTLS.
type StartTLSUnsupportedError struct {
	Policy StartTLSPolicy
}


func (e StartTLSUnsupportedError) Error() string {
	return "gomail: " + e.Policy.String() + " required, but " + "SMTP server does not support STARTTLS"
}


func addr(host string, port int) string {
	return fmt.Sprintf("%s:%d", host, port)
}


// DialAndSend opens a connection to the SMTP server, sends the given emails and closes the connection.
func (d *Dialer) DialAndSend(m ...*Message) error {
	//--
	defer panicHandler()
	//--
	s, err := d.Dial()
	if err != nil {
		return err
	}
	defer func() {
		err := s.Close()
		if(SmtpDebug) {
			if(err != nil) {
				log.Println("[DEBUG]", "gomail:", "SMTP Client connection closed, Err:", err)
			} else {
				log.Println("[DEBUG]", "gomail:", "SMTP Client connection closed")
			}
		}
	}()

	if(SmtpDebug) {
		log.Println("[DEBUG]", "gomail:", "SMTP Client is Sending Messages #", len(m))
	}

	var errSend error
	d.SentMessages, errSend = Send(s, d.DkimSignOptions, d.DkimVerifyOptions, d.MsgXtraEpilogueFn, m...)

	return errSend
}


type smtpSender struct {
	smtpClient
	conn net.Conn
	d    *Dialer
}


func (c *smtpSender) retryError(err error) bool {
	//--
	defer panicHandler()
	//--

	if !c.d.RetryFailure {
		return false
	}

	if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
		if(SmtpDebug) {
			log.Println("[DEBUG]", "gomail:", "SMTP Client was Retrying an Error")
		}
		return true
	}

	return err == io.EOF
}


func (c *smtpSender) Send(from string, to []string, msg []byte) error {
	//--
	defer panicHandler()
	//--

	if(msg == nil) {
		return errors.New("Message Data is Empty")
	}

	if c.d.Timeout > 0 {
		c.conn.SetDeadline(time.Now().Add(c.d.Timeout))
	}

	if(SmtpDebug) {
		log.Println("[DEBUG]", "gomail:", "SMTP Client is sending a message, From:", from, ";", "To:", to)
	}

	if err := c.Mail(from); err != nil {
		if c.retryError(err) {
			// This is probably due to a timeout, so reconnect and try again.
			sc, derr := c.d.Dial()
			if derr == nil {
				if s, ok := sc.(*smtpSender); ok {
					*c = *s
					return c.Send(from, to, msg)
				}
			}
		}

		return err
	}

	for _, addr := range to {
		if err := c.Rcpt(addr); err != nil {
			return err
		}
	}

	w, err := c.Data()
	if err != nil {
		return err
	}

	r := bytes.NewReader(msg)
	if _, err = io.Copy(w, r); err != nil {
		w.Close()
		return err
	}

	return w.Close()
}


func (c *smtpSender) Close() error {
	//--
	defer panicHandler()
	//--

	if(SmtpDebug) {
		log.Println("[DEBUG]", "gomail:", "SMTP Client will close the connection, QUIT")
	}

	return c.Quit()
}


//-- unixman
func isLocalhost(name string) bool {
	return name == "localhost" || name == "127.0.0.1" || name == "::1"
}
//-- #

// #end
