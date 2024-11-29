
# Compose HTML Message

```go
m := mail.NewMessage()
m.SetHeader("From", "alex@example.com")
m.SetHeader("To", "bob@example.com", "cora@example.com")
m.SetAddressHeader("Cc", "dan@example.com", "Dan")
m.SetHeader("Subject", "Hello!")
m.SetBody("text/html", "Hello <b>Bob</b> and <i>Cora</i>!")
m.Attach("/home/Alex/lolcat.jpg")

d := mail.NewDialer("smtp.example.com", 587, "user", "123456")
//d.TLSConfig = &tls.Config{InsecureSkipVerify: true} // enable this for self signed certificates
d.StartTLSPolicy = mail.MandatoryStartTLS

// Send the email to Bob, Cora and Dan.
if err := d.DialAndSend(m); err != nil {
	panic(err)
}
```


# Efficiently send a customized newsletter to a list of recipients

```go
// The list of recipients.
var list []struct {
	Name    string
	Address string
}

d := mail.NewDialer("smtp.example.com", 587, "user", "123456")
d.StartTLSPolicy = mail.MandatoryStartTLS
s, err := d.Dial()
if err != nil {
	panic(err)
}

m := mail.NewMessage()
for _, r := range list {
	m.SetHeader("From", "no-reply@example.com")
	m.SetAddressHeader("To", r.Address, r.Name)
	m.SetHeader("Subject", "Newsletter #1")
	m.SetBody("text/html", fmt.Sprintf("Hello %s!", r.Name))

	if err := mail.Send(s, m); err != nil {
		log.Printf("Could not send email to %q: %v", r.Address, err)
	}
	m.Reset()
}
```


# No Auth: Send an email using a local SMTP server

```go
m := mail.NewMessage()
m.SetHeader("From", "from@example.com")
m.SetHeader("To", "to@example.com")
m.SetHeader("Subject", "Hello!")
m.SetBody("text/plain", "Hello!")

d := mail.Dialer{Host: "localhost", Port: 587}
if err := d.DialAndSend(m); err != nil {
	panic(err)
}
```


# No SMTP: Send an email using an API or postfix

```go
m := mail.NewMessage()
m.SetHeader("From", "from@example.com")
m.SetHeader("To", "to@example.com")
m.SetHeader("Subject", "Hello!")
m.SetBody("text/plain", "Hello!")

s := mail.SendFunc(func(from string, to []string, msg io.WriterTo) error {
	// Implements you email-sending function, for example by calling
	// an API, or running postfix, etc.
	fmt.Println("From:", from)
	fmt.Println("To:", to)
	return nil
})

if err := mail.Send(s, m); err != nil {
	panic(err)
}
```



# A daemon that listens to a channel and sends all incoming messages

```go
ch := make(chan *mail.Message)

go func() {
	d := mail.NewDialer("smtp.example.com", 587, "user", "123456")
	d.StartTLSPolicy = mail.MandatoryStartTLS

	var s mail.SendCloser
	var err error
	open := false
	for {
		select {
		case m, ok := <-ch:
			if !ok {
				return
			}
			if !open {
				if s, err = d.Dial(); err != nil {
					panic(err)
				}
				open = true
			}
			if err := mail.Send(s, m); err != nil {
				log.Print(err)
			}
		// Close the connection to the SMTP server if no email was sent in
		// the last 30 seconds.
		case <-time.After(30 * time.Second):
			if open {
				if err := s.Close(); err != nil {
					panic(err)
				}
				open = false
			}
		}
	}
}()
```

