
package mail

// modified by unixman # r.20260915

import (
	"fmt"
	"errors"

	stdmail "net/mail"

	dkim "github.com/unix-world/smartgo/mx/dkim"
)


// Sender is the interface that wraps the Send method. Send sends an email to the given addresses.
type Sender interface {
	Send(from string, to []string, msg []byte) error
}


// SendCloser is the interface that groups the Send and Close methods.
type SendCloser interface {
	Sender
	Close() error
}


// Send sends emails using the given Sender.
func Send(s Sender, dkimOpts *dkim.SignOptions, dkimVfyOpts *dkim.VerifyOptions, msgXtraEpilogueFn MessageXtraEpilogueFn, msg ...*Message) ([]MimeSentMessage, error) {
	//--
	defer panicHandler()
	//--
	mms := []MimeSentMessage{}
	//--
	for i, m := range msg {
		mm, err := send(uint(i), s, dkimOpts, dkimVfyOpts, msgXtraEpilogueFn, m)
		mms = append(mms, mm)
		if err != nil {
			return mms, &SendError{Cause: err, Index: uint(i)}
		}
	}
	//--
	return mms, nil
	//--
}


type MimeSentMessage struct {
	SendIndex 				uint
	SendError 				error
	ComposeError			error
	DkimVerifications 		[]string
	MessageBytes 			[]byte
}


func send(idx uint, s Sender, dkimOpts *dkim.SignOptions, dkimVfyOpts *dkim.VerifyOptions, msgXtraEpilogueFn MessageXtraEpilogueFn, m *Message) (MimeSentMessage, error) {
	//--
	defer panicHandler()
	//--

	mm := MimeSentMessage{
		SendIndex: idx + 1,
		ComposeError: errors.New("Empty: Init Mime Only"),
	}

	from, err := m.getFrom()
	if err != nil {
		return mm, err
	}

	to, err := m.getRecipients()
	if err != nil {
		return mm, err
	}

	mm.MessageBytes, mm.DkimVerifications, mm.ComposeError = GetComposedMessageContent(m, dkimOpts, dkimVfyOpts, msgXtraEpilogueFn)
	if(mm.ComposeError != nil) {
		return mm, mm.ComposeError
	}
	if(len(mm.MessageBytes) <= 0) {
		mm.ComposeError = errors.New("Mime Message is Empty")
		return mm, mm.ComposeError
	}
	if err := s.Send(from, to, mm.MessageBytes); err != nil {
		mm.SendError = err
		return mm, err
	}

	return mm, nil
}


func addAddress(list []string, addr string) []string {
	for _, a := range list {
		if addr == a {
			return list
		}
	}

	return append(list, addr)
}


func parseAddress(field string) (string, error) {
	//--
	defer panicHandler()
	//--
	addr, err := stdmail.ParseAddress(field)
	if err != nil {
		return "", fmt.Errorf("gomail: invalid address %q: %v", field, err)
	}
	return addr.Address, nil
}


// #end
