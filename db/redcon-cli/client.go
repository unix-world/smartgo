
package redconcli

import (
	"fmt"
	"errors"

	"context"
	"time"
	"io"
	"net"
)

var (
	_ io.Closer = &Client{}
)

type Client struct {
	conn   net.Conn
	reader *Reader
	writer *Writer
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) Send(values []interface{}) (*Result, error) {
	if((values == nil) || (len(values) <= 0)) {
		return nil, errors.New("failed to execute operation: values are null or empty !")
	}
	c.conn.SetDeadline(time.Now().Add(time.Second * 5))

	if err := c.writer.WriteArray(values); err != nil {
		return nil, errors.New(fmt.Sprintf("failed to execute operation: %v\n%v", err, values[0]))
	}

	return c.reader.Read()
}

func Connect(ctx context.Context, address string) (*Client, error) {
	if(address == "") {
		return nil, errors.New("failed to connect: address is empty")
	}

	dialer := net.Dialer{
		Timeout:   time.Second * 5,
		KeepAlive: time.Second * 10,
	}

	conn, err := dialer.DialContext(ctx, "tcp4", address)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("failed to connect to [%s]: %v", address, err))
	}

	return &Client{
		conn:   conn,
		reader: NewReader(conn),
		writer: NewWriter(conn),
	}, nil
}
