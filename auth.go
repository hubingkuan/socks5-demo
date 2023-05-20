package socks5

import (
	"bytes"
	"errors"
	"io"
)

type ClientAuthMessage struct {
	Version  byte
	NMethods byte
	Methods  []Method
}

func NewClientAuthMessage(conn io.Reader) (*ClientAuthMessage, error) {
	buf := make([]byte, 2)
	// 根据RFC协议  2个字节读取version  nmethods
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	// 验证版本是否是sockets5
	if buf[0] != SOCKS5VERSION {
		return nil,ErrVersionNotSupported
	}
	// 读取methods
	nmethods := buf[1]
	buf = make([]byte, nmethods)
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	return &ClientAuthMessage{
		Version:  SOCKS5VERSION,
		NMethods: nmethods,
		Methods:  buf,
	}, nil
}

func NewServerAuthMessage(conn io.Writer, method Method) error {
	buf := []byte{SOCKS5VERSION, method}
	_, err := conn.Write(buf)
	return err
}

const (
	MethodNoAuth       Method = 0x00
	MethodGSSAPI       Method = 0x01
	MethodPassword     Method = 0x02
	MethodNoAcceptable Method = 0xff
)

type Method = byte