package socks5

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"sync"
)

type ClientRequestMessage struct {
	Version  byte
	Cmd      Command
	AddrType AddressTye
	Address  string
	Port     uint16
}

type Command = byte

const (
	CmdConnect Command = 0x01
	CmdBind    Command = 0x02
	CmdUDP     Command = 0x03
)

type AddressTye = byte

const (
	TypeIPv4   AddressTye = 0x01
	TypeDomain AddressTye = 0x03
	TypeIPv6   AddressTye = 0x04
)

type ReplyTye = byte

const (
	ReplySuccess ReplyTye = iota
	ReplyServerFailure
	ReplyConnectionNotAllowed
	ReplyNetworkUnreachable
	ReplyHostUnreachable
	ReplyConnectionRefused
	ReplyTTLExpired
	ReplyCommandNotSupported
	ReplyAddressTypeNotSupported
)

func NewClientRequestMessage(conn io.Reader) (*ClientRequestMessage, error) {
	buf := make([]byte, 4)
	// 根据RFC协议  4个字节读取version  cmd(01代表connect 02代表bind  03代表udp)  RSV(固定00) ATYP(AddressType)
	_, err := io.ReadFull(conn, buf)
	if err != nil {
		return nil, err
	}
	version, command, reserved, addrTye := buf[0], buf[1], buf[2], buf[3]
	if version != SOCKS5VERSION {
		return nil, ErrVersionNotSupported
	}
	if command != CmdConnect && command != CmdBind && command != CmdUDP {
		return nil, ErrCommandNotSupported
	}
	if reserved != ReservedField {
		return nil, ErrInvalidReversedField
	}
	if addrTye != TypeIPv4 && addrTye != TypeDomain && addrTye != TypeIPv6 {
		return nil, ErrTypeNotSupported
	}
	message := &ClientRequestMessage{
		Version:  SOCKS5VERSION,
		Cmd:      command,
		AddrType: addrTye,
	}
	switch addrTye {
	case TypeIPv6:
		buf = make([]byte, net.IPv6len)
		fallthrough
	case TypeIPv4:
		if _, err := io.ReadFull(conn, buf); err != nil {
			return nil, err
		}
		ip := net.IP(buf)
		message.Address = ip.String()
	case TypeDomain:
		if _, err := io.ReadFull(conn, buf[:1]); err != nil {
			return nil, err
		}
		domainLength := buf[0]
		if domainLength > net.IPv4len {
			buf = make([]byte, domainLength)
		}
		if _, err := io.ReadFull(conn, buf[:domainLength]); err != nil {
			return nil, err
		}
		message.Address = string(buf[:domainLength])
	}
	// 读取port  2个字节
	if _, err := io.ReadFull(conn, buf[:2]); err != nil {
		return nil, err
	}
	message.Port = binary.BigEndian.Uint16(buf[:2])
	return message, nil
}

func WriteRequestSuccessMessage(conn io.Writer, ip net.IP, port uint16) error {
	addressType := TypeIPv4
	if len(ip) == net.IPv6len {
		addressType = TypeIPv6
	}
	// write version, reply success, reserved, address type
	_, err := conn.Write([]byte{SOCKS5VERSION, ReplySuccess, ReservedField, addressType})
	if err != nil {
		return err
	}
	// write bind ip
	if _, err := conn.Write(ip); err != nil {
		return err
	}
	// write bind port
	buf := make([]byte, 2)
	// 将num转为byte类型并写入
	binary.PutUvarint(buf, uint64(port))
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	return err
}

func WriteRequestFailureMessage(conn io.Writer, replyType ReplyTye) error {
	_, err := conn.Write([]byte{SOCKS5VERSION, replyType, ReservedField, TypeIPv4, 0, 0, 0, 0, 0, 0})
	return err
}