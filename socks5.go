package socks5

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
)

type Server interface {
	Run() error
}

type Socks5Server struct {
	IP   string
	Port int
}

var (
	ErrVersionNotSupported  = errors.New("protocol version not support")
	ErrCommandNotSupported  = errors.New("request command not support")
	ErrInvalidReversedField = errors.New("request reversed not support")
	ErrTypeNotSupported     = errors.New("request type not support")
	ErrAddressTypeNotSupported     = errors.New("request address type not support")
)

const (
	SOCKS5VERSION = 0x05
	ReservedField = 0x00
)

func (s *Socks5Server) Run() error {
	address := fmt.Sprintf("%s:%d", s.IP, s.Port)
	listen, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Printf("connection failure from :%s :%s", conn.RemoteAddr(), err)
			continue
		}
		go func() {
			defer conn.Close()
			err = handleConnection(conn)
			if err != nil {
				log.Printf("handle connection failure from :%s :%s", conn.RemoteAddr(), err)
			}
		}()
	}
}

func handleConnection(conn net.Conn) error {
	// 协商过程
	if err := auth(conn); err != nil {
		return err
	}
	// 请求过程
	targetConn, err := request(conn)
	if err != nil {
		return err
	}
	// 转发过程
	forward(conn,targetConn)
	return nil
}

func forward(conn io.ReadWriter,targetConn io.ReadWriteCloser){
	// 从目标服务器读取数据并写入到客户端
	go io.Copy(targetConn,conn)
	io.Copy(conn,targetConn)
}

func request(conn io.ReadWriter) (io.ReadWriteCloser, error) {
	message, err := NewClientRequestMessage(conn)
	if err != nil {
		return nil, err
	}
	if message.Cmd != CmdConnect {
		WriteRequestFailureMessage(conn, ReplyCommandNotSupported)
		return nil, ErrCommandNotSupported
	}
	if message.AddrType != TypeIPv4 {
		WriteRequestFailureMessage(conn, ReplyAddressTypeNotSupported)
		return nil, ErrTypeNotSupported
	}
	// 访问目标tcp服务
	address := fmt.Sprintf("%s:%d", message.Address, message.Port)
	targetConn, err := net.Dial("tcp", address)
	if err != nil {
		WriteRequestFailureMessage(conn,ReplyConnectionRefused)
		return nil, ErrAddressTypeNotSupported
	}
	// send success reply
	addrValue := targetConn.LocalAddr()
	addr :=addrValue.(*net.TCPAddr)
	WriteRequestSuccessMessage(conn,addr.IP,uint16(addr.Port))
	return targetConn, nil
}

func auth(conn io.ReadWriter) error {
	clientMessage, err := NewClientAuthMessage(conn)
	if err != nil {
		return err
	}
	var acceptable bool
	// 仅支持no-auth
	log.Println(clientMessage.Version, clientMessage.NMethods, clientMessage.Methods)
	for _, method := range clientMessage.Methods {
		if method == MethodNoAuth {
			acceptable = true
		}
	}
	if !acceptable {
		NewServerAuthMessage(conn, MethodNoAcceptable)
		return errors.New("method no supported")
	}
	return NewServerAuthMessage(conn, MethodNoAuth)
}