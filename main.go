package main

import (
	"log"
	socks5 "socks5-demo"
)

func main() {
	server := socks5.Socks5Server{
		IP:   "localhost",
		Port: 7890,
	}
	err := server.Run()
	if err != nil {
		log.Fatalln(err)
	}
}