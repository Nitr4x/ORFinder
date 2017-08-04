package scanner

import (
	"bufio"
	"fmt"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/proxy"
)

// Function randomString() string
// Generate a random string from "orfinder" to avoid blacklisting
// Return the generated string
func randomString() string {
	src := "orfinder"
	buf := make([]byte, len(src))

	for i := 0; i < len(src); i++ {
		buf[i] = src[rand.Intn(len(src))]
	}

	return string(buf)
}

// Function sendCmd(con net.Conn, cmd string, status int) bool
// Send command to the smtp services
// Return true in case of success
func sendCmd(con net.Conn, cmd string, status int) bool {
	b := make([]byte, 4096)

	fmt.Fprintf(con, cmd)
	bufio.NewReader(con).Read(b)

	if strings.Contains(string(b), strconv.Itoa(status)) {
		return true
	}

	return false
}

// Function isVulnerable(address net.IP) bool
// Check if the smtp service is vulnerable to open relay attack
// Return true if vulnerable
func isVulnerable(address net.IP) bool {
	dialer, err := proxy.SOCKS5("tcp", "127.0.0.1:9050", nil, proxy.Direct)
	if err != nil {
		log.Fatal(err)
	}

	con, err := dialer.Dial("tcp", fmt.Sprintf("%s:%d", address.To4(), 25))
	if err != nil {
		log.Fatal(err)
	}

	defer con.Close()

	if sendCmd(con, "", 220) {
		if sendCmd(con, fmt.Sprintf("HELO %s.com\n", randomString()), 250) {
			if sendCmd(con, fmt.Sprintf("MAIL FROM: %s@gmail.com\n", randomString()), 250) {
				if sendCmd(con, fmt.Sprintf("RCPT TO: %s@gmail.com\n", randomString()), 250) {
					return true
				}
			}
		}
	}

	return false
}
