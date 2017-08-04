package scanner

import (
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/fatih/color"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Function getLocalAddress(dstip net.IP) (net.IP, layers.TCPPort)
// Get the local address necessary to instantiate the TCP connexion
// Return the source IP and port
func getLocalAddress(dstip net.IP) (net.IP, layers.TCPPort) {
	serverAddr, err := net.ResolveUDPAddr("udp", dstip.String()+":12345")
	if err != nil {
		log.Fatal(err)
	}

	if con, _ := net.DialUDP("udp", nil, serverAddr); err == nil {
		if udpaddr, ok := con.LocalAddr().(*net.UDPAddr); ok {
			return udpaddr.IP, layers.TCPPort(udpaddr.Port)
		}
	}
	return nil, layers.TCPPort(0)
}

// Function portIsOpen(dstip net.IP, dstport layers.TCPPort) bool
// Perform SYN SCAN to detect open port
// Retrun true if the given port is open
func portIsOpen(dstip net.IP, dstport layers.TCPPort) bool {
	srcip, srcport := getLocalAddress(dstip)

	ip := &layers.IPv4{
		SrcIP:    srcip,
		DstIP:    dstip,
		Protocol: layers.IPProtocolTCP,
	}

	tcp := &layers.TCP{
		SrcPort: srcport,
		DstPort: dstport,
		Seq:     1105024978,
		SYN:     true,
		Window:  14600,
	}

	tcp.SetNetworkLayerForChecksum(ip)

	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		ComputeChecksums: true,
		FixLengths:       true,
	}

	if err := gopacket.SerializeLayers(buf, opts, tcp); err != nil {
		log.Fatal(err)
	}

	con, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
	if err != nil {
		log.Fatal(err)
	}

	if _, err := con.WriteTo(buf.Bytes(), &net.IPAddr{IP: dstip}); err != nil {
		log.Fatal(err)
	}

	if err := con.SetDeadline(time.Now().Add(time.Second)); err != nil {
		log.Fatal(err)
	}

	for {
		b := make([]byte, 4096)

		n, addr, err := con.ReadFrom(b)
		if err != nil {
			return false
		} else if addr.String() == dstip.String() {
			packet := gopacket.NewPacket(b[:n], layers.LayerTypeTCP, gopacket.Default)

			if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
				tcp, _ := tcpLayer.(*layers.TCP)

				if tcp.DstPort == srcport {
					if tcp.SYN && tcp.ACK {
						return true
					}
				}
			}
		}

	}
}

// Function inc(ip net.IP)
// Enumerate IPs within a range
func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// Function Scan(address string, wg *sync.WaitGroup)
// Perform SYN scanning on a given IP range
func Scan(address string, wg *sync.WaitGroup) {
	ip, ipnet, err := net.ParseCIDR(address)
	if err != nil {
		log.Fatal(err)
	}

	for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
		res := portIsOpen(ip, 25)

		if res {
			if isVulnerable(ip) {
				color.Green(fmt.Sprintf("[+] %s is vulnerable to open relay attack", ip))
			} else {
				color.Red(fmt.Sprintf("[-] %s is not vulnerable to open relay attack", ip))
			}
		}
	}

	wg.Done()
}
