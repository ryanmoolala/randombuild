package main

import (
	// "bytes"
	"context"
	"encoding/binary"
	"errors"

	// "errors"
	"fmt"
	// "log"
	"net"
	// "os"go
	// "os/signal"
	"syscall"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"time"
)

// // IPv4Header represents a minimal IPv4 header (20 bytes)
// type IPv4Header struct {
// 	VersionIHL uint8   // Version (4 bits) + Internet Header Length (4 bits)
// 	TOS        uint8   // Type of Service
// 	Length     uint16  // Total Length
// 	ID         uint16  // Identification
// 	FlagsFrag  uint16  // Flags (3 bits) + Fragment Offset (13 bits)
// 	TTL        uint8   // Time to Live
// 	Protocol   uint8   // Protocol (17 for UDP)
// 	Checksum   uint16  // Header Checksum
// 	SrcIP      []byte // Source IP
// 	DstIP      []byte // Destination IP
// }

// // UDPHeader represents a UDP header (8 bytes)
// type UDPHeader struct {
// 	SrcPort  uint16
// 	DstPort  uint16
// 	Length   uint16
// 	Checksum uint16
// }

func dns_lookup(ctx context.Context, hostname string) (net.IP, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", hostname)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no IPv4 address found for %s", hostname)
	}
	return ips[0].To4(), nil
}

func marshalProbe(ipAddr net.IP, ttl int, srcPort, dstPort uint16) ([]byte, error) {
	// Raw sockets on macOS require the IP length in host byte order.
	// Marshal handles the platform's raw-socket format for us.
	header := ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + 8,
		ID:       ttl,
		TTL:      ttl,
		Protocol: syscall.IPPROTO_UDP,
		Dst:      ipAddr,
	}
	packet, err := header.Marshal()
	if err != nil {
		return nil, err
	}
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	return append(packet, udp...), nil
}

func send(ctx context.Context, hostname string, maxhops int) {
	fmt.Println("Sending packet to ", hostname)
	ipAddr, err := dns_lookup(ctx, hostname)
	if err != nil {
		fmt.Printf("DNS lookup: %v\n", err)
		return
	}
	// fmt.Println("target ip addr ", ipAddr)

	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW) //GET RAW SOCKET
	if err != nil {
		fmt.Println(fmt.Errorf("create raw socket (requires root or CAP_NET_RAW): %w", err))
		return
	}
	defer syscall.Close(fd)
	// fmt.Println("file descriptor ", fd)

	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		fmt.Printf("enable IP_HDRINCL: %v\n", err)
		return
	}
	//this option makes the kernel use the IPv4 header you built. 
	// Without it on macOS, the kernel adds another IPv4 header, 
	// producing an incorrectly structured probe. ?
	

	recvFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
	if err != nil {
		fmt.Printf("create receiving socket: %v\n", err)
		return
	}
	defer syscall.Close(recvFD)

	buffer := make([]byte, 65535)
	fmt.Printf("Traceroute to %s (%s)\n", hostname, ipAddr)

	for ttl := 1; ttl <= maxhops && ttl <= 255; ttl++ {
		srcPort := uint16(49152)
		dstPort := uint16(33434 + ttl - 1)
		packet, err := marshalProbe(ipAddr, ttl, srcPort, dstPort)
		if err != nil {
			fmt.Printf("marshal probe: %v\n", err)
			return
		}

		//send
		destination := &syscall.SockaddrInet4{}
		copy(destination.Addr[:], ipAddr)

		start := time.Now()
		if err := syscall.Sendto(
			fd, packet, 0, destination,
		); err != nil {
			fmt.Printf("send probe: %v\n", err)
			return
		}

		deadline := start.Add(2 * time.Second)
		matched := false

		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				fmt.Println(ctx.Err())
				return
			}

			// Short receive waits let us check context cancellation.
			wait := time.Until(deadline)
			if wait > 200*time.Millisecond {
				wait = 200 * time.Millisecond
			}
			if wait <= 0 {
				break
			}

			timeout := syscall.NsecToTimeval(wait.Nanoseconds())
			if err := syscall.SetsockoptTimeval(
				recvFD, syscall.SOL_SOCKET,
				syscall.SO_RCVTIMEO, &timeout,
			); err != nil {
				fmt.Printf("set receive timeout: %v\n", err)
				return
			}

			n, from, err := syscall.Recvfrom(recvFD, buffer, 0)
			if err != nil {
				if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
					continue 
				}
				fmt.Printf("receive: %v\n", err)
				return
			}

			// Strip the outer IPv4 header.
			if n < 20 || buffer[0]>>4 != 4 {
				continue
			}
			headerLength := int(buffer[0]&0x0f) * 4
			if headerLength < 20 || n < headerLength+8 {
				continue
			}

			msg, err := icmp.ParseMessage(1, buffer[headerLength:n])
			if err != nil {
				continue
			}

			// ICMP errors quote the original IP + UDP headers.
			var quoted []byte
			switch body := msg.Body.(type) {
			case *icmp.TimeExceeded:
				if msg.Code != 0 { // Only TTL expired in transit.
					continue
				}
				quoted = body.Data
			case *icmp.DstUnreach:
				quoted = body.Data
			default:
				continue
			}

			//match the quoted packet to the current UDP probe.
			if len(quoted) < 20 || quoted[0]>>4 != 4 {
				continue
			}
			quotedHeaderLength := int(quoted[0]&0x0f) * 4
			if quotedHeaderLength < 20 ||
				len(quoted) < quotedHeaderLength+8 {
				continue
			}
			if quoted[9] != 17 ||
				!net.IP(quoted[16:20]).Equal(ipAddr) {
				continue
			}

			udp := quoted[quotedHeaderLength:]
			if binary.BigEndian.Uint16(udp[:2]) != srcPort ||
				binary.BigEndian.Uint16(udp[2:4]) != dstPort {
				continue
			}

			addr, ok := from.(*syscall.SockaddrInet4)
			if !ok {
				continue
			}
			routerIP := net.IP(addr.Addr[:])

			fmt.Printf(
				"Hop %d: %s  %v  ICMP %v (type %d, code %d, %d bytes)\n",
				ttl, routerIP, time.Since(start).Round(time.Microsecond),
				msg.Type, msg.Type, msg.Code, n-headerLength,
			)
			matched = true

			if msg.Type == ipv4.ICMPTypeDestinationUnreachable {
				if msg.Code == 3 && routerIP.Equal(ipAddr) {
					fmt.Println("Destination reached.")
				} else {
					fmt.Printf("Destination unreachable, code %d\n", msg.Code)
				}
				return
			}
			break //next TTL.
		}

		if !matched {
			fmt.Printf("Hop %d: *\n", ttl)
		}

	}

}

func main() {
	send(context.Background(), "www.google.com", 30)
}
