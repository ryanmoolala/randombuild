package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const timeout = 60 * time.Second // Total run duration.

type ICMPHeader struct {
	Type       uint8
	Code       uint8
	Checksum   uint16
	Identifier uint16
	Sequence   uint16
}

type PingPacket struct {
	Header  ICMPHeader
	Payload []byte
}

func checksum(data []byte) uint16 {
	var sum uint32
	for len(data) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(data[:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func (p *PingPacket) marshal() []byte {
	data := make([]byte, 8+len(p.Payload))
	data[0], data[1] = p.Header.Type, p.Header.Code
	binary.BigEndian.PutUint16(data[4:6], p.Header.Identifier)
	binary.BigEndian.PutUint16(data[6:8], p.Header.Sequence)
	copy(data[8:], p.Payload)
	// Checksum covers the entire ICMP message, with its checksum field zero.
	p.Header.Checksum = checksum(data)
	binary.BigEndian.PutUint16(data[2:4], p.Header.Checksum)
	return data
}

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

// func reverse_dns_lookup(ctx context.Context, ip string) string {
// 	lookupCtx, cancel := context.WithTimeout(ctx, time.Second)
// 	defer cancel()
// 	names, err := net.DefaultResolver.LookupAddr(lookupCtx, ip)
// 	if err != nil || len(names) == 0 {
// 		return ip
// 	}
// 	return names[0]
// }

func receive_reply(ctx context.Context, fd int, target net.IP, packet PingPacket, sent time.Time) (bool, error) {
	buffer := make([]byte, 65535)
	deadline := sent.Add(time.Second)
	for ctx.Err() == nil && time.Now().Before(deadline) {
		n, from, err := syscall.Recvfrom(fd, buffer, 0)
		// fmt.Printf("Received %d bytes from %v\n", n, from)
		if err != nil {
			if errors.Is(err, syscall.EAGAIN) || errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EINTR) {
				continue
			}
			return false, err
		}
		source, ok := from.(*syscall.SockaddrInet4)
		if !ok || !net.IP(source.Addr[:]).Equal(target) {
			continue
		}
		// Linux raw IPv4 receives include an IPv4 header; account for IP options.
		if n < 20 || buffer[0]>>4 != 4 || buffer[9] != syscall.IPPROTO_ICMP {
			continue
		}
		ihl := int(buffer[0]&0x0f) * 4
		if ihl < 20 || n < ihl+8 {
			continue
		}
		msg := buffer[ihl:n]
		if msg[0] != 0 || msg[1] != 0 || checksum(msg) != 0 ||
			binary.BigEndian.Uint16(msg[4:6]) != packet.Header.Identifier ||
			binary.BigEndian.Uint16(msg[6:8]) != packet.Header.Sequence ||
			!bytes.Equal(msg[8:], packet.Payload) {
			continue
		}
		fmt.Printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
			len(msg), target, packet.Header.Sequence, buffer[8], float64(time.Since(sent))/float64(time.Millisecond))
		return true, nil
	}
	return false, nil
}

func send_ping(ctx context.Context, hostname string) error {
	ip, err := dns_lookup(ctx, hostname) //GET IP ADDRESS
	if err != nil {
		return fmt.Errorf("DNS lookup: %w", err)
	}
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP) //GET RAW SOCKET
	if err != nil {
		return fmt.Errorf("create raw socket (requires root or CAP_NET_RAW): %w", err)
	}
	defer syscall.Close(fd)
	// Short blocking reads let us check Ctrl+C and the reply deadline regularly.
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO,
		&syscall.Timeval{Sec: 0, Usec: 100000}); err != nil {
		return fmt.Errorf("set receive timeout: %w", err)
	}
	var destination syscall.SockaddrInet4
	copy(destination.Addr[:], ip)
	packet := PingPacket{
		Header: ICMPHeader{Type: 8, Code: 0, Identifier: uint16(os.Getpid()), Sequence: 1},
		Payload: []byte("ping-data"),
	}
	transmitted, received := 0, 0
	defer func() { //HAPPENS AT THE END OF THE FUNCTION
		loss := 0.0
		if transmitted > 0 {
			loss = 100 * float64(transmitted-received) / float64(transmitted)
		}
		fmt.Printf("\n--- %s ping statistics ---\n%d transmitted, %d received, %.1f%% packet loss\n",
			hostname, transmitted, received, loss)
	}()
	for ctx.Err() == nil {
		data := packet.marshal()
		sent := time.Now()

		fmt.Printf("PING %s (%s), %d data bytes\n", hostname, ip, len(packet.Payload))
		if err := syscall.Sendto(fd, data, 0, &destination); err != nil {
			return fmt.Errorf("send: %w", err)
		}
		transmitted++
		

		ok, err := receive_reply(ctx, fd, ip, packet, sent)
		if err != nil {
			return fmt.Errorf("receive: %w", err)
		}

		if ok {
			received++
			packet.Header.Sequence++
		} else if ctx.Err() == nil {
			fmt.Printf("Request timeout for icmp_seq=%d\n",
				packet.Header.Sequence)
		}

		wait := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			wait.Stop()
			return nil
		case <-wait.C:
		}
	}
	return nil
}

func main() {
	hostname := "www.google.com"
	if len(os.Args) > 1 {
		hostname = os.Args[1]
	}
	signalCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(signalCtx, timeout)
	defer cancel()
	if err := send_ping(ctx, hostname); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}