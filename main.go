package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const (
	MagicPacketSize = 102
	TargetPort      = "9"
	Timeout         = 5 * time.Second
	Retries         = 3
)

func main() {
	logger := log.New(os.Stderr, "", log.LstdFlags)

	// CLI flags
	macAddr := flag.String("mac", "", "Target MAC address (e.g., AA:BB:CC:DD:EE:FF)")
	broadcastIP := flag.String("ip", "255.255.255.255", "Broadcast IP address")
	retries := flag.Int("retries", Retries, "Number of magic packet broadcasts to send")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [options]\n\n", os.Args[0])
		fmt.Println("Send a Wake-on-LAN magic packet to wake a remote machine.")
		fmt.Println("\nOptions:")
		flag.PrintDefaults()
		fmt.Println("\nExamples:")
		fmt.Printf("  %s -mac 12:34:56:78:9A:BC\n", os.Args[0])
		fmt.Printf("  %s -mac 12:34:56:78:9A:BC -ip 192.168.1.255\n", os.Args[0])
		fmt.Printf("  %s -mac AA:BB:CC:DD:EE:FF -retries 5 -timeout 500ms\n", os.Args[0])
	}

	flag.Parse()

	macBytes, err := parseMAC(*macAddr)
	if err != nil {
		logger.Fatalf("Invalid MAC address '%s': %v", *macAddr, err)
	}

	packet := buildMagicPacket(macBytes)

	// Send magic packets
	addr := net.JoinHostPort(*broadcastIP, TargetPort)
	conn, err := net.DialTimeout("udp", addr, Timeout)
	if err != nil {
		logger.Fatalf("Failed to connect: %v", err)
	}

	defer conn.Close()

	var successCount int
	for i := 0; i < *retries; i++ {
		n, err := conn.Write(packet)
		if err != nil {
			logger.Printf("Attempt %d/%d failed: %v", i+1, *retries, err)
			continue
		}

		if n != len(packet) {
			logger.Printf("Attempt %d/%d: short write (%d/%d bytes)", i+1, *retries, n, len(packet))
			continue
		}

		successCount++
		logger.Printf("Magic packet sent successfully (attempt %d/%d)", i+1, *retries)
	}

	if successCount == 0 {
		logger.Fatal("All attempts failed to send magic packet")
	}

	logger.Printf("Wake-on-LAN initiated successfully. Machine should power on within 30 seconds.")
}

// parseMAC converts a MAC address string to byte slice.
func parseMAC(mac string) ([6]byte, error) {
	var b [6]byte
	parts := strings.Split(mac, ":")

	if len(parts) == 6 {
		for i, p := range parts {
			val, err := hex.DecodeString(p)
			if err != nil {
				return b, fmt.Errorf("invalid hex segment: %w", err)
			}

			if len(val) != 1 {
				return b, fmt.Errorf("hex segment must be 2 characters")
			}

			b[i] = val[0]
		}
		return b, nil
	}

	return b, fmt.Errorf("expected 6 octets, got %d", len(parts))
}

// buildMagicPacket creates a WoL magic packet.
// Structure: 6 bytes 0xFF followed by target MAC address repeated 16 times (102 bytes total).
func buildMagicPacket(mac [6]byte) []byte {
	packet := make([]byte, MagicPacketSize)
	// First 6 bytes are all 0xFF (synchronization stream)
	for i := range 6 {
		packet[i] = 0xFF
	}
	// Next 16 repetitions of the 6-byte MAC address
	for i := range 16 {
		offset := 6 + (i * 6)
		copy(packet[offset:offset+6], mac[:])
	}
	return packet
}
