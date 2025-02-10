package main

import (
	"fmt"
	"log"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Configuration yapısı
type Config struct {
	MaxConnPerIP   int
	TimeWindow     time.Duration
	BlockDuration  time.Duration
	WhitelistedIPs []string
	MonitoredPorts []int
}

// Connection takibi için yapı
type ConnectionTracker struct {
	connections map[string][]time.Time
	mutex       sync.RWMutex
}

func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections: make(map[string][]time.Time),
	}
}

// IP'ye göre bağlantı sayısını takip et
func (ct *ConnectionTracker) AddConnection(ip string) {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	now := time.Now()
	if _, exists := ct.connections[ip]; !exists {
		ct.connections[ip] = []time.Time{now}
		return
	}

	ct.connections[ip] = append(ct.connections[ip], now)
}

// IP'yi iptables ile engelle
func blockIP(ip string) error {
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-j", "DROP")
	return cmd.Run()
}

// IP engelini kaldır
func unblockIP(ip string) error {
	cmd := exec.Command("iptables", "-D", "INPUT", "-s", ip, "-j", "DROP")
	return cmd.Run()
}

// Port tarama tespiti
func detectPortScan(ct *ConnectionTracker, config Config) {
	for {
		ct.mutex.RLock()
		for ip, connections := range ct.connections {
			// Whitelist kontrolü
			if contains(config.WhitelistedIPs, ip) {
				continue
			}

			// Son TimeWindow içindeki bağlantıları say
			recent := 0
			now := time.Now()
			for _, conn := range connections {
				if now.Sub(conn) <= config.TimeWindow {
					recent++
				}
			}

			// Eğer bağlantı sayısı limiti aşıyorsa
			if recent > config.MaxConnPerIP {
				log.Printf("Port tarama tespit edildi! IP: %s", ip)
				if err := blockIP(ip); err != nil {
					log.Printf("IP engelleme hatası %s: %v", ip, err)
				}
			}
		}
		ct.mutex.RUnlock()
		time.Sleep(1 * time.Second)
	}
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

// Paket yakalama fonksiyonu
func capturePackets(tracker *ConnectionTracker, config Config) {
	// Ağ arayüzünü aç
	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// TCP paketlerini filtrele
	err = handle.SetBPFFilter("tcp")
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer == nil {
			continue
		}

		ip, _ := ipLayer.(*layers.IPv4)
		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp, _ := tcpLayer.(*layers.TCP)

		// SYN paketi kontrolü (port tarama göstergesi)
		if tcp.SYN && !tcp.ACK {
			sourceIP := ip.SrcIP.String()
			tracker.AddConnection(sourceIP)
		}
	}
}

func main() {
	// Root yetkisi kontrolü
	if os.Geteuid() != 0 {
		fmt.Println("Bu uygulama root yetkisi gerektirir!")
		os.Exit(1)
	}

	config := Config{
		MaxConnPerIP:   50,
		TimeWindow:     time.Second * 10,
		BlockDuration:  time.Minute * 30,
		WhitelistedIPs: []string{"127.0.0.1"},
		MonitoredPorts: []int{80, 443, 22, 21},
	}

	tracker := NewConnectionTracker()

	// Port tarama tespiti başlat
	go detectPortScan(tracker, config)

	// Paket yakalama başlat
	go capturePackets(tracker, config)

	fmt.Println("Port tarama koruması aktif...")
	select {}
}
