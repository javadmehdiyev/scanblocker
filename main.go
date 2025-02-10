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

// Connection takibi için gelişmiş yapı
type ConnectionTracker struct {
	connections    map[string][]time.Time
	portAttempts   map[string]map[uint16]bool // IP -> Port -> Denendi mi?
	lastConnection map[string]time.Time       // Son bağlantı zamanı
	mutex          sync.RWMutex
}

func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections:    make(map[string][]time.Time),
		portAttempts:   make(map[string]map[uint16]bool),
		lastConnection: make(map[string]time.Time),
	}
}

// IP'ye göre bağlantı ve port denemelerini takip et
func (ct *ConnectionTracker) AddConnection(ip string, port uint16) {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	now := time.Now()

	// Bağlantı zamanlarını güncelle
	if _, exists := ct.connections[ip]; !exists {
		ct.connections[ip] = []time.Time{now}
	} else {
		ct.connections[ip] = append(ct.connections[ip], now)
	}

	// Port denemelerini takip et
	if _, exists := ct.portAttempts[ip]; !exists {
		ct.portAttempts[ip] = make(map[uint16]bool)
	}
	ct.portAttempts[ip][port] = true

	// Son bağlantı zamanını güncelle
	ct.lastConnection[ip] = now
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

// Yavaş port tarama tespiti için gelişmiş analiz
func detectPortScan(ct *ConnectionTracker, config Config) {
	for {
		ct.mutex.RLock()
		now := time.Now()

		for ip, attempts := range ct.portAttempts {
			// Whitelist kontrolü
			if contains(config.WhitelistedIPs, ip) {
				continue
			}

			// Son TimeWindow içindeki bağlantıları say
			recent := 0
			for _, conn := range ct.connections[ip] {
				if now.Sub(conn) <= config.TimeWindow {
					recent++
				}
			}

			// Hızlı port tarama kontrolü
			if recent > config.MaxConnPerIP {
				log.Printf("Hızlı port tarama tespit edildi! IP: %s", ip)
				if err := blockIP(ip); err != nil {
					log.Printf("IP engelleme hatası %s: %v", ip, err)
				}
				continue
			}

			// Yavaş port tarama kontrolü (T1/T2 gibi)
			uniquePorts := len(attempts)
			lastConn := ct.lastConnection[ip]
			timeSinceFirst := now.Sub(ct.connections[ip][0])

			// Eğer:
			// 1. Belirli sayıda farklı porta erişim denemesi varsa (örn: 10+)
			// 2. Uzun bir süre içinde yapılmışsa (örn: 5+ dakika)
			// 3. Düzenli aralıklarla devam ediyorsa
			if uniquePorts >= 10 &&
				timeSinceFirst >= 5*time.Minute &&
				now.Sub(lastConn) <= 30*time.Second {
				log.Printf("Yavaş port tarama tespit edildi! IP: %s, Taranan Port Sayısı: %d", ip, uniquePorts)
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

// Paket yakalama fonksiyonu güncellendi
func capturePackets(tracker *ConnectionTracker, config Config) {
	handle, err := pcap.OpenLive("any", 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

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
			destPort := uint16(tcp.DstPort)
			tracker.AddConnection(sourceIP, destPort)
		}
	}
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Println("Bu uygulama root yetkisi gerektirir!")
		os.Exit(1)
	}

	config := Config{
		MaxConnPerIP:   50, // 10 saniye içinde maksimum 50 bağlantı
		TimeWindow:     time.Second * 10,
		BlockDuration:  time.Hour * 24, // Engelleme süresini 24 saate çıkardık
		WhitelistedIPs: []string{"127.0.0.1"},
		MonitoredPorts: []int{80, 443, 22, 21, 25, 53, 3306, 5432, 8080, 8443}, // İzlenen port sayısını artırdık
	}

	tracker := NewConnectionTracker()

	go detectPortScan(tracker, config)
	go capturePackets(tracker, config)

	fmt.Println("Port tarama koruması aktif...")
	fmt.Println("Hızlı ve yavaş port tarama tespiti etkin.")
	select {}
}
