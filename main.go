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
	portAttempts   map[string]map[uint16]bool
	lastConnection map[string]time.Time
	fingerprints   map[string][]PacketFingerprint // Paket parmak izleri
	serviceProbes  map[string]map[uint16]int      // Servis probe sayıları
	udpAttempts    map[string]map[uint16]bool     // UDP taramaları
	mutex          sync.RWMutex
}

// Paket parmak izi yapısı
type PacketFingerprint struct {
	Timestamp time.Time
	SrcPort   uint16
	DstPort   uint16
	Flags     string
	Size      int
	TTL       uint8
}

func NewConnectionTracker() *ConnectionTracker {
	return &ConnectionTracker{
		connections:    make(map[string][]time.Time),
		portAttempts:   make(map[string]map[uint16]bool),
		lastConnection: make(map[string]time.Time),
		fingerprints:   make(map[string][]PacketFingerprint),
		serviceProbes:  make(map[string]map[uint16]int),
		udpAttempts:    make(map[string]map[uint16]bool),
	}
}

// Paket analizi ve parmak izi çıkarma
func (ct *ConnectionTracker) AddPacketFingerprint(ip string, fp PacketFingerprint) {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	if _, exists := ct.fingerprints[ip]; !exists {
		ct.fingerprints[ip] = []PacketFingerprint{}
	}
	ct.fingerprints[ip] = append(ct.fingerprints[ip], fp)
}

// Servis probe tespiti
func (ct *ConnectionTracker) AddServiceProbe(ip string, port uint16) {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	if _, exists := ct.serviceProbes[ip]; !exists {
		ct.serviceProbes[ip] = make(map[uint16]int)
	}
	ct.serviceProbes[ip][port]++
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

// Gelişmiş tarama tespiti
func detectAdvancedScan(ct *ConnectionTracker, config Config) {
	for {
		ct.mutex.RLock()
		now := time.Now()

		for ip, fps := range ct.fingerprints {
			if contains(config.WhitelistedIPs, ip) {
				continue
			}

			// Son 5 dakikadaki parmak izlerini analiz et
			recentFPs := []PacketFingerprint{}
			for _, fp := range fps {
				if now.Sub(fp.Timestamp) <= 5*time.Minute {
					recentFPs = append(recentFPs, fp)
				}
			}

			// Goby benzeri tarayıcı tespiti
			if isGobyLikeScan(recentFPs) {
				log.Printf("Profesyonel tarayıcı tespit edildi (Goby benzeri)! IP: %s", ip)
				if err := blockIP(ip); err != nil {
					log.Printf("IP engelleme hatası %s: %v", ip, err)
				}

				// Ekstra önlem: Tüm portları kapat
				if err := blockAllPorts(ip); err != nil {
					log.Printf("Port engelleme hatası %s: %v", ip, err)
				}
			}

			// Servis probe analizi
			if probes, exists := ct.serviceProbes[ip]; exists {
				totalProbes := 0
				for _, count := range probes {
					totalProbes += count
				}
				if totalProbes > 20 { // Çok sayıda servis probe'u
					log.Printf("Aşırı servis taraması tespit edildi! IP: %s", ip)
					if err := blockIP(ip); err != nil {
						log.Printf("IP engelleme hatası %s: %v", ip, err)
					}
				}
			}
		}
		ct.mutex.RUnlock()
		time.Sleep(1 * time.Second)
	}
}

// Goby benzeri tarayıcı tespiti
func isGobyLikeScan(fps []PacketFingerprint) bool {
	if len(fps) < 10 {
		return false
	}

	// Paket özelliklerini analiz et
	var (
		uniquePorts     = make(map[uint16]bool)
		hasServiceProbe = false
		hasNullScan     = false
		hasSynScan      = false
	)

	for _, fp := range fps {
		uniquePorts[fp.DstPort] = true

		// Farklı tarama tekniklerini kontrol et
		switch fp.Flags {
		case "S": // SYN scan
			hasSynScan = true
		case "": // NULL scan
			hasNullScan = true
		case "SF", "PA": // Service probe
			hasServiceProbe = true
		}
	}

	// Goby benzeri davranış kriterleri:
	// 1. Çoklu port tarama
	// 2. Farklı tarama teknikleri
	// 3. Servis probe'ları
	return len(uniquePorts) > 5 &&
		(hasServiceProbe || hasNullScan) &&
		hasSynScan
}

// Tüm portları engelle
func blockAllPorts(ip string) error {
	cmd := exec.Command("iptables", "-A", "INPUT", "-s", ip, "-p", "tcp", "-j", "DROP")
	if err := cmd.Run(); err != nil {
		return err
	}

	cmd = exec.Command("iptables", "-A", "INPUT", "-s", ip, "-p", "udp", "-j", "DROP")
	return cmd.Run()
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

	// TCP ve UDP paketlerini yakala
	err = handle.SetBPFFilter("tcp or udp")
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
		sourceIP := ip.SrcIP.String()

		// TCP paket analizi
		if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
			tcp, _ := tcpLayer.(*layers.TCP)

			fp := PacketFingerprint{
				Timestamp: time.Now(),
				SrcPort:   uint16(tcp.SrcPort),
				DstPort:   uint16(tcp.DstPort),
				Flags:     getTCPFlags(tcp),
				Size:      len(packet.Data()),
				TTL:       ip.TTL,
			}

			tracker.AddPacketFingerprint(sourceIP, fp)

			// Servis probe tespiti
			if tcp.PSH && tcp.ACK {
				tracker.AddServiceProbe(sourceIP, uint16(tcp.DstPort))
			}
		}

		// UDP paket analizi
		if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
			udp, _ := udpLayer.(*layers.UDP)
			tracker.AddConnection(sourceIP, uint16(udp.DstPort))
		}
	}
}

// TCP bayraklarını string olarak al
func getTCPFlags(tcp *layers.TCP) string {
	flags := ""
	if tcp.SYN {
		flags += "S"
	}
	if tcp.ACK {
		flags += "A"
	}
	if tcp.PSH {
		flags += "P"
	}
	if tcp.FIN {
		flags += "F"
	}
	if tcp.RST {
		flags += "R"
	}
	if tcp.URG {
		flags += "U"
	}
	return flags
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Println("Bu uygulama root yetkisi gerektirir!")
		os.Exit(1)
	}

	config := Config{
		MaxConnPerIP:   50,
		TimeWindow:     time.Second * 10,
		BlockDuration:  time.Hour * 24,
		WhitelistedIPs: []string{"127.0.0.1"},
		MonitoredPorts: []int{80, 443, 22, 21, 25, 53, 3306, 5432, 8080, 8443},
	}

	tracker := NewConnectionTracker()

	go detectPortScan(tracker, config)
	go detectAdvancedScan(tracker, config)
	go capturePackets(tracker, config)

	fmt.Println("Port tarama koruması aktif...")
	fmt.Println("Gelişmiş tarama tespiti (Goby dahil) etkin.")
	select {}
}
