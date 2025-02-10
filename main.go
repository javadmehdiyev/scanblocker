package main

import (
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// Configuration yapısı genişletildi
type Config struct {
	MaxConnPerIP   int
	TimeWindow     time.Duration
	BlockDuration  time.Duration
	WhitelistedIPs []string
	MonitoredPorts []int
	HoneypotPorts  []int        // Honeypot portları
	LogFile        string       // Log dosyası
	MLThreshold    float64      // ML anomali eşiği
	DPIPatterns    []DPIPattern // DPI desenleri
	AlertWebhook   string       // Alert webhook URL'i
}

// DPI desenleri için yapı
type DPIPattern struct {
	Name    string
	Pattern string
	Score   float64
}

// Honeypot yapısı
type Honeypot struct {
	Port       int
	Protocol   string
	Hits       map[string]int
	LastAccess map[string]time.Time
	mutex      sync.RWMutex
}

// ML için özellik vektörü
type FeatureVector struct {
	PacketSizeAvg   float64
	PacketSizeStd   float64
	InterArrivalAvg float64
	PortEntropy     float64
	FlagEntropy     float64
	TTLVariance     float64
}

// Connection takibi için gelişmiş yapı güncellendi
type ConnectionTracker struct {
	connections    map[string][]time.Time
	portAttempts   map[string]map[uint16]bool
	lastConnection map[string]time.Time
	fingerprints   map[string][]PacketFingerprint
	serviceProbes  map[string]map[uint16]int
	udpAttempts    map[string]map[uint16]bool
	dpiScores      map[string]float64        // DPI skorları
	mlFeatures     map[string]*FeatureVector // ML özellikleri
	honeypots      map[int]*Honeypot         // Honeypot'lar
	blockedIPs     map[string]time.Time      // Bloklu IP'ler
	alertCount     map[string]int            // Alert sayıları
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

// Yeni ConnectionTracker
func NewConnectionTracker() *ConnectionTracker {
	ct := &ConnectionTracker{
		connections:    make(map[string][]time.Time),
		portAttempts:   make(map[string]map[uint16]bool),
		lastConnection: make(map[string]time.Time),
		fingerprints:   make(map[string][]PacketFingerprint),
		serviceProbes:  make(map[string]map[uint16]int),
		udpAttempts:    make(map[string]map[uint16]bool),
		dpiScores:      make(map[string]float64),
		mlFeatures:     make(map[string]*FeatureVector),
		honeypots:      make(map[int]*Honeypot),
		blockedIPs:     make(map[string]time.Time),
		alertCount:     make(map[string]int),
	}

	// Honeypot'ları başlat
	for _, port := range []int{4444, 8888, 9999} {
		ct.honeypots[port] = &Honeypot{
			Port:       port,
			Protocol:   "tcp",
			Hits:       make(map[string]int),
			LastAccess: make(map[string]time.Time),
		}
	}

	return ct
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

// Deep Packet Inspection
func (ct *ConnectionTracker) performDPI(packet gopacket.Packet, ip string, config Config) {
	applicationLayer := packet.ApplicationLayer()
	if applicationLayer == nil {
		return
	}

	payload := string(applicationLayer.Payload())
	score := 0.0

	for _, pattern := range config.DPIPatterns {
		if strings.Contains(payload, pattern.Pattern) {
			score += pattern.Score
			log.Printf("DPI: Şüpheli pattern tespit edildi - IP: %s, Pattern: %s", ip, pattern.Name)
		}
	}

	ct.mutex.Lock()
	ct.dpiScores[ip] += score
	ct.mutex.Unlock()

	if score > 0 {
		ct.sendAlert(fmt.Sprintf("DPI Alert - IP: %s, Score: %.2f", ip, score))
	}
}

// Entropy hesaplama
func calculateEntropyUint16(counts map[uint16]int) float64 {
	total := 0
	for _, count := range counts {
		total += count
	}

	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func calculateEntropyString(counts map[string]int) float64 {
	total := 0
	for _, count := range counts {
		total += count
	}

	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// ML özellik vektörü güncelleme
func (ct *ConnectionTracker) updateMLFeatures(ip string, packet gopacket.Packet, fp PacketFingerprint) {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	if _, exists := ct.mlFeatures[ip]; !exists {
		ct.mlFeatures[ip] = &FeatureVector{}
	}

	features := ct.mlFeatures[ip]

	// Paket boyutu istatistikleri
	packetSize := float64(len(packet.Data()))
	features.PacketSizeAvg = (features.PacketSizeAvg + packetSize) / 2.0
	features.PacketSizeStd = math.Sqrt(math.Pow(packetSize-features.PacketSizeAvg, 2))

	// Port entropi hesaplama
	portCount := make(map[uint16]int)
	for port := range ct.portAttempts[ip] {
		portCount[port]++
	}
	features.PortEntropy = calculateEntropyUint16(portCount)

	// Flag entropi hesaplama
	flagCount := make(map[string]int)
	for _, f := range ct.fingerprints[ip] {
		flagCount[f.Flags]++
	}
	features.FlagEntropy = calculateEntropyString(flagCount)

	// TTL varyans
	ttls := make([]float64, 0)
	for _, f := range ct.fingerprints[ip] {
		ttls = append(ttls, float64(f.TTL))
	}
	features.TTLVariance = calculateVariance(ttls)
}

// Anomali skoru hesaplama
func (ct *ConnectionTracker) calculateAnomalyScore(ip string) float64 {
	ct.mutex.RLock()
	defer ct.mutex.RUnlock()

	if features, exists := ct.mlFeatures[ip]; exists {
		// Özellik ağırlıkları
		weights := map[string]float64{
			"PacketSizeStd": 0.2,
			"PortEntropy":   0.3,
			"FlagEntropy":   0.3,
			"TTLVariance":   0.2,
		}

		score := features.PacketSizeStd * weights["PacketSizeStd"]
		score += features.PortEntropy * weights["PortEntropy"]
		score += features.FlagEntropy * weights["FlagEntropy"]
		score += features.TTLVariance * weights["TTLVariance"]

		return score
	}
	return 0
}

// Honeypot yönetimi
func (ct *ConnectionTracker) startHoneypots() {
	for port, hp := range ct.honeypots {
		go func(port int, hp *Honeypot) {
			listener, err := net.Listen(hp.Protocol, fmt.Sprintf(":%d", port))
			if err != nil {
				log.Printf("Honeypot başlatma hatası port %d: %v", port, err)
				return
			}
			defer listener.Close()

			for {
				conn, err := listener.Accept()
				if err != nil {
					continue
				}

				remoteIP := strings.Split(conn.RemoteAddr().String(), ":")[0]

				hp.mutex.Lock()
				hp.Hits[remoteIP]++
				hp.LastAccess[remoteIP] = time.Now()
				hitCount := hp.Hits[remoteIP]
				hp.mutex.Unlock()

				// Honeypot'a erişim tespiti
				log.Printf("Honeypot erişimi tespit edildi - IP: %s, Port: %d, Hit Count: %d", remoteIP, port, hitCount)

				if hitCount >= 3 {
					ct.sendAlert(fmt.Sprintf("Honeypot Alert - IP: %s çok sayıda honeypot erişimi!", remoteIP))
					blockIP(remoteIP)
				}

				conn.Close()
			}
		}(port, hp)
	}
}

// Detaylı loglama
func (ct *ConnectionTracker) logActivity(ip string, activity string, details interface{}) {
	logEntry := struct {
		Timestamp time.Time
		IP        string
		Activity  string
		Details   interface{}
	}{
		Timestamp: time.Now(),
		IP:        ip,
		Activity:  activity,
		Details:   details,
	}

	jsonLog, _ := json.MarshalIndent(logEntry, "", "  ")
	log.Printf("%s\n", string(jsonLog))
}

// Alert gönderme
func (ct *ConnectionTracker) sendAlert(message string) {
	// Webhook veya email ile alert gönderme implementasyonu
	log.Printf("ALERT: %s", message)
}

// Varyans hesaplama
func calculateVariance(numbers []float64) float64 {
	if len(numbers) == 0 {
		return 0
	}

	mean := 0.0
	for _, n := range numbers {
		mean += n
	}
	mean /= float64(len(numbers))

	variance := 0.0
	for _, n := range numbers {
		variance += math.Pow(n-mean, 2)
	}
	variance /= float64(len(numbers))

	return variance
}

// Ana detection fonksiyonu güncellendi
func (ct *ConnectionTracker) detectThreats(config Config) {
	for {
		ct.mutex.RLock()

		for ip := range ct.fingerprints {
			if contains(config.WhitelistedIPs, ip) {
				continue
			}

			// DPI skoru kontrolü
			if ct.dpiScores[ip] > 10.0 {
				log.Printf("Yüksek DPI skoru tespit edildi! IP: %s, Score: %.2f", ip, ct.dpiScores[ip])
				blockIP(ip)
				continue
			}

			// ML anomali skoru kontrolü
			anomalyScore := ct.calculateAnomalyScore(ip)
			if anomalyScore > config.MLThreshold {
				log.Printf("Anormal davranış tespit edildi! IP: %s, Anomaly Score: %.2f", ip, anomalyScore)
				blockIP(ip)
				continue
			}

			// Honeypot kontrolleri
			for _, hp := range ct.honeypots {
				hp.mutex.RLock()
				if hits, exists := hp.Hits[ip]; exists && hits > 2 {
					log.Printf("Çoklu honeypot erişimi tespit edildi! IP: %s", ip)
					blockIP(ip)
				}
				hp.mutex.RUnlock()
			}
		}

		ct.mutex.RUnlock()
		time.Sleep(1 * time.Second)
	}
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
		HoneypotPorts:  []int{4444, 8888, 9999},
		LogFile:        "/var/log/scanblocker.log",
		MLThreshold:    0.75,
		DPIPatterns: []DPIPattern{
			{Name: "SQLi", Pattern: "UNION SELECT", Score: 5.0},
			{Name: "XSS", Pattern: "<script>", Score: 4.0},
			{Name: "ShellShock", Pattern: "() {", Score: 5.0},
			{Name: "Goby", Pattern: "Goby Scanner", Score: 10.0},
		},
		AlertWebhook: "http://your-webhook-url/alert",
	}

	// Log dosyasını ayarla
	logFile, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
	}

	tracker := NewConnectionTracker()

	// Honeypot'ları başlat
	tracker.startHoneypots()

	// Tespit mekanizmalarını başlat
	go tracker.detectThreats(config)
	go detectPortScan(tracker, config)
	go detectAdvancedScan(tracker, config)
	go capturePackets(tracker, config)

	fmt.Println("ScanBlocker Pro Aktif")
	fmt.Println("✓ Port Tarama Koruması")
	fmt.Println("✓ Deep Packet Inspection")
	fmt.Println("✓ Makine Öğrenmesi Tabanlı Anomali Tespiti")
	fmt.Println("✓ Honeypot Sistemi")
	fmt.Println("✓ Detaylı Loglama ve Alert Sistemi")
	select {}
}
