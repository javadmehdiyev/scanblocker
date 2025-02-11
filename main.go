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
	HoneypotPorts  []int
	LogFile        string
	MLThreshold    float64
	DPIPatterns    []DPIPattern
	AlertWebhook   string
	LearningMode   bool // Öğrenme modu
	RateLimits     RateLimitConfig
	TrustedSubnets []string // Güvenilir subnet'ler
	ServicePorts   []int    // Legitimate servis portları
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

// Connection takibi için gelişmiş yapı
type ConnectionTracker struct {
	connections     map[string][]time.Time
	portAttempts    map[string]map[uint16]bool
	lastConnection  map[string]time.Time
	fingerprints    map[string][]PacketFingerprint
	serviceProbes   map[string]map[uint16]int
	udpAttempts     map[string]map[uint16]bool
	dpiScores       map[string]float64        // DPI skorları
	mlFeatures      map[string]*FeatureVector // ML özellikleri
	honeypots       map[int]*Honeypot         // Honeypot'lar
	blockedIPs      map[string]time.Time      // Bloklu IP'ler
	alertCount      map[string]int            // Alert sayıları
	mutex           sync.RWMutex
	trafficPatterns map[string][]TrafficPattern // IP bazlı trafik pattern'leri
	rateLimiters    map[string]*RateLimiter     // IP ve port bazlı rate limit
	learningData    map[string]*LearningData    // Öğrenme verisi
	trustedHosts    map[string]TrustScore       // Güvenilir host'lar
	config          Config
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

// Rate limit yapılandırması
type RateLimitConfig struct {
	HTTPRate    int           // HTTP istekleri için rate limit
	SSHRate     int           // SSH bağlantıları için rate limit
	DBRate      int           // Veritabanı bağlantıları için rate limit
	DefaultRate int           // Diğer portlar için varsayılan rate
	BurstFactor float64       // Burst toleransı
	WindowSize  time.Duration // Rate limit penceresi
}

// Legitimate trafik pattern'leri
type TrafficPattern struct {
	Port              int
	Protocol          string
	AverageRate       float64
	PeakRate          float64
	StandardDeviation float64
	TimeOfDay         map[int]float64 // Saat bazında normal trafik oranları
}

// Rate limiter yapısı
type RateLimiter struct {
	limit      int
	burst      int
	tokens     float64
	lastUpdate time.Time
	mutex      sync.Mutex
}

// Öğrenme verisi yapısı
type LearningData struct {
	Connections   []time.Time
	PortAccesses  map[int][]time.Time
	ResponseTimes []float64
	FailureRates  map[int]float64
	LastUpdate    time.Time
}

// Güven skoru yapısı
type TrustScore struct {
	Score        float64
	LastActivity time.Time
	FailCount    int
	SuccessCount int
}

// Yeni ConnectionTracker
func NewConnectionTracker() *ConnectionTracker {
	ct := &ConnectionTracker{
		connections:     make(map[string][]time.Time),
		portAttempts:    make(map[string]map[uint16]bool),
		lastConnection:  make(map[string]time.Time),
		fingerprints:    make(map[string][]PacketFingerprint),
		serviceProbes:   make(map[string]map[uint16]int),
		udpAttempts:     make(map[string]map[uint16]bool),
		dpiScores:       make(map[string]float64),
		mlFeatures:      make(map[string]*FeatureVector),
		honeypots:       make(map[int]*Honeypot),
		blockedIPs:      make(map[string]time.Time),
		alertCount:      make(map[string]int),
		trafficPatterns: make(map[string][]TrafficPattern),
		rateLimiters:    make(map[string]*RateLimiter),
		learningData:    make(map[string]*LearningData),
		trustedHosts:    make(map[string]TrustScore),
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
			if ct.isTrustedIP(ip) {
				continue
			}

			score := ct.calculateThreatScore(ip)

			if score > config.MLThreshold {
				// Yanlış pozitif kontrolü
				if !ct.isLikelyFalsePositive(ip) {
					log.Printf("Tehdit tespit edildi! IP: %s, Score: %.2f", ip, score)
					ct.handleThreat(ip, score)
				}
			}
		}

		ct.mutex.RUnlock()
		time.Sleep(1 * time.Second)
	}
}

// Tehdit skoru hesaplama
func (ct *ConnectionTracker) calculateThreatScore(ip string) float64 {
	var score float64

	// DPI skoru
	score += ct.dpiScores[ip] * 0.3

	// Anomali skoru
	score += ct.calculateAnomalyScore(ip) * 0.3

	// Pattern uyumsuzluk skoru
	score += ct.calculatePatternMismatchScore(ip) * 0.2

	// Honeypot hit skoru
	score += ct.calculateHoneypotScore(ip) * 0.2

	return score
}

// Yanlış pozitif kontrolü
func (ct *ConnectionTracker) isLikelyFalsePositive(ip string) bool {
	// Legitimate servis kontrolü
	if ct.isLegitimateService(ip) {
		return true
	}

	// Geçmiş davranış analizi
	if ct.hasGoodHistory(ip) {
		return true
	}

	// Subnet kontrolü
	if ct.isInTrustedSubnet(ip) {
		return true
	}

	return false
}

// IP'nin güvenilir olup olmadığını kontrol et
func (ct *ConnectionTracker) isTrustedIP(ip string) bool {
	// Whitelist kontrolü
	if contains(ct.config.WhitelistedIPs, ip) {
		return true
	}

	// Güvenilir host kontrolü
	if score, exists := ct.trustedHosts[ip]; exists && score.Score > 0.8 {
		return true
	}

	return false
}

// Tehdidi işle
func (ct *ConnectionTracker) handleThreat(ip string, score float64) {
	ct.mutex.Lock()
	defer ct.mutex.Unlock()

	// IP'yi blokla
	if err := blockIP(ip); err != nil {
		log.Printf("IP engelleme hatası %s: %v", ip, err)
		return
	}

	// Aktiviteyi logla
	ct.logActivity(ip, "threat_detected", map[string]interface{}{
		"score": score,
		"time":  time.Now(),
	})

	// Alert gönder
	ct.sendAlert(fmt.Sprintf("Tehdit engellendi - IP: %s, Score: %.2f", ip, score))
}

// Pattern uyumsuzluk skoru hesapla
func (ct *ConnectionTracker) calculatePatternMismatchScore(ip string) float64 {
	patterns, exists := ct.trafficPatterns[ip]
	if !exists {
		return 0
	}

	var totalMismatch float64
	for _, pattern := range patterns {
		currentRate := ct.calculateCurrentRate(ip, pattern.Port)
		expectedRate := pattern.TimeOfDay[time.Now().Hour()]

		// Sapma hesapla
		mismatch := math.Abs(currentRate-expectedRate) / pattern.StandardDeviation
		totalMismatch += mismatch
	}

	return math.Min(totalMismatch/float64(len(patterns)), 1.0)
}

// Honeypot hit skoru hesapla
func (ct *ConnectionTracker) calculateHoneypotScore(ip string) float64 {
	var totalHits int
	for _, hp := range ct.honeypots {
		hp.mutex.RLock()
		hits := hp.Hits[ip]
		hp.mutex.RUnlock()
		totalHits += hits
	}

	// 3 veya daha fazla hit varsa maksimum skor
	if totalHits >= 3 {
		return 1.0
	}

	return float64(totalHits) / 3.0
}

// IP'nin legitimate servis olup olmadığını kontrol et
func (ct *ConnectionTracker) isLegitimateService(ip string) bool {
	// Servis portlarına yapılan bağlantıları kontrol et
	if attempts, exists := ct.portAttempts[ip]; exists {
		legitimatePortCount := 0
		for port := range attempts {
			if containsPort(ct.config.ServicePorts, int(port)) {
				legitimatePortCount++
			}
		}

		// Sadece legitimate portlara erişim varsa
		return legitimatePortCount == len(attempts)
	}
	return false
}

// IP'nin iyi bir geçmişi olup olmadığını kontrol et
func (ct *ConnectionTracker) hasGoodHistory(ip string) bool {
	if score, exists := ct.trustedHosts[ip]; exists {
		// Başarılı bağlantı oranı yüksekse
		successRate := float64(score.SuccessCount) / float64(score.SuccessCount+score.FailCount)
		return successRate > 0.9 && score.Score > 0.7
	}
	return false
}

// IP'nin güvenilir bir subnet'te olup olmadığını kontrol et
func (ct *ConnectionTracker) isInTrustedSubnet(ip string) bool {
	for _, subnet := range ct.config.TrustedSubnets {
		_, ipNet, err := net.ParseCIDR(subnet)
		if err != nil {
			continue
		}

		ipAddr := net.ParseIP(ip)
		if ipAddr != nil && ipNet.Contains(ipAddr) {
			return true
		}
	}
	return false
}

// Öğrenme modunu başlat
func (ct *ConnectionTracker) startLearningMode() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ct.mutex.Lock()
			// Her IP için trafik pattern'lerini güncelle
			for ip := range ct.learningData {
				ct.updateTrafficPatterns(ip)
			}
			ct.mutex.Unlock()
		}
	}
}

// Mevcut bağlantı hızını hesapla
func (ct *ConnectionTracker) calculateCurrentRate(ip string, port int) float64 {
	now := time.Now()
	window := now.Add(-10 * time.Minute)

	var count int
	if accesses, exists := ct.learningData[ip].PortAccesses[port]; exists {
		for _, access := range accesses {
			if access.After(window) {
				count++
			}
		}
	}

	return float64(count) / 600.0 // 10 dakikalık pencerede saniye başına düşen bağlantı
}

// Port listesinde port var mı kontrol et
func containsPort(ports []int, port int) bool {
	for _, p := range ports {
		if p == port {
			return true
		}
	}
	return false
}

// Trafik pattern'lerini güncelle
func (ct *ConnectionTracker) updateTrafficPatterns(ip string) {
	data := ct.learningData[ip]
	patterns := make([]TrafficPattern, 0)

	for port, accesses := range data.PortAccesses {
		pattern := TrafficPattern{
			Port:      port,
			TimeOfDay: make(map[int]float64),
		}

		// Saat bazında ortalama trafik hesapla
		hourlyAccesses := make(map[int][]time.Time)
		for _, access := range accesses {
			hour := access.Hour()
			hourlyAccesses[hour] = append(hourlyAccesses[hour], access)
		}

		for hour, times := range hourlyAccesses {
			pattern.TimeOfDay[hour] = float64(len(times)) / 24.0 // Saatlik ortalama
		}

		// Standart sapma hesapla
		var sum float64
		for _, rate := range pattern.TimeOfDay {
			sum += rate
		}
		mean := sum / 24.0

		var variance float64
		for _, rate := range pattern.TimeOfDay {
			variance += math.Pow(rate-mean, 2)
		}
		pattern.StandardDeviation = math.Sqrt(variance / 24.0)

		patterns = append(patterns, pattern)
	}

	ct.trafficPatterns[ip] = patterns
}

func main() {
	if os.Geteuid() != 0 {
		fmt.Println("Bu uygulama root yetkisi gerektirir!")
		os.Exit(1)
	}

	config := Config{
		MaxConnPerIP:   100,              // Artırıldı
		TimeWindow:     time.Second * 30, // Artırıldı
		BlockDuration:  time.Hour * 24,
		WhitelistedIPs: []string{"127.0.0.1"},
		MonitoredPorts: []int{80, 443, 22, 21, 25, 53, 3306, 5432, 8080, 8443},
		HoneypotPorts:  []int{4444, 8888, 9999},
		LogFile:        "/var/log/scanblocker.log",
		MLThreshold:    0.85, // Daha toleranslı
		LearningMode:   true, // Öğrenme modu aktif
		RateLimits: RateLimitConfig{
			HTTPRate:    1000, // Saniyede 1000 HTTP isteği
			SSHRate:     10,   // Saniyede 10 SSH bağlantısı
			DBRate:      100,  // Saniyede 100 DB bağlantısı
			DefaultRate: 50,   // Diğer portlar için
			BurstFactor: 2.0,  // 2x burst toleransı
			WindowSize:  time.Second * 10,
		},
		TrustedSubnets: []string{
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
		},
		ServicePorts: []int{80, 443, 22, 3306, 5432}, // Legitimate servis portları
	}

	// Log dosyasını ayarla
	logFile, err := os.OpenFile(config.LogFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err == nil {
		log.SetOutput(logFile)
	}

	tracker := NewConnectionTracker()
	tracker.config = config

	// Honeypot'ları başlat
	tracker.startHoneypots()

	// Öğrenme modunu başlat
	if config.LearningMode {
		go tracker.startLearningMode()
	}

	// Servisleri başlat
	go tracker.detectThreats(config)
	go detectPortScan(tracker, config)
	go detectAdvancedScan(tracker, config)
	go capturePackets(tracker, config)

	fmt.Println("ScanBlocker Enterprise Edition Aktif")
	fmt.Println("✓ Akıllı Port Tarama Koruması")
	fmt.Println("✓ Deep Packet Inspection")
	fmt.Println("✓ Self-Learning Anomali Tespiti")
	fmt.Println("✓ Rate Limiting")
	fmt.Println("✓ Legitimate Trafik Analizi")
	select {}
}
