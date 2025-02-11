# ScanBlocker Enterprise Edition

Gelişmiş port tarama, fuzzing ve siber saldırı tespiti yapan, makine öğrenmesi destekli güvenlik duvarı uygulaması.

## Özellikler

### 1. Akıllı Tespit Mekanizmaları
- Port tarama tespiti (hızlı ve yavaş)
- SYN flood koruması
- Fuzzing tespiti
- Honeypot sistemi
- Deep Packet Inspection (DPI)
- Makine öğrenmesi tabanlı anomali tespiti

### 2. Self-Learning Özellikleri
- Normal trafik pattern'lerini öğrenme
- Saat bazında trafik analizi
- Güvenilir host tespiti
- Yanlış pozitif oranını minimize etme

### 3. Rate Limiting
- Servis bazlı rate limitleri:
  - HTTP: 1000 istek/saniye
  - SSH: 10 bağlantı/saniye
  - DB: 100 bağlantı/saniye
  - Diğer: 50 istek/saniye
- Burst toleransı (2x)
- Dinamik rate ayarlama

### 4. Güvenlik Özellikleri
- IP bazlı bağlantı takibi
- Whitelist desteği
- Otomatik IP engelleme
- iptables entegrasyonu
- Subnet bazlı güvenlik

## Gereksinimler

- Go 1.16 veya üzeri
- libpcap-dev
- iptables
- Root yetkisi

## Kurulum

1. Gerekli paketleri yükleyin:

```bash
# Ubuntu/Debian
sudo apt-get update
sudo apt-get install -y libpcap-dev iptables

# CentOS/RHEL
sudo yum install -y libpcap-devel iptables

# macOS
brew install libpcap
```

2. Uygulamayı indirin ve derleyin:
```bash
git clone https://github.com/yourusername/scanblocker.git
cd scanblocker
go build
```

## Kullanım

1. Uygulamayı başlatın:
```bash
sudo ./scanblocker
```

2. Logları izleyin:
```bash
tail -f /var/log/scanblocker.log
```

3. Bloklanmış IP'leri görüntüleyin:
```bash
sudo iptables -L INPUT -n | grep DROP
```

4. IP engelini kaldırın:
```bash
sudo iptables -D INPUT -s IP_ADRESI -j DROP
```

## Yapılandırma

`main.go` dosyasındaki Config yapısını düzenleyerek aşağıdaki ayarları özelleştirebilirsiniz:

### Bağlantı Limitleri
```go
MaxConnPerIP: 100,              // IP başına maksimum bağlantı
TimeWindow:   time.Second * 30, // Zaman penceresi
```

### Rate Limitleri
```go
RateLimits: RateLimitConfig{
    HTTPRate:    1000, // HTTP için
    SSHRate:     10,   // SSH için
    DBRate:      100,  // Veritabanı için
    DefaultRate: 50,   // Diğer portlar için
    BurstFactor: 2.0,  // Burst toleransı
},
```

### Güvenilir Network'ler
```go
TrustedSubnets: []string{
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
},
```

### Servis Portları
```go
ServicePorts: []int{80, 443, 22, 3306, 5432},
```

### Honeypot Portları
```go
HoneypotPorts: []int{4444, 8888, 9999},
```

## Özellik Detayları

### 1. Deep Packet Inspection
- Paket içeriği analizi
- Şüpheli pattern tespiti
- SQL injection, XSS, ShellShock tespiti
- Özel imza desteği

### 2. Makine Öğrenmesi
- Paket boyutu analizi
- Port entropi hesaplama
- Flag entropi analizi
- TTL varyans analizi
- Anomali skoru hesaplama

### 3. Honeypot Sistemi
- Çoklu honeypot desteği
- Otomatik saldırgan tespiti
- Hit sayısı takibi
- Gerçek zamanlı alert sistemi

### 4. Rate Limiting
- Port bazlı rate limiting
- Servis bazlı limitler
- Burst toleransı
- Dinamik limit ayarlama

## Güvenlik Tavsiyeleri

1. Whitelist Yapılandırması
   - Güvenilir IP'leri whitelist'e ekleyin
   - İç network subnet'lerini tanımlayın
   - Kritik servisleri belirtin

2. Rate Limit Ayarları
   - Servis ihtiyaçlarına göre ayarlayın
   - Burst faktörünü trafiğe göre düzenleyin
   - Peak saatleri göz önünde bulundurun

3. Honeypot Yapılandırması
   - Gerçekçi portlar seçin
   - Alert eşiklerini belirleyin
   - Yanlış pozitifleri izleyin

4. Logging ve Monitoring
   - Log rotasyonu yapılandırın
   - Alert'leri takip edin
   - Periyodik rapor alın

## Troubleshooting

1. Yanlış Pozitifler
   - Whitelist'i kontrol edin
   - Rate limitleri ayarlayın
   - Servis portlarını doğrulayın

2. Performans Sorunları
   - Rate limitleri artırın
   - Burst faktörünü yükseltin
   - Log seviyesini ayarlayın

3. Bağlantı Sorunları
   - iptables kurallarını kontrol edin
   - Whitelist'i doğrulayın
   - Servis portlarını onaylayın

## Lisans

MIT

## Katkıda Bulunma

1. Fork edin
2. Feature branch oluşturun
3. Değişikliklerinizi commit edin
4. Branch'inizi push edin
5. Pull request açın 