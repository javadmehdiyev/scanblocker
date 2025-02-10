# ScanBlocker

Port tarama ve fuzzing saldırılarına karşı koruma sağlayan Go tabanlı güvenlik duvarı uygulaması.

## Özellikler

- Port tarama tespiti ve engelleme
- SYN flood koruması
- IP bazlı bağlantı takibi
- Whitelist desteği
- iptables entegrasyonu

## Gereksinimler

- Go 1.16 veya üzeri
- libpcap-dev
- iptables
- Root yetkisi

## Kurulum

1. Gerekli paketleri yükleyin:

```bash
# Ubuntu/Debian
sudo apt-get install libpcap-dev

# CentOS/RHEL
sudo yum install libpcap-devel
```

2. Uygulamayı derleyin:

```bash
go build
```

## Kullanım

```bash
sudo ./scanblocker
```

## Yapılandırma

Varsayılan yapılandırma:

- Maksimum bağlantı sayısı: 50 bağlantı/10 saniye
- Engelleme süresi: 30 dakika
- İzlenen portlar: 80, 443, 22, 21
- Whitelist: 127.0.0.1

## Güvenlik Notları

- Uygulama root yetkisi ile çalıştırılmalıdır
- Whitelist'e güvenilir IP'leri eklemeyi unutmayın
- Üretim ortamında kullanmadan önce test edin

## Lisans

MIT 