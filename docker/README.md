# Docker Proxy

Run sni-spoof-rs as a shared HTTP proxy. One machine runs the container, all devices on the network connect through it.

**[English](#usage)** | **[Persian](#%D8%B1%D8%A7%D9%87%D9%86%D9%85%D8%A7)** 

## Usage

### 1. Build

```bash
cd sni-spoofing-rust
docker build -f docker/Dockerfile -t sni-spoof-proxy .
```

### 2. Run

```bash
docker run -d --name snispoof \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 1080:1080 \
  -e VLESS_URI='vless://your-uuid@server.com:443?security=tls&sni=server.com&type=ws&host=server.com&path=/path' \
  -e FAKE_SNI='security.vercel.com' \
  sni-spoof-proxy
```

Replace the `VLESS_URI` value with your actual VLESS link. Paste the full `vless://...` URI.

### 3. Connect your devices

On any device connected to the same network (WiFi):

**iPhone/iPad:**
Settings > WiFi > tap your network > Configure Proxy > Manual
- Server: your host machine's IP (e.g. `192.168.1.100`)
- Port: `1080`

**Android:**
Settings > WiFi > long press your network > Modify > Advanced > Proxy > Manual
- Proxy hostname: your host machine's IP
- Proxy port: `1080`

**Mac/Linux/Windows:**
```bash
export http_proxy=http://192.168.1.100:1080
export https_proxy=http://192.168.1.100:1080
```

Or set it in your browser's proxy settings.

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `VLESS_URI` | (required) | Your full `vless://...` link |
| `FAKE_SNI` | `security.vercel.com` | SNI for the fake packet |
| `PROXY_PORT` | `1080` | HTTP proxy port to expose |

### Supported transport types

ws, xhttp, grpc, tcp

### Check if it works

```bash
curl -x http://127.0.0.1:1080 https://icanhazip.com
```

Should return your remote server's IP, not your real IP.

### Logs

```bash
docker logs snispoof
```

### Stop

```bash
docker stop snispoof && docker rm snispoof
```

---

## راهنما

با این داکر می‌توانید یک پروکسی HTTP روی یک دستگاه راه بیندازید و همه دستگاه‌های شبکه (گوشی، لپ‌تاپ، تبلت) از آن استفاده کنند.

### ۱. ساخت

```bash
cd sni-spoofing-rust
docker build -f docker/Dockerfile -t sni-spoof-proxy .
```

### ۲. اجرا

```bash
docker run -d --name snispoof \
  --cap-add=NET_RAW --cap-add=NET_ADMIN \
  -p 1080:1080 \
  -e VLESS_URI='vless://لینک-کامل-شما' \
  -e FAKE_SNI='security.vercel.com' \
  sni-spoof-proxy
```

به جای `VLESS_URI` لینک کامل `vless://...` خود را بگذارید.

### ۳. اتصال دستگاه‌ها

روی هر دستگاهی که به همان شبکه WiFi وصل است:

**آیفون/آیپد:**
Settings > WiFi > روی شبکه بزنید > Configure Proxy > Manual
- Server: آی‌پی دستگاه میزبان (مثلا `192.168.1.100`)
- Port: `1080`

**اندروید:**
تنظیمات > WiFi > روی شبکه نگه دارید > تغییر > پیشرفته > پروکسی > دستی
- نام میزبان پروکسی: آی‌پی دستگاه میزبان
- پورت پروکسی: `1080`

### تست

```bash
curl -x http://127.0.0.1:1080 https://icanhazip.com
```

باید آی‌پی سرور ریموت شما را نشان دهد، نه آی‌پی واقعی شما.
