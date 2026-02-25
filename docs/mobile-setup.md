# WebPhomet — Mobile Application Testing Guide

## Overview

WebPhomet supports mobile app pentesting by leveraging **Caido** as a man-in-the-middle (MITM) proxy to intercept traffic from Android emulators. The Z.ai agent automatically analyzes captured mobile API traffic, discovers endpoints, and applies the full OWASP testing pipeline.

---

## Architecture

```
┌─────────────┐       ┌───────────────┐       ┌──────────────┐
│  Android     │──────▶│  Caido Proxy  │──────▶│  Target API  │
│  Emulator    │ HTTPS │  (port 8088)  │       │  Server      │
│  (AVD/Geny)  │       │  + CA cert    │       │              │
└─────────────┘       └───────┬───────┘       └──────────────┘
                              │
                    ┌─────────▼─────────┐
                    │  WebPhomet Agent   │
                    │  (Z.ai analysis)   │
                    │  ─ endpoint disc.  │
                    │  ─ vuln scanning   │
                    │  ─ OWASP testing   │
                    └───────────────────┘
```

---

## Prerequisites

| Component | Version | Purpose |
|-----------|---------|---------|
| Android SDK / Android Studio | Latest | AVD management |
| **OR** Genymotion | 3.x+ | Faster alternative emulator |
| Caido | 0.40+ | MITM proxy |
| adb | Latest (from Android SDK) | Device interaction |
| WebPhomet | Running (Docker Compose) | Automated analysis |

---

## Option A: Android Studio AVD

### 1. Create an emulator

```bash
# List available system images
sdkmanager --list | grep "system-images"

# Install a system image (API 33, Google APIs, x86_64)
sdkmanager "system-images;android-33;google_apis;x86_64"

# Create AVD
avdmanager create avd \
  -n "webphomet_test" \
  -k "system-images;android-33;google_apis;x86_64" \
  -d "pixel_6"
```

### 2. Start emulator with writable system

```bash
# IMPORTANT: -writable-system is needed to install CA cert as system cert
emulator -avd webphomet_test \
  -writable-system \
  -http-proxy http://$(hostname -I | awk '{print $1}'):8088 \
  -no-snapshot-load
```

> **Note:** Replace the IP with your host machine IP. On macOS, use `ipconfig getifaddr en0`.

### 3. Install CA certificate

```bash
# Use the provided script
./scripts/install-ca-cert.sh
```

See [CA Certificate Installation](#ca-certificate-installation) below.

---

## Option B: Genymotion (Recommended for Speed)

### 1. Install Genymotion

Download from [genymotion.com](https://www.genymotion.com/download/).

### 2. Create a device

- Select **Custom Phone - API 33** (or any API ≥ 28)
- Enable **Google APIs** if needed
- Set **Network mode** to **Bridge** or **NAT**

### 3. Configure proxy

In Genymotion:

1. Settings → Network → HTTP Proxy
2. Set proxy to: `<host_ip>:8088`
3. Or configure via ADB:

```bash
adb shell settings put global http_proxy <host_ip>:8088
```

### 4. Install CA certificate

```bash
./scripts/install-ca-cert.sh --genymotion
```

---

## CA Certificate Installation

### Automatic (recommended)

The `install-ca-cert.sh` script handles everything:

```bash
cd /path/to/webphomet

# For AVD
./scripts/install-ca-cert.sh

# For Genymotion
./scripts/install-ca-cert.sh --genymotion

# For physical device via USB
./scripts/install-ca-cert.sh --device
```

The script will:
1. Export Caido's CA certificate from `http://localhost:8088/ca`
2. Convert to the Android system cert format (hashed .0 filename)
3. Push to `/system/etc/security/cacerts/` on the device
4. Reboot and verify installation

### Manual installation

```bash
# 1. Download Caido CA cert
curl -o caido-ca.pem http://localhost:8088/ca

# 2. Get the hash for Android system cert store
HASH=$(openssl x509 -inform PEM -subject_hash_old -in caido-ca.pem | head -1)

# 3. Rename to Android format
cp caido-ca.pem "${HASH}.0"

# 4. Push to device
adb root
adb remount
adb push "${HASH}.0" /system/etc/security/cacerts/
adb shell chmod 644 "/system/etc/security/cacerts/${HASH}.0"
adb reboot
```

---

## Configuring Caido for Mobile Traffic

### 1. Ensure Caido listens on all interfaces

In Caido settings (http://localhost:8088):
- Listeners → Edit default listener
- Set bind address to `0.0.0.0:8088`

### 2. Scope configuration

Add mobile API domains to your Caido scope:
```
api.target-app.com
*.target-app.com
```

### 3. SSL/TLS settings

Ensure "Intercept TLS" is enabled for all target domains.

---

## Running Mobile Pentest with WebPhomet

### 1. Start a pentest session

```bash
curl -X POST http://localhost:8000/api/sessions/ \
  -H 'Content-Type: application/json' \
  -d '{"target": "api.target-app.com", "scope_regex": ".*\\.target-app\\.com"}'
```

### 2. Interact with the mobile app

Open the target app in the emulator and navigate through all features:
- Login / Registration
- Profile management
- File uploads
- Payment flows
- Push notifications
- Deep links

### 3. Analyze captured traffic

Use the `analyze_mobile_traffic` tool:

```bash
curl -X POST http://localhost:8000/api/tools/analyze-mobile-traffic \
  -H 'Content-Type: application/json' \
  -d '{"session_id": "<session-uuid>", "host_filter": "api.target-app.com"}'
```

This will:
1. Pull all intercepted requests from Caido
2. Group by endpoint (method + path)
3. Identify auth mechanisms (Bearer tokens, cookies, API keys)
4. Detect sensitive data in requests/responses
5. Map the full API surface
6. Feed discovered endpoints into the OWASP testing pipeline

### 4. Review results

```bash
# Get findings
curl http://localhost:8000/api/sessions/<session-uuid>/findings
```

---

## Troubleshooting

### Emulator can't reach Caido proxy

```bash
# Check host IP
ifconfig | grep "inet " | grep -v 127.0.0.1

# Verify Caido is listening on 0.0.0.0
curl http://<host_ip>:8088/health

# Test from emulator
adb shell curl http://<host_ip>:8088/health
```

### SSL errors in the app

- Verify CA cert is installed as **system** cert (not user cert)
- Some apps use certificate pinning — use Frida to bypass:

```bash
# Install Frida server on emulator
adb push frida-server /data/local/tmp/
adb shell chmod +x /data/local/tmp/frida-server
adb shell /data/local/tmp/frida-server &

# Bypass cert pinning
frida -U -l ssl-pinning-bypass.js -f com.target.app
```

### App detects emulator

Some apps detect the emulator. Mitigations:
- Use a **physical device** with USB debugging
- Use Magisk + props editing to hide root/emulator indicators
- Genymotion has better detection evasion than stock AVD

---

## Certificate Pinning Bypass (Advanced)

For apps with certificate pinning, use one of these approaches:

### Frida + objection

```bash
pip install frida-tools objection

# Start objection
objection -g com.target.app explore

# Disable SSL pinning
android sslpinning disable
```

### Patching the APK

```bash
# Decompile
apktool d target-app.apk -o target-decompiled

# Edit network_security_config.xml to trust user certs
# Recompile and sign
apktool b target-decompiled -o target-patched.apk
jarsigner -keystore debug.keystore target-patched.apk debug
```

---

## Physical Device Setup

For testing on a real Android device:

1. Enable **Developer Options** → **USB Debugging**
2. Connect via USB
3. Run: `./scripts/install-ca-cert.sh --device`
4. Set WiFi proxy to `<host_ip>:8088`

> **Important:** Physical devices with API ≥ 24 (Android 7+) require rooting to install system CA certs. Use Magisk for root access.
