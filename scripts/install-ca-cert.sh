#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────
# WebPhomet — Install Caido CA certificate on Android device/emulator
# Usage:
#   ./install-ca-cert.sh              # AVD (default)
#   ./install-ca-cert.sh --genymotion # Genymotion
#   ./install-ca-cert.sh --device     # Physical device via USB
# ──────────────────────────────────────────────────────────────
set -euo pipefail

CAIDO_URL="${CAIDO_CA_URL:-http://localhost:8088/ca}"
CERT_DIR=$(mktemp -d)
CERT_FILE="${CERT_DIR}/caido-ca.pem"
MODE="avd"

# Parse args
while [[ $# -gt 0 ]]; do
    case "$1" in
        --genymotion) MODE="genymotion"; shift ;;
        --device)     MODE="device"; shift ;;
        --caido-url)  CAIDO_URL="$2"; shift 2 ;;
        -h|--help)
            echo "Usage: $0 [--genymotion|--device] [--caido-url URL]"
            exit 0 ;;
        *) echo "Unknown arg: $1"; exit 1 ;;
    esac
done

cleanup() { rm -rf "$CERT_DIR"; }
trap cleanup EXIT

echo "╔══════════════════════════════════════════════════════════╗"
echo "║  WebPhomet — CA Certificate Installer                   ║"
echo "╚══════════════════════════════════════════════════════════╝"
echo ""
echo "Mode:      ${MODE}"
echo "Caido URL: ${CAIDO_URL}"
echo ""

# ── Step 1: Check ADB ────────────────────────────────────────
if ! command -v adb &>/dev/null; then
    echo "❌ adb not found. Install Android SDK Platform Tools."
    echo "   brew install android-platform-tools  (macOS)"
    echo "   apt install adb                      (Linux)"
    exit 1
fi

# ── Step 2: Check that a device is connected ─────────────────
DEVICE_COUNT=$(adb devices | grep -cE "device$" || true)
if [[ "$DEVICE_COUNT" -eq 0 ]]; then
    echo "❌ No Android device/emulator detected."
    echo "   Start your emulator or connect a device via USB."
    exit 1
fi
echo "✅ Device detected (${DEVICE_COUNT} device(s))"

# ── Step 3: Download Caido CA cert ─────────────────────────
echo "⬇  Downloading CA certificate from ${CAIDO_URL}..."
if ! curl -sf -o "$CERT_FILE" "$CAIDO_URL"; then
    echo "❌ Failed to download CA cert. Is Caido running?"
    echo "   Ensure Caido is at ${CAIDO_URL}"
    exit 1
fi
echo "✅ Certificate downloaded"

# ── Step 4: Convert to Android system cert format ──────────
if ! command -v openssl &>/dev/null; then
    echo "❌ openssl not found. Install openssl."
    exit 1
fi

HASH=$(openssl x509 -inform PEM -subject_hash_old -in "$CERT_FILE" | head -1)
ANDROID_CERT="${CERT_DIR}/${HASH}.0"
cp "$CERT_FILE" "$ANDROID_CERT"

# Append text form for Android to parse
openssl x509 -inform PEM -text -in "$CERT_FILE" >> "$ANDROID_CERT"
echo "✅ Converted to Android format: ${HASH}.0"

# ── Step 5: Push to device ───────────────────────────────────
echo "📱 Installing certificate on device..."

case "$MODE" in
    avd)
        # AVD with -writable-system
        adb root 2>/dev/null || true
        sleep 1
        adb remount 2>/dev/null || {
            echo "⚠  remount failed. Did you start emulator with -writable-system?"
            echo "   emulator -avd <name> -writable-system"
            exit 1
        }
        adb push "$ANDROID_CERT" "/system/etc/security/cacerts/${HASH}.0"
        adb shell "chmod 644 /system/etc/security/cacerts/${HASH}.0"
        ;;
    genymotion)
        # Genymotion allows direct root + mount
        adb shell "mount -o rw,remount /system" 2>/dev/null || true
        adb push "$ANDROID_CERT" "/system/etc/security/cacerts/${HASH}.0"
        adb shell "chmod 644 /system/etc/security/cacerts/${HASH}.0"
        ;;
    device)
        # Physical device — needs root (e.g., Magisk)
        adb root 2>/dev/null || {
            echo "⚠  Cannot get root access. Physical devices need root (Magisk recommended)."
            echo "   Alternatively, install as user cert (less coverage):"
            echo "   adb push ${CERT_FILE} /sdcard/caido-ca.pem"
            echo "   Then: Settings → Security → Install from storage"
            exit 1
        }
        sleep 1
        adb remount 2>/dev/null || adb shell "mount -o rw,remount /system"
        adb push "$ANDROID_CERT" "/system/etc/security/cacerts/${HASH}.0"
        adb shell "chmod 644 /system/etc/security/cacerts/${HASH}.0"
        ;;
esac

echo "✅ Certificate pushed to system store"

# ── Step 6: Verify ──────────────────────────────────────────
echo "🔄 Rebooting device..."
adb reboot
echo "   Waiting for device to come back online..."
adb wait-for-device
sleep 10  # Extra wait for boot completion

# Verify cert exists
if adb shell "ls /system/etc/security/cacerts/${HASH}.0" &>/dev/null; then
    echo ""
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║  ✅ CA certificate installed successfully!              ║"
    echo "║                                                         ║"
    echo "║  Hash: ${HASH}                                    ║"
    echo "║  Path: /system/etc/security/cacerts/${HASH}.0     ║"
    echo "║                                                         ║"
    echo "║  Configure proxy on device:                             ║"
    echo "║    WiFi settings → Proxy → Manual                      ║"
    echo "║    Host: <your-host-ip>    Port: 8088                   ║"
    echo "╚══════════════════════════════════════════════════════════╝"
else
    echo "❌ Certificate verification failed after reboot."
    exit 1
fi
