# SNI-ByPass

A lightweight TCP/TLS DPI-bypass tool that forges an outbound TLS `ClientHello` with a **whitelisted SNI** before your real handshake.

## What this does

When `outbound_tls_spoof` is enabled, the tool:

1. Opens a normal TCP connection to `CONNECT_IP:CONNECT_PORT`.
2. Sends a forged TLS `ClientHello` containing `FAKE_SNI`.
3. Waits for ACK behavior expected by the selected bypass mode (`wrong_seq`).
4. Starts relaying your real TLS stream.

This can help against middleboxes that make early SNI-based decisions.

---

## Configuration (`config.json`)

```json
{
  "LISTEN_HOST": "0.0.0.0",
  "LISTEN_PORT": 40443,
  "CONNECT_IP": "188.114.98.0",
  "CONNECT_PORT": 443,
  "FAKE_SNI": "auth.vercel.com",
  "outbound_tls_spoof": true,
  "spoof_method": "single",
  "randomized_fingerprint": true,
  "fragmentaion": false,
  "fragment_min_size": 24,
  "fragment_max_size": 96
}
```

### Field reference

- `LISTEN_HOST`, `LISTEN_PORT`: local listener.
- `CONNECT_IP`, `CONNECT_PORT`: upstream destination.
- `FAKE_SNI`: whitelisted SNI placed into the forged ClientHello.
- `outbound_tls_spoof`:
  - `true` = forged ClientHello is injected before relay.
  - `false` = plain TCP relay (no spoof stage).
- `spoof_method`:
  - `single` = one forged TCP packet for ClientHello.
  - `fragmented_random` = split ClientHello into randomized fragment sizes.
- `randomized_fingerprint`:
  - randomizes TLS fingerprint details (cipher order, extension order, supported_groups order) while preserving the chosen SNI.
- `fragmentaion` (kept with existing spelling for compatibility):
  - `true` forces `fragmented_random` spoofing.
- `fragment_min_size`, `fragment_max_size`: min/max bytes per random fragment.

---

## Run

```bash
pip install -r requirements.txt
python main.py
```

> Note: This project depends on WinDivert/pydivert behavior for packet interception and injection.

Telegram:
- https://t.me/projectXhttp
- https://t.me/patterniha
