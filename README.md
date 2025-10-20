# WIFI-QR-Code
Wi-Fi auto-connect QR
# Wi-Fi / Password QR Generator

Simple Tkinter GUI to generate QR codes for:
- Wi‑Fi auto-connect payloads (WIFI:T:<auth>;S:<ssid>;P:<password>;H:<true|false>;;)
- Plain text / password-only QR codes

Main application code: [main.py](main.py)  
## Requirements

- Python 3.7+
- qrcode with Pillow backend and Pillow:
  ```
  pip install qrcode[pil] pillow
  ```

## Usage

Run the GUI:
```bash
python main.py
```

- Select mode: "Wi‑Fi auto-connect" or "Password only".
- When in Wi‑Fi mode, enter SSID, password (or leave empty for open networks), choose security (WPA/WEP/nopass), and mark "Hidden network" if applicable.
- Click "Generate QR" to preview.
- Use "Save PNG..." to save the generated QR or "Copy text to clipboard" to copy the encoded payload.

The Wi‑Fi payload format is produced by [`QRApp._build_wifi_text`](main.py).

## Notes

- The app escapes special characters in SSID/password per common practice (backslash, semicolon, comma, colon, double-quote).
- Saved files are PNG images. Preview uses a scaled thumbnail for display.
- The GUI uses the Tk themed widgets (ttk) and attempts to use the "clam" theme if available.

## Files

- [main.py](main.py) — single-file application with the full GUI and QR generation logic.

## License

Use or modify as you like. No license file included.
