"""
main.py
Tkinter GUI to generate:
 - Wi-Fi auto-connect QR
 - Password-only QR
 - Link / URL QR

Requirements:
    pip install qrcode[pil] pillow
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import qrcode
from PIL import Image, ImageTk

APP_TITLE = "Wi-Fi / Password / Link QR Generator"


class QRApp:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.resizable(False, False)

        frame = ttk.Frame(root, padding=12)
        frame.grid(row=0, column=0, sticky="nsew")

        # Mode selector
        self.mode_var = tk.StringVar(value="wifi")
        mode_frame = ttk.LabelFrame(frame, text="Mode", padding=(8, 6))
        mode_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        ttk.Radiobutton(mode_frame, text="Wi-Fi auto-connect", variable=self.mode_var,
                        value="wifi", command=self._on_mode_change).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(mode_frame, text="Password only", variable=self.mode_var,
                        value="pwd", command=self._on_mode_change).grid(row=1, column=0, sticky="w")
        ttk.Radiobutton(mode_frame, text="Link / URL", variable=self.mode_var,
                        value="link", command=self._on_mode_change).grid(row=2, column=0, sticky="w")

        # SSID
        self.label_ssid = ttk.Label(frame, text="SSID:")
        self.label_ssid.grid(row=1, column=0, sticky="e")
        self.ssid_entry = ttk.Entry(frame, width=30)
        self.ssid_entry.grid(row=1, column=1, sticky="w", pady=2)

        # Password
        self.label_pw = ttk.Label(frame, text="Password:")
        self.label_pw.grid(row=2, column=0, sticky="e")
        self.pw_entry = ttk.Entry(frame, width=30, show="*")
        self.pw_entry.grid(row=2, column=1, sticky="w", pady=2)

        # Show password checkbox
        self.show_pw_var = tk.BooleanVar(value=False)
        self.show_pw_check = ttk.Checkbutton(frame, text="Show password",
                                             variable=self.show_pw_var, command=self._toggle_pw)
        self.show_pw_check.grid(row=3, column=1, sticky="w")

        # Auth type (WPA/WEP/nopass)
        self.label_auth = ttk.Label(frame, text="Security:")
        self.label_auth.grid(row=4, column=0, sticky="e")
        self.auth_var = tk.StringVar(value="WPA")
        self.auth_combo = ttk.Combobox(frame, textvariable=self.auth_var,
                                       values=["WPA", "WEP", "nopass"], state="readonly", width=27)
        self.auth_combo.grid(row=4, column=1, sticky="w", pady=2)

        # Hidden network checkbox
        self.hidden_var = tk.BooleanVar(value=False)
        self.hidden_check = ttk.Checkbutton(frame, text="Hidden network", variable=self.hidden_var)
        self.hidden_check.grid(row=5, column=1, sticky="w")

        # URL input
        self.label_url = ttk.Label(frame, text="URL:")
        self.label_url.grid(row=6, column=0, sticky="e")
        self.url_entry = ttk.Entry(frame, width=30)
        self.url_entry.grid(row=6, column=1, sticky="w", pady=2)

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=7, column=0, columnspan=2, pady=(8, 0))
        self.gen_btn = ttk.Button(btn_frame, text="Generate QR", command=self.generate_qr)
        self.gen_btn.grid(row=0, column=0, padx=(0, 6))
        self.save_btn = ttk.Button(btn_frame, text="Save PNG...", command=self.save_png, state="disabled")
        self.save_btn.grid(row=0, column=1, padx=(6, 6))
        self.copy_btn = ttk.Button(btn_frame, text="Copy text", command=self.copy_text, state="disabled")
        self.copy_btn.grid(row=0, column=2, padx=(6, 0))

        # QR Preview
        preview_frame = ttk.LabelFrame(frame, text="Preview", padding=(8, 8))
        preview_frame.grid(row=0, column=2, rowspan=8, padx=(12, 0))
        self.preview_label = ttk.Label(preview_frame)
        self.preview_label.grid(row=0, column=0)

        # State
        self.last_image = None
        self.last_data_text = ""

        self._on_mode_change()

    def _on_mode_change(self):
        """Show/hide fields based on mode."""
        mode = self.mode_var.get()

        # Always show URL by default
        self.label_url.grid_remove()
        self.url_entry.grid_remove()

        # Show all Wi-Fi/password widgets first
        wifi_widgets = [
            self.label_ssid, self.ssid_entry,
            self.label_pw, self.pw_entry,
            self.show_pw_check,
            self.label_auth, self.auth_combo,
            self.hidden_check
        ]
        for w in wifi_widgets:
            w.grid()  # ensure visible

        if mode == "wifi":
            self.label_url.grid_remove()
            self.url_entry.grid_remove()

        elif mode == "pwd":
            # Hide SSID + auth + hidden, show password only
            for w in [self.label_ssid, self.ssid_entry, self.label_auth, self.auth_combo, self.hidden_check]:
                w.grid_remove()
            self.label_url.grid_remove()
            self.url_entry.grid_remove()

        elif mode == "link":
            # Hide Wi-Fi/password related fields
            for w in wifi_widgets:
                w.grid_remove()
            # Show URL only
            self.label_url.grid()
            self.url_entry.grid()

    def _toggle_pw(self):
        self.pw_entry.configure(show="" if self.show_pw_var.get() else "*")

    def _build_wifi_text(self, ssid: str, password: str, auth: str, hidden: bool) -> str:
        def esc(s: str) -> str:
            return s.replace("\\", "\\\\").replace(";", r"\;").replace(",", r"\,").replace(":", r"\:").replace('"', r'\"')
        if auth == "nopass":
            password = ""
        hidden_flag = "true" if hidden else "false"
        return f"WIFI:T:{auth};S:{esc(ssid)};P:{esc(password)};H:{hidden_flag};;"

    def generate_qr(self):
        mode = self.mode_var.get()
        payload = ""

        if mode == "wifi":
            ssid = self.ssid_entry.get().strip()
            password = self.pw_entry.get().strip()
            if not ssid:
                messagebox.showerror("Missing SSID", "SSID is required for Wi-Fi QR.")
                return
            if self.auth_var.get() != "nopass" and not password:
                if not messagebox.askyesno("No Password", "Password is empty. Continue?"):
                    return
            payload = self._build_wifi_text(ssid, password, self.auth_var.get(), self.hidden_var.get())

        elif mode == "pwd":
            password = self.pw_entry.get().strip()
            if not password:
                messagebox.showerror("Missing Password", "Please enter a password.")
                return
            payload = password

        elif mode == "link":
            url = self.url_entry.get().strip()
            if not url:
                messagebox.showerror("Missing URL", "Please enter a link (e.g. https://example.com).")
                return
            if not (url.startswith("http://") or url.startswith("https://")):
                url = "https://" + url
            payload = url

        # Generate QR
        qr = qrcode.QRCode(
            version=None, error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10, border=4,
        )
        qr.add_data(payload)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

        self.last_image = img
        self.last_data_text = payload

        preview = img.copy()
        preview.thumbnail((260, 260))
        self.tk_preview = ImageTk.PhotoImage(preview)
        self.preview_label.configure(image=self.tk_preview)

        self.save_btn.configure(state="normal")
        self.copy_btn.configure(state="normal")

    def save_png(self):
        if not self.last_image:
            messagebox.showinfo("No QR", "Generate a QR code first.")
            return
        default_name = f"{self.mode_var.get()}_qr.png"
        path = filedialog.asksaveasfilename(defaultextension=".png",
                                            filetypes=[("PNG image", "*.png")],
                                            initialfile=default_name)
        if not path:
            return
        try:
            self.last_image.save(path)
            messagebox.showinfo("Saved", f"QR saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save error", str(e))

    def copy_text(self):
        if not self.last_data_text:
            messagebox.showinfo("Nothing to copy", "Generate a QR first.")
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(self.last_data_text)
        messagebox.showinfo("Copied", "Encoded text copied to clipboard.")


def main():
    root = tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    QRApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
