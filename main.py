
"""
wifi_qr_gui.py
Tkinter GUI to generate:
 - Wi-Fi auto-connect QR (WIFI:T:<auth>;S:<ssid>;P:<password>;H:<true|false>;;)
 - Password-only QR (just plain text)

Requirements:
    pip install qrcode[pil] pillow

"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import qrcode
from PIL import Image, ImageTk
import io
import os

APP_TITLE = "Wi-Fi / Password QR Generator"

class QRApp:
    def __init__(self, root):
        self.root = root
        root.title(APP_TITLE)
        root.resizable(False, False)

        # Main frame
        frame = ttk.Frame(root, padding=12)
        frame.grid(row=0, column=0, sticky="nsew")

        # Mode: Auto wifi or Password only
        self.mode_var = tk.StringVar(value="wifi")
        mode_frame = ttk.LabelFrame(frame, text="Mode", padding=(8,6))
        mode_frame.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0,8))
        ttk.Radiobutton(mode_frame, text="Wi-Fi auto-connect (SSID + password)", variable=self.mode_var, value="wifi", command=self._on_mode_change).grid(row=0, column=0, sticky="w")
        ttk.Radiobutton(mode_frame, text="Password only (plain text in QR)", variable=self.mode_var, value="pwd", command=self._on_mode_change).grid(row=1, column=0, sticky="w")

        # SSID
        ttk.Label(frame, text="SSID:").grid(row=1, column=0, sticky="e")
        self.ssid_entry = ttk.Entry(frame, width=30)
        self.ssid_entry.grid(row=1, column=1, sticky="w", pady=2)

        # Password
        ttk.Label(frame, text="Password:").grid(row=2, column=0, sticky="e")
        self.pw_entry = ttk.Entry(frame, width=30, show="*")
        self.pw_entry.grid(row=2, column=1, sticky="w", pady=2)

        # Show password checkbox
        self.show_pw_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Show password", variable=self.show_pw_var, command=self._toggle_pw).grid(row=3, column=1, sticky="w")

        # Auth type (WPA/WEP/nopass)
        ttk.Label(frame, text="Security:").grid(row=4, column=0, sticky="e")
        self.auth_var = tk.StringVar(value="WPA")
        auth_combo = ttk.Combobox(frame, textvariable=self.auth_var, values=["WPA","WEP","nopass"], state="readonly", width=27)
        auth_combo.grid(row=4, column=1, sticky="w", pady=2)

        # Hidden checkbox
        self.hidden_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Hidden network", variable=self.hidden_var).grid(row=5, column=1, sticky="w")

        # Buttons
        btn_frame = ttk.Frame(frame)
        btn_frame.grid(row=6, column=0, columnspan=2, pady=(8,0))
        self.gen_btn = ttk.Button(btn_frame, text="Generate QR", command=self.generate_qr)
        self.gen_btn.grid(row=0, column=0, padx=(0,6))
        self.save_btn = ttk.Button(btn_frame, text="Save PNG...", command=self.save_png, state="disabled")
        self.save_btn.grid(row=0, column=1, padx=(6,6))
        self.copy_btn = ttk.Button(btn_frame, text="Copy text to clipboard", command=self.copy_text, state="disabled")
        self.copy_btn.grid(row=0, column=2, padx=(6,0))

        # QR preview
        preview_frame = ttk.LabelFrame(frame, text="Preview", padding=(8,8))
        preview_frame.grid(row=0, column=2, rowspan=7, padx=(12,0))
        self.preview_label = ttk.Label(preview_frame)
        self.preview_label.grid(row=0, column=0)

        self.last_image = None    # PIL Image
        self.last_data_text = ""  # encoded text

        self._on_mode_change()

    def _on_mode_change(self):
        """Enable/disable SSID & security fields based on mode."""
        mode = self.mode_var.get()
        if mode == "pwd":
            # password-only
            self.ssid_entry.configure(state="disabled")
            self.auth_var.set("WPA")
            self.hidden_var.set(False)
           
            self.ssid_entry.state = 'disabled'
            try:
                self.ssid_entry.configure(state="disabled")
            except Exception:
                pass
        else:
            # wifi mode:
            try:
                self.ssid_entry.configure(state="normal")
            except Exception:
                pass

    def _toggle_pw(self):
        if self.show_pw_var.get():
            self.pw_entry.configure(show="")
        else:
            self.pw_entry.configure(show="*")

    def _build_wifi_text(self, ssid: str, password: str, auth: str, hidden: bool) -> str:
        """
        Build the standard Wi-Fi QR payload:
        WIFI:T:<WPA|WEP|nopass>;S:<ssid>;P:<password>;H:<true|false>;;
        Values must escape special chars: backslash, semicolon, comma, colon, double-quote
        We'll escape \,;,,:," by prefixing with backslash per common practice.
        """
        def escape(s: str) -> str:
            return s.replace('\\', '\\\\').replace(';', r'\;').replace(',', r'\,').replace(':', r'\:').replace('"', r'\"')
        # If auth is "nopass" password should be empty
        if auth == "nopass":
            password = ""
        hidden_flag = "true" if hidden else "false"
        return f"WIFI:T:{auth};S:{escape(ssid)};P:{escape(password)};H:{hidden_flag};;"

    def generate_qr(self):
        mode = self.mode_var.get()
        password = self.pw_entry.get().strip()
        ssid = self.ssid_entry.get().strip()

        if mode == "wifi":
            if not ssid:
                messagebox.showerror("Missing SSID", "SSID is required for Wi-Fi auto-connect QR.")
                return
            # no password
            if self.auth_var.get() != "nopass" and not password:
                resp = messagebox.askyesno("Empty password", "Password is empty. Continue anyway?")
                if not resp:
                    return
            payload = self._build_wifi_text(ssid, password, self.auth_var.get(), self.hidden_var.get())
        else:
            # password-only
            if not password:
                messagebox.showerror("Missing password", "Please enter a password (or text) to encode.")
                return
            payload = password

        # Create QR code
        qr = qrcode.QRCode(
            version=None,  
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(payload)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").convert("RGB")

        self.last_image = img
        self.last_data_text = payload

        # preview
        preview_size = 260
        img_preview = img.copy()
        img_preview.thumbnail((preview_size, preview_size), Image.LANCZOS)
        self.tk_preview = ImageTk.PhotoImage(img_preview)
        self.preview_label.configure(image=self.tk_preview)

        # Save / Copy buttons
        self.save_btn.configure(state="normal")
        self.copy_btn.configure(state="normal")

    def save_png(self):
        if self.last_image is None:
            messagebox.showinfo("No image", "Generate a QR code first.")
            return
        default_name = "wifi_qr.png" if self.mode_var.get() == "wifi" else "password_qr.png"
        path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG image","*.png")], initialfile=default_name)
        if not path:
            return
        try:
            self.last_image.save(path)
            messagebox.showinfo("Saved", f"QR code saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Save error", f"Could not save file:\n{e}")

    def copy_text(self):
        if not self.last_data_text:
            messagebox.showinfo("Nothing to copy", "Generate a QR code first.")
            return
        try:
            self.root.clipboard_clear()
            self.root.clipboard_append(self.last_data_text)
            messagebox.showinfo("Copied", "Encoded text copied to clipboard.")
        except Exception as e:
            messagebox.showerror("Clipboard error", f"Could not copy to clipboard:\n{e}")


def main():
    root = tk.Tk()
    style = ttk.Style()
    try:
        style.theme_use("clam")
    except Exception:
        pass
    app = QRApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
