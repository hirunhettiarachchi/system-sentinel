import hashlib
import re
import socket
import string
import threading
import customtkinter as ctk
import requests
import secrets

# Appearance settings
ctk.set_appearance_mode("Dark")
ctk.set_default_color_theme("blue")


# --- Core Logic Functions ---
def check_password_strength(password):
    score = 0
    if len(password) >= 8:
        score += 1
    if re.search(r"[A-Z]", password):
        score += 1
    if re.search(r"[a-z]", password):
        score += 1
    if re.search(r"\d", password):
        score += 1
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 1

    if score <= 2:
        return "Weak", "#FF4D4D"
    elif score <= 4:
        return "Moderate", "#FFC107"
    else:
        return "Strong", "#2ECC71"


def check_pwned_password(password):
    sha1_password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1_password[:5], sha1_password[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response = requests.get(url, timeout=5)
        if response.status_code != 200:
            return "⚠️ Connection Error", "#FFC107"

        hashes = (line.split(":") for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return f"🚨 Leaked! ({count} times)", "#FF4D4D"

        return "🛡️ Safe! (No leaks found)", "#2ECC71"
    except Exception:
        return "⚠️ Network Error!", "#FFC107"


def generate_password(
    length=12,
    use_uppercase=True,
    use_lowercase=True,
    use_digits=True,
    use_special=True,
):
    characters = ""
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_digits:
        characters += string.digits
    if use_special:
        characters += string.punctuation

    if not characters:
        return "Error: Select at least one option!"

    return "".join(secrets.choice(characters) for _ in range(length))


# --- Main GUI Application ---
class SystemSentinelApp(ctk.CTk):

    def __init__(self):
        super().__init__()

        self.title("System Sentinel")
        self.geometry("480x670")
        self.resizable(False, False)

        self.header = ctk.CTkLabel(
            self,
            text="🛡️ SYSTEM SENTINEL",
            font=ctk.CTkFont(size=22, weight="bold"),
        )
        self.header.pack(pady=(20, 10))

        self.tabview = ctk.CTkTabview(self, width=440, height=560)
        self.tabview.pack(padx=20, pady=(0, 20))

        self.tab_pwd = self.tabview.add("Password Checker")
        self.tab_ports = self.tabview.add("Port Scanner")
        self.tab_generator = self.tabview.add("Password Generator")

        self.create_password_checker_ui()
        self.create_port_scanner_ui()
        self.create_password_generator_ui()

    # --- Password Checker UI ---
    def create_password_checker_ui(self):
        label = ctk.CTkLabel(
            self.tab_pwd, text="Enter Password to Test:", font=("Arial", 13)
        )
        label.pack(pady=(20, 5))

        self.pwd_entry = ctk.CTkEntry(
            self.tab_pwd, show="*", width=300, placeholder_text="Type password..."
        )
        self.pwd_entry.pack(pady=10)

        check_btn = ctk.CTkButton(
            self.tab_pwd, text="Check Security", command=self.on_check_password
        )
        check_btn.pack(pady=10)

        self.pwd_result_label = ctk.CTkLabel(
            self.tab_pwd, text="", font=("Arial", 13, "bold"), justify="center"
        )
        self.pwd_result_label.pack(pady=20)

    def on_check_password(self):
        password = self.pwd_entry.get().strip()
        if not password:
            self.pwd_result_label.configure(
                text="Please enter a password!", text_color="#FF4D4D"
            )
            return

        self.pwd_result_label.configure(
            text="Checking data leaks...", text_color="#FFC107"
        )
        self.update_idletasks()

        status_msg, color = check_password_strength(password)
        pwned_msg, pwned_color = check_pwned_password(password)

        final_text = f"Strength: {status_msg}\nLeak Status: {pwned_msg}"
        self.pwd_result_label.configure(text=final_text, text_color=color)

    # --- Port Scanner UI ---
    def create_port_scanner_ui(self):
        host_label = ctk.CTkLabel(
            self.tab_ports, text="Target Host / IP:", font=("Arial", 13)
        )
        host_label.pack(pady=(15, 5))

        self.host_entry = ctk.CTkEntry(self.tab_ports, width=300)
        self.host_entry.insert(0, "127.0.0.1")
        self.host_entry.pack(pady=5)

        self.scan_btn = ctk.CTkButton(
            self.tab_ports, text="Start Scan", command=self.start_scan_thread
        )
        self.scan_btn.pack(pady=10)

        self.output_box = ctk.CTkTextbox(
            self.tab_ports, width=380, height=260, font=("Courier", 12)
        )
        self.output_box.pack(pady=10)

    def start_scan_thread(self):
        self.scan_btn.configure(state="disabled", text="Scanning...")
        self.output_box.delete("1.0", ctk.END)

        thread = threading.Thread(target=self.run_port_scan)
        thread.daemon = True
        thread.start()

    def run_port_scan(self):
        target_host = self.host_entry.get().strip()
        common_ports = [21, 22, 53, 80, 443, 3306, 8080]

        self.append_text_safe(f"Scanning {target_host}...\n\n")

        for port in common_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.8)
            result = s.connect_ex((target_host, port))

            if result == 0:
                self.append_text_safe(f"[+] Port {port:<5d} : OPEN 🟢\n")
            else:
                self.append_text_safe(f"[-] Port {port:<5d} : CLOSED 🔴\n")
            s.close()

        self.append_text_safe("\nScan Completed!")
        self.after(
            0,
            lambda: self.scan_btn.configure(
                state="normal", text="Start Scan"
            ),
        )

    def append_text_safe(self, text):
        """Thread-safe GUI update for Textbox"""
        self.after(0, lambda: self.output_box.insert(ctk.END, text))

    # --- Password Generator UI ---
    def create_password_generator_ui(self):
        length_label = ctk.CTkLabel(
            self.tab_generator, text="Password Length:", font=("Arial", 12)
        )
        length_label.pack(pady=(10, 2))

        self.length_slider = ctk.CTkSlider(
            self.tab_generator,
            from_=8,
            to=32,
            number_of_steps=24,
            command=self.update_length_display,
        )
        self.length_slider.set(16)
        self.length_slider.pack(pady=5, padx=20, fill="x")

        self.length_display = ctk.CTkLabel(
            self.tab_generator, text="16 characters", font=("Arial", 10)
        )
        self.length_display.pack(pady=2)

        checkbox_frame = ctk.CTkFrame(self.tab_generator)
        checkbox_frame.pack(pady=8, padx=20)

        self.check_uppercase = ctk.CTkCheckBox(
            checkbox_frame, text="Uppercase (A-Z)"
        )
        self.check_uppercase.pack(anchor="w", pady=3)
        self.check_uppercase.select()

        self.check_lowercase = ctk.CTkCheckBox(
            checkbox_frame, text="Lowercase (a-z)"
        )
        self.check_lowercase.pack(anchor="w", pady=3)
        self.check_lowercase.select()

        self.check_digits = ctk.CTkCheckBox(checkbox_frame, text="Digits (0-9)")
        self.check_digits.pack(anchor="w", pady=3)
        self.check_digits.select()

        self.check_special = ctk.CTkCheckBox(
            checkbox_frame, text="Special (!@#$%...)"
        )
        self.check_special.pack(anchor="w", pady=3)
        self.check_special.select()

        gen_btn = ctk.CTkButton(
            self.tab_generator,
            text="Generate Password",
            command=self.on_generate_password,
        )
        gen_btn.pack(pady=10)

        self.gen_pwd_entry = ctk.CTkEntry(
            self.tab_generator, width=320, font=("Courier", 13), state="readonly"
        )
        self.gen_pwd_entry.pack(pady=5)

        copy_btn = ctk.CTkButton(
            self.tab_generator,
            text="📋 Copy to Clipboard",
            command=self.copy_to_clipboard,
            width=150,
        )
        copy_btn.pack(pady=5)

        self.gen_result_label = ctk.CTkLabel(
            self.tab_generator, text="", font=("Arial", 11, "bold")
        )
        self.gen_result_label.pack(pady=5)

    def update_length_display(self, value):
        self.length_display.configure(text=f"{int(float(value))} characters")

    def on_generate_password(self):
        length = int(float(self.length_slider.get()))
        use_upper = self.check_uppercase.get()
        use_lower = self.check_lowercase.get()
        use_digit = self.check_digits.get()
        use_spec = self.check_special.get()

        generated_pwd = generate_password(
            length, use_upper, use_lower, use_digit, use_spec
        )

        self.gen_pwd_entry.configure(state="normal")
        self.gen_pwd_entry.delete(0, ctk.END)
        self.gen_pwd_entry.insert(0, generated_pwd)
        self.gen_pwd_entry.configure(state="readonly")

        status_msg, color = check_password_strength(generated_pwd)
        self.gen_result_label.configure(
            text=f"Generated Strength: {status_msg}", text_color=color
        )

    def copy_to_clipboard(self):
        password = self.gen_pwd_entry.get()
        if password and not password.startswith("Error"):
            self.clipboard_clear()
            self.clipboard_append(password)
            self.update()
            self.gen_result_label.configure(
                text="Copied to clipboard! ✅", text_color="#2ECC71"
            )


if __name__ == "__main__":
    app = SystemSentinelApp()
    app.mainloop()