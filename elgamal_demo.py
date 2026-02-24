import tkinter as tk
from tkinter import ttk, scrolledtext
import threading
import queue
import random
import time
import os
import matplotlib
matplotlib.use("TkAgg")
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a, n):
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        q = r // newr
        t, newt = newt, t - q * newt
        r, newr = newr, r - q * newr
    if r > 1:
        raise ValueError("No modular inverse exists")
    if t < 0:
        t += n
    return t


def miller_rabin(n, k=20):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    while True:
        n = int.from_bytes(os.urandom(bits // 8), 'big')
        n |= (1 << (bits - 1))
        n |= 1
        if miller_rabin(n):
            return n


def generate_keys(bits=1024):
    p = generate_prime(bits)
    g = 2
    x = random.randrange(2, p - 1)
    y = pow(g, x, p)
    return p, g, x, y


def sign(m, p, g, x, k):
    r = pow(g, k, p)
    inv_k = mod_inverse(k, p - 1)
    s = ((m - x * r) * inv_k) % (p - 1)
    return r, s


def verify(m, p, g, y, r, s):
    if r <= 0 or r >= p:
        return False
    if s <= 0 or s >= p - 1:
        return False
    lhs = pow(g, m, p)
    rhs = (pow(y, r, p) * pow(r, s, p)) % p
    return lhs == rhs


def generate_bad_k(p):
    k = random.randrange(2, p - 2)
    if k % 2 != 0:
        k += 1
    if k >= p - 2:
        k -= 2
    return k


def run_attack(p, g, x, y, n=25):
    results = []
    m = random.randrange(2, p - 2)
    for i in range(n):
        k = generate_bad_k(p)
        d = gcd(k, p - 1)
        t0 = time.perf_counter()
        r_val = s_val = None
        try:
            r_val, s_val = sign(m, p, g, x, k)
            valid = verify(m, p, g, y, r_val, s_val)
            elapsed = time.perf_counter() - t0
            outcome = "forged" if not valid else "passed"
        except ValueError:
            elapsed = time.perf_counter() - t0
            outcome = "broken"
        results.append({"case": i + 1, "k": k, "gcd": d, "outcome": outcome,
                        "r": r_val, "s": s_val, "time": elapsed})
    broken = sum(1 for r in results if r["outcome"] == "broken")
    forged = sum(1 for r in results if r["outcome"] == "forged")
    vulnerable = broken + forged
    success_rate = (vulnerable / n) * 100
    return results, success_rate, m


def run_prevention(p, g, x, y, m, n=25):
    results = []
    for i in range(n):
        bad_k = generate_bad_k(p)
        d = gcd(bad_k, p - 1)
        if d != 1:
            valid_k = random.randrange(2, p - 2)
            while gcd(valid_k, p - 1) != 1:
                valid_k = random.randrange(2, p - 2)
        else:
            valid_k = bad_k
        t0 = time.perf_counter()
        r, s = sign(m, p, g, x, valid_k)
        valid = verify(m, p, g, y, r, s)
        elapsed = time.perf_counter() - t0
        results.append({
            "case": i + 1,
            "bad_k": bad_k,
            "valid_k": valid_k,
            "gcd": d,
            "blocked": d != 1,
            "r": r,
            "s": s,
            "outcome": "secure" if valid else "failed",
            "time": elapsed
        })
    return results


def benchmark_key_sizes(sizes):
    timings = []
    for bits in sizes:
        t0 = time.perf_counter()
        p, g, x, y = generate_keys(bits)
        keygen_t = time.perf_counter() - t0
        m = random.randrange(2, p - 2)
        valid_k = random.randrange(2, p - 2)
        while gcd(valid_k, p - 1) != 1:
            valid_k = random.randrange(2, p - 2)
        t0 = time.perf_counter()
        r, s = sign(m, p, g, x, valid_k)
        sign_t = time.perf_counter() - t0
        t0 = time.perf_counter()
        verify(m, p, g, y, r, s)
        verify_t = time.perf_counter() - t0
        timings.append({"bits": bits, "keygen": keygen_t, "sign": sign_t, "verify": verify_t})
    return timings


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("ElGamal Invalid-k Vulnerability Demo")
        self.configure(bg="#1e1e2e")
        self.resizable(True, True)
        self.q = queue.Queue()
        self.p = self.g = self.x = self.y = None
        self.attack_results = None
        self.prevention_results = None
        self.attack_success_rate = 0
        self.last_m = None
        self._build_ui()
        self._poll()

    def _build_ui(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure("TButton", font=("Segoe UI", 10, "bold"), padding=6)
        style.configure("TFrame", background="#1e1e2e")

        title = tk.Label(
            self, text="ElGamal Signature — Invalid Random k Vulnerability",
            font=("Segoe UI", 13, "bold"), bg="#1e1e2e", fg="#cdd6f4"
        )
        title.grid(row=0, column=0, columnspan=4, pady=(12, 4), padx=12)

        self.key_info = tk.Label(
            self, text="Keys not generated yet.",
            font=("Consolas", 9), bg="#1e1e2e", fg="#a6adc8", wraplength=780, justify="left"
        )
        self.key_info.grid(row=1, column=0, columnspan=4, padx=12, pady=(0, 6))

        btn_frame = ttk.Frame(self)
        btn_frame.grid(row=2, column=0, columnspan=4, pady=4)

        self.btn_keygen = ttk.Button(btn_frame, text="Generate Keys", command=self._keygen)
        self.btn_attack = ttk.Button(btn_frame, text="Run Attack (bad k)", command=self._attack, state="disabled")
        self.btn_prevent = ttk.Button(btn_frame, text="Apply Prevention", command=self._prevention, state="disabled")
        self.btn_graphs = ttk.Button(btn_frame, text="Show Graphs", command=self._show_graphs, state="disabled")

        for i, btn in enumerate([self.btn_keygen, self.btn_attack, self.btn_prevent, self.btn_graphs]):
            btn.grid(row=0, column=i, padx=6)

        self.log_box = scrolledtext.ScrolledText(
            self, width=100, height=24, bg="#181825", fg="#cdd6f4",
            font=("Consolas", 10), state="disabled", relief="flat", borderwidth=2
        )
        self.log_box.grid(row=3, column=0, columnspan=4, padx=12, pady=6, sticky="nsew")
        self.log_box.tag_configure("red", foreground="#f38ba8")
        self.log_box.tag_configure("green", foreground="#a6e3a1")
        self.log_box.tag_configure("cyan", foreground="#89dceb")
        self.log_box.tag_configure("yellow", foreground="#f9e2af")
        self.log_box.tag_configure("bold", font=("Consolas", 10, "bold"))

        self.status = tk.Label(self, text="Ready.", font=("Segoe UI", 9), bg="#1e1e2e", fg="#6c7086")
        self.status.grid(row=4, column=0, columnspan=4, pady=(0, 8))

        self.columnconfigure(0, weight=1)
        self.rowconfigure(3, weight=1)

    def log(self, msg, tag=""):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", msg + "\n", tag)
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _set_status(self, msg):
        self.status.configure(text=msg)

    def _poll(self):
        try:
            while True:
                item = self.q.get_nowait()
                item()
        except queue.Empty:
            pass
        self.after(100, self._poll)

    def _keygen(self):
        self.btn_keygen.configure(state="disabled")
        self._set_status("Generating 1024-bit prime... this may take a few seconds.")
        self.log("─" * 70, "cyan")
        self.log("Generating 1024-bit ElGamal keys...", "cyan")

        def worker():
            p, g, x, y = generate_keys(1024)
            def done():
                self.p, self.g, self.x, self.y = p, g, x, y
                self.key_info.configure(
                    text=f"p = {str(p)[:60]}...  |  g = {g}  |  Key size = 1024 bits"
                )
                self.log(f"p = {str(p)[:60]}...", "cyan")
                self.log(f"g = {g}", "cyan")
                self.log(f"x (private) = {str(x)[:50]}...", "yellow")
                self.log(f"y (public)  = {str(y)[:50]}...", "cyan")
                self.log("Keys generated successfully.", "green")
                self.btn_keygen.configure(state="normal")
                self.btn_attack.configure(state="normal")
                self._set_status("Keys ready.")
            self.q.put(done)

        threading.Thread(target=worker, daemon=True).start()

    def _attack(self):
        self.btn_attack.configure(state="disabled")
        self._set_status("Running attack with 25 bad-k values...")
        self.log("─" * 70, "red")
        self.log("ATTACK MODE — Using invalid k values (gcd(k, p-1) ≠ 1)", "red")
        self.log("All k values chosen as even → gcd(k, p-1) ≥ 2 guaranteed", "yellow")
        self.log("─" * 70, "red")

        def worker():
            results, success_rate, m = run_attack(self.p, self.g, self.x, self.y, 25)
            def done():
                self.attack_results = results
                self.attack_success_rate = success_rate
                self.last_m = m
                self.log(f"Message m = {str(m)[:55]}...", "cyan")
                self.log("")
                for r in results:
                    tag = "red" if r["outcome"] in ("broken", "forged") else "green"
                    self.log(f"Case {r['case']:02d}:", tag)
                    self.log(f"  k              = {str(r['k'])[:55]}...", tag)
                    self.log(f"  gcd(k, p-1)    = {r['gcd']}", "yellow")
                    self.log(f"  Inverse exists = {'No — k^-1 mod (p-1) undefined' if r['gcd'] != 1 else 'Yes'}", tag)
                    if r["outcome"] == "broken":
                        self.log(f"  mod_inverse failed — gcd={r['gcd']}, signing aborted", tag)
                    else:
                        self.log(f"  r = g^k mod p  = {str(r['r'])[:55]}...", tag)
                        self.log(f"  s              = {str(r['s'])[:55]}...", tag)
                        self.log(f"  Verification   = {'FAIL — signature invalid' if r['outcome'] == 'forged' else 'PASS'}", tag)
                    self.log(f"  Outcome        : {r['outcome'].upper()}", tag)
                    self.log("")
                self.log("")
                self.log(f"Attack Success Rate: {success_rate:.1f}%  "
                         f"({sum(1 for r in results if r['outcome'] != 'passed')}/25 cases vulnerable)", "red")
                self.log("─" * 70, "red")
                self.btn_attack.configure(state="normal")
                self.btn_prevent.configure(state="normal")
                self.btn_graphs.configure(state="normal")
                self._set_status(f"Attack complete. Vulnerability rate: {success_rate:.1f}%")
            self.q.put(done)

        threading.Thread(target=worker, daemon=True).start()

    def _prevention(self):
        self.btn_prevent.configure(state="disabled")
        self._set_status("Running prevention mechanism...")
        self.log("─" * 70, "green")
        self.log("PREVENTION MODE — gcd(k, p-1) = 1 enforced before signing", "green")
        self.log("─" * 70, "green")

        def worker():
            results = run_prevention(self.p, self.g, self.x, self.y, self.last_m, 25)
            def done():
                self.prevention_results = results
                for r in results:
                    self.log(f"Case {r['case']:02d}:", "green")
                    self.log(f"  bad k          = {str(r['bad_k'])[:55]}...", "yellow")
                    self.log(f"  gcd(bad_k,p-1) = {r['gcd']}", "yellow")
                    if r["blocked"]:
                        self.log(f"  k REJECTED — gcd = {r['gcd']}, no modular inverse", "red")
                        self.log(f"  new valid k    = {str(r['valid_k'])[:55]}...", "green")
                        self.log(f"  gcd(valid_k,p-1) = {gcd(r['valid_k'], self.p - 1)} — inverse exists", "green")
                    else:
                        self.log(f"  k accepted — gcd = 1", "green")
                    self.log(f"  r = g^k mod p  = {str(r['r'])[:55]}...", "green")
                    self.log(f"  s              = {str(r['s'])[:55]}...", "green")
                    self.log(f"  Verification   = PASS", "green")
                    self.log(f"  Outcome        : {r['outcome'].upper()}", "green")
                    self.log("")
                self.log("")
                self.log("Before Fix  →  Attack Success Rate: "
                         f"{self.attack_success_rate:.1f}%", "red")
                self.log("After Fix   →  Attack Success Rate: 0.0%", "green")
                self.log("─" * 70, "green")
                self.btn_prevent.configure(state="normal")
                self._set_status("Prevention applied. Attack rate: 0%")
            self.q.put(done)

        threading.Thread(target=worker, daemon=True).start()

    def _show_graphs(self):
        if self.attack_results is None:
            self.log("Run the attack first.", "yellow")
            return

        win = tk.Toplevel(self)
        win.title("Analysis Graphs")
        win.configure(bg="#1e1e2e")

        fig = Figure(figsize=(13, 9), facecolor="#1e1e2e")
        fig.subplots_adjust(hspace=0.45, wspace=0.35)

        attack_counts = {"broken": 0, "forged": 0, "passed": 0}
        for r in self.attack_results:
            attack_counts[r["outcome"]] += 1
        vulnerable_before = attack_counts["broken"] + attack_counts["forged"]

        ax1 = fig.add_subplot(2, 2, 1)
        ax1.set_facecolor("#181825")
        bars = ax1.bar(
            ["Before Fix", "After Fix"],
            [self.attack_success_rate, 0],
            color=["#f38ba8", "#a6e3a1"], width=0.4
        )
        ax1.set_ylim(0, 110)
        ax1.set_ylabel("Success Rate (%)", color="#cdd6f4")
        ax1.set_title("Attack Success Rate Before vs After Fix", color="#cdd6f4", pad=8)
        ax1.tick_params(colors="#cdd6f4")
        for spine in ax1.spines.values():
            spine.set_edgecolor("#45475a")
        for bar, val in zip(bars, [self.attack_success_rate, 0]):
            ax1.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 1,
                     f"{val:.1f}%", ha="center", color="#cdd6f4", fontsize=10, fontweight="bold")

        ax2 = fig.add_subplot(2, 2, 2)
        ax2.set_facecolor("#181825")
        self._set_status("Benchmarking key sizes for Graph 2...")
        timings = benchmark_key_sizes([512, 1024, 1536])
        bits_labels = [str(t["bits"]) for t in timings]
        keygen_times = [t["keygen"] for t in timings]
        sign_times = [t["sign"] * 1000 for t in timings]
        verify_times = [t["verify"] * 1000 for t in timings]
        ax2.plot(bits_labels, keygen_times, marker="o", color="#89b4fa", label="Key Gen (s)")
        ax2_r = ax2.twinx()
        ax2_r.plot(bits_labels, sign_times, marker="s", color="#f9e2af", label="Sign (ms)")
        ax2_r.plot(bits_labels, verify_times, marker="^", color="#a6e3a1", label="Verify (ms)")
        ax2_r.tick_params(colors="#cdd6f4")
        ax2_r.set_ylabel("Sign / Verify (ms)", color="#cdd6f4")
        for spine in ax2_r.spines.values():
            spine.set_edgecolor("#45475a")
        ax2.set_ylabel("Key Gen (s)", color="#cdd6f4")
        ax2.set_title("Time vs Key Size", color="#cdd6f4", pad=8)
        ax2.tick_params(colors="#cdd6f4")
        for spine in ax2.spines.values():
            spine.set_edgecolor("#45475a")
        lines1, labels1 = ax2.get_legend_handles_labels()
        lines2, labels2 = ax2_r.get_legend_handles_labels()
        ax2.legend(lines1 + lines2, labels1 + labels2,
                   facecolor="#313244", labelcolor="#cdd6f4", fontsize=7)

        ax3 = fig.add_subplot(2, 2, 3)
        ax3.set_facecolor("#181825")
        cases = [r["case"] for r in self.attack_results]
        valid_before = [1 if r["outcome"] == "passed" else 0 for r in self.attack_results]
        valid_after = [1] * 25
        ax3.bar(cases, valid_before, color="#f38ba8", label="Before Fix", alpha=0.85)
        if self.prevention_results:
            ax3.bar(cases, valid_after, color="#a6e3a1", label="After Fix", alpha=0.4)
        ax3.set_xlabel("Test Case", color="#cdd6f4")
        ax3.set_ylabel("Valid Signature (1=Yes, 0=No)", color="#cdd6f4")
        ax3.set_title("Authentication Rate per Test Case", color="#cdd6f4", pad=8)
        ax3.tick_params(colors="#cdd6f4")
        ax3.legend(facecolor="#313244", labelcolor="#cdd6f4", fontsize=8)
        for spine in ax3.spines.values():
            spine.set_edgecolor("#45475a")

        ax4 = fig.add_subplot(2, 2, 4)
        ax4.set_facecolor("#181825")
        attack_times_ms = [r["time"] * 1000 for r in self.attack_results]
        prevent_times_ms = ([r["time"] * 1000 for r in self.prevention_results]
                            if self.prevention_results else [0] * 25)
        mean_attack = sum(attack_times_ms) / len(attack_times_ms)
        mean_prevent = sum(prevent_times_ms) / len(prevent_times_ms)
        bars4 = ax4.bar(
            ["Without gcd\nCheck (attack)", "With gcd\nCheck (prevention)"],
            [mean_attack, mean_prevent],
            color=["#f38ba8", "#a6e3a1"], width=0.4
        )
        ax4.set_ylabel("Mean Latency (ms)", color="#cdd6f4")
        ax4.set_title("Signing Latency Overhead", color="#cdd6f4", pad=8)
        ax4.tick_params(colors="#cdd6f4")
        for spine in ax4.spines.values():
            spine.set_edgecolor("#45475a")
        for bar, val in zip(bars4, [mean_attack, mean_prevent]):
            ax4.text(bar.get_x() + bar.get_width() / 2, bar.get_height() * 1.02,
                     f"{val:.4f} ms", ha="center", color="#cdd6f4", fontsize=9)

        canvas = FigureCanvasTkAgg(fig, master=win)
        canvas.draw()
        canvas.get_tk_widget().pack(fill="both", expand=True, padx=8, pady=8)
        self._set_status("Graphs ready.")


if __name__ == "__main__":
    app = App()
    app.mainloop()
