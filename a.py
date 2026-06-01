"""
Password Strength Analyzer — Python (Tkinter GUI)
Run:  python password_strength_analyzer.py
Requires: Python 3.8+  (tkinter is built-in, no pip install needed)
"""

import tkinter as tk
from tkinter import ttk, messagebox
import hashlib
import random
import string
import re
import math


# ── Common / weak passwords ────────────────────────────────────────────────
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "monkey",
    "1234567", "letmein", "trustno1", "dragon", "baseball", "iloveyou",
    "master", "sunshine", "ashley", "bailey", "passw0rd", "shadow",
    "123123", "654321", "superman", "qazwsx", "michael", "football",
    "password1", "password123", "admin", "welcome", "login", "hello",
}

WORDLIST = [
    "thunder", "crimson", "falcon", "nebula", "prism", "vortex",
    "ember", "cipher", "zenith", "mosaic", "phantom", "lantern",
    "spiral", "quasar", "aurora", "glacier", "mystic", "cobalt",
    "desert", "inferno", "lunar", "oracle", "raven", "titan",
]


# ── Core analysis logic ────────────────────────────────────────────────────

def calc_entropy(password: str) -> float:
    pool = 0
    if re.search(r"[a-z]", password): pool += 26
    if re.search(r"[A-Z]", password): pool += 26
    if re.search(r"[0-9]", password): pool += 10
    if re.search(r"[^a-zA-Z0-9]", password): pool += 32
    return round(password and math.log2(pool) * len(password), 1)


def crack_time_label(entropy: float) -> str:
    guesses_per_sec = 1e10
    seconds = (2 ** entropy) / guesses_per_sec / 2 if entropy else 0
    if seconds < 1:        return "instantly"
    if seconds < 60:       return f"~{int(seconds)}s"
    if seconds < 3600:     return f"~{int(seconds/60)} min"
    if seconds < 86400:    return f"~{int(seconds/3600)} hrs"
    if seconds < 31536000: return f"~{int(seconds/86400)} days"
    years = seconds / 31536000
    if years < 1e6:        return f"~{int(years):,} years"
    return f"~{years:.1e} years"


def analyze_password(password: str, history_hashes: set) -> dict:
    pw = password
    length = len(pw)
    score = 0
    checks = []

    # Length
    ok = length >= 12
    warn = 8 <= length < 12
    checks.append(("Length ≥ 12 chars", ok, warn,
                   f"Current: {length} char{'s' if length != 1 else ''}"))
    if length >= 8:  score += 10
    if length >= 12: score += 15
    if length >= 16: score += 15
    if length >= 20: score += 10

    # Complexity
    has_lower  = bool(re.search(r"[a-z]", pw))
    has_upper  = bool(re.search(r"[A-Z]", pw))
    has_digit  = bool(re.search(r"[0-9]", pw))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", pw))
    checks.append(("Lowercase letters (a-z)", has_lower, False, ""))
    checks.append(("Uppercase letters (A-Z)", has_upper, False, ""))
    checks.append(("Numbers (0-9)",            has_digit, False, ""))
    checks.append(("Special characters (!@#…)", has_symbol, False, ""))
    if has_lower:  score += 5
    if has_upper:  score += 10
    if has_digit:  score += 10
    if has_symbol: score += 15

    # Common password
    is_common = pw.lower() in COMMON_PASSWORDS
    checks.append(("Not a common password", not is_common, False,
                   "Found in common password list" if is_common else ""))
    if is_common: score -= 40

    # Repeating chars
    all_same = len(set(pw)) == 1 if pw else False
    checks.append(("No all-identical characters", not all_same, False,
                   "All characters are the same" if all_same else ""))
    if all_same: score -= 20

    # Sequential pattern
    seq = bool(re.search(r"(012|123|234|345|456|567|678|789|abc|bcd|cde|qwer|asdf|zxcv)", pw.lower()))
    checks.append(("No sequential/keyboard patterns", not seq, False,
                   "Contains sequential pattern" if seq else ""))
    if seq: score -= 15

    # Character variety
    unique_ratio = len(set(pw)) / length if length else 0
    good_variety = unique_ratio >= 0.6
    checks.append(("Good character variety (≥60% unique)", good_variety,
                   not good_variety and unique_ratio >= 0.4,
                   f"{int(unique_ratio*100)}% unique characters"))
    if good_variety: score += 10

    # Reuse check
    h = hashlib.sha256(pw.encode()).hexdigest()
    reused = h in history_hashes and length > 0
    checks.append(("Not previously used (this session)", not reused, False,
                   "Password was used before" if reused else ""))
    if reused: score -= 20

    score = max(0, min(100, score))
    entropy = calc_entropy(pw)

    if score < 20:   label, color = "Very Weak",   "#E24B4A"
    elif score < 40: label, color = "Weak",         "#E07B39"
    elif score < 60: label, color = "Fair",         "#E0B839"
    elif score < 80: label, color = "Strong",       "#4CAF50"
    else:            label, color = "Very Strong",  "#2196F3"

    return {
        "score": score, "label": label, "color": color,
        "checks": checks, "entropy": entropy,
        "crack_time": crack_time_label(entropy), "hash": h,
    }


def generate_suggestions() -> list[str]:
    suggestions = []
    syms = "!@#$%^&*"
    for _ in range(3):
        w1 = random.choice(WORDLIST).capitalize()
        w2 = random.choice(WORDLIST)
        sym = random.choice(syms)
        num = random.randint(10, 999)
        suggestions.append(f"{w1}{w2}{sym}{num}")
    # Passphrase
    words = random.sample(WORDLIST, 4)
    suggestions.append("-".join(words) + str(random.randint(10, 99)))
    return suggestions


# ── GUI ───────────────────────────────────────────────────────────────────

class PasswordAnalyzerApp(tk.Tk):
    BG        = "#1a1a2e"
    PANEL     = "#16213e"
    ACCENT    = "#0f3460"
    TEXT      = "#e0e0e0"
    SUBTEXT   = "#8892a4"
    FONT_MAIN = ("Courier New", 11)
    FONT_HEAD = ("Courier New", 13, "bold")
    FONT_BIG  = ("Courier New", 20, "bold")

    def __init__(self):
        super().__init__()
        self.title("Password Strength Analyzer")
        self.geometry("700x820")
        self.resizable(False, False)
        self.configure(bg=self.BG)
        self.history_hashes: set[str] = set()
        self.history_list: list[dict] = []
        self._build_ui()

    # ── UI construction ──────────────────────────────────────────────────

    def _build_ui(self):
        # Title
        tk.Label(self, text="🔐 Password Strength Analyzer",
                 font=("Courier New", 16, "bold"),
                 bg=self.BG, fg="#e0e0e0").pack(pady=(20, 4))
        tk.Label(self, text="Enter a password to evaluate its security",
                 font=("Courier New", 10), bg=self.BG, fg=self.SUBTEXT).pack()

        # Input area
        input_frame = tk.Frame(self, bg=self.PANEL, pady=16, padx=20)
        input_frame.pack(fill="x", padx=24, pady=(16, 8))

        tk.Label(input_frame, text="PASSWORD", font=("Courier New", 9, "bold"),
                 bg=self.PANEL, fg=self.SUBTEXT).pack(anchor="w")

        entry_row = tk.Frame(input_frame, bg=self.PANEL)
        entry_row.pack(fill="x", pady=(4, 0))

        self.pw_var = tk.StringVar()
        self.pw_var.trace_add("write", lambda *_: self._on_type())
        self.show_pw = False

        self.entry = tk.Entry(entry_row, textvariable=self.pw_var, show="•",
                              font=("Courier New", 14), bg="#0d1b2a",
                              fg="#00e5ff", insertbackground="#00e5ff",
                              relief="flat", bd=0)
        self.entry.pack(side="left", fill="x", expand=True, ipady=8, ipadx=8)
        self.entry.focus()

        self.vis_btn = tk.Button(entry_row, text="👁", font=("Courier New", 12),
                                 bg=self.ACCENT, fg=self.TEXT, relief="flat",
                                 cursor="hand2", command=self._toggle_vis,
                                 padx=8)
        self.vis_btn.pack(side="left", padx=(6, 0))

        # Strength meter
        meter_frame = tk.Frame(self, bg=self.BG)
        meter_frame.pack(fill="x", padx=24, pady=(0, 8))

        self.score_lbl = tk.Label(meter_frame, text="—",
                                  font=self.FONT_BIG, bg=self.BG, fg=self.SUBTEXT)
        self.score_lbl.pack(side="left")

        right = tk.Frame(meter_frame, bg=self.BG)
        right.pack(side="left", fill="x", expand=True, padx=(16, 0))

        self.label_lbl = tk.Label(right, text="Enter a password",
                                  font=self.FONT_HEAD, bg=self.BG, fg=self.SUBTEXT)
        self.label_lbl.pack(anchor="w")

        bar_bg = tk.Frame(right, bg="#2a2a4a", height=8)
        bar_bg.pack(fill="x", pady=(4, 2))
        bar_bg.pack_propagate(False)
        self.bar_fill = tk.Frame(bar_bg, bg=self.SUBTEXT, height=8, width=0)
        self.bar_fill.place(x=0, y=0, relheight=1, width=0)

        self.crack_lbl = tk.Label(right, text="",
                                  font=("Courier New", 9), bg=self.BG, fg=self.SUBTEXT)
        self.crack_lbl.pack(anchor="w")

        self.entropy_lbl = tk.Label(right, text="",
                                    font=("Courier New", 9), bg=self.BG, fg=self.SUBTEXT)
        self.entropy_lbl.pack(anchor="w")

        # Checks panel
        checks_outer = tk.Frame(self, bg=self.PANEL, padx=20, pady=14)
        checks_outer.pack(fill="x", padx=24, pady=(4, 8))
        tk.Label(checks_outer, text="SECURITY CHECKS",
                 font=("Courier New", 9, "bold"), bg=self.PANEL, fg=self.SUBTEXT).pack(anchor="w")
        self.checks_frame = tk.Frame(checks_outer, bg=self.PANEL)
        self.checks_frame.pack(fill="x", pady=(6, 0))

        # Suggestions panel
        sug_outer = tk.Frame(self, bg=self.PANEL, padx=20, pady=14)
        sug_outer.pack(fill="x", padx=24, pady=(0, 8))
        sug_head = tk.Frame(sug_outer, bg=self.PANEL)
        sug_head.pack(fill="x")
        tk.Label(sug_head, text="STRONGER ALTERNATIVES",
                 font=("Courier New", 9, "bold"), bg=self.PANEL, fg=self.SUBTEXT).pack(side="left")
        tk.Button(sug_head, text="↻ Regenerate", font=("Courier New", 9),
                  bg=self.ACCENT, fg=self.TEXT, relief="flat", cursor="hand2",
                  command=self._regen_suggestions, padx=6).pack(side="right")
        self.sug_frame = tk.Frame(sug_outer, bg=self.PANEL)
        self.sug_frame.pack(fill="x", pady=(8, 0))
        self._regen_suggestions()

        # History panel
        hist_outer = tk.Frame(self, bg=self.PANEL, padx=20, pady=14)
        hist_outer.pack(fill="x", padx=24, pady=(0, 16))
        hist_head = tk.Frame(hist_outer, bg=self.PANEL)
        hist_head.pack(fill="x")
        tk.Label(hist_head, text="PASSWORD HISTORY  (session only — hashed)",
                 font=("Courier New", 9, "bold"), bg=self.PANEL, fg=self.SUBTEXT).pack(side="left")
        tk.Button(hist_head, text="Clear", font=("Courier New", 9),
                  bg=self.ACCENT, fg=self.TEXT, relief="flat", cursor="hand2",
                  command=self._clear_history, padx=6).pack(side="right")
        self.hist_frame = tk.Frame(hist_outer, bg=self.PANEL)
        self.hist_frame.pack(fill="x", pady=(8, 0))
        self._render_history()

    # ── Event handlers ───────────────────────────────────────────────────

    def _on_type(self):
        pw = self.pw_var.get()
        if not pw:
            self._reset_ui()
            return
        result = analyze_password(pw, self.history_hashes)
        self._update_score(result)
        self._update_checks(result["checks"])
        # Save to history when password changes and len > 3
        if len(pw) > 3:
            h = result["hash"]
            if h not in self.history_hashes:
                self.history_hashes.add(h)
                masked = pw[0] + "•" * (len(pw) - 2) + pw[-1]
                self.history_list.insert(0, {
                    "masked": masked, "score": result["score"],
                    "label": result["label"], "color": result["color"]
                })
                if len(self.history_list) > 6:
                    self.history_list.pop()
                self._render_history()

    def _toggle_vis(self):
        self.show_pw = not self.show_pw
        self.entry.config(show="" if self.show_pw else "•")
        self.vis_btn.config(text="🙈" if self.show_pw else "👁")

    def _regen_suggestions(self):
        for w in self.sug_frame.winfo_children():
            w.destroy()
        for s in generate_suggestions():
            row = tk.Frame(self.sug_frame, bg="#0d1b2a", pady=4, padx=10)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=s, font=("Courier New", 11),
                     bg="#0d1b2a", fg="#00e5ff").pack(side="left")
            tk.Button(row, text="Copy", font=("Courier New", 9),
                      bg=self.ACCENT, fg=self.TEXT, relief="flat", cursor="hand2",
                      command=lambda v=s: self._copy(v), padx=6).pack(side="right")

    def _copy(self, text: str):
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("Copied", f"Copied to clipboard:\n{text}")

    def _clear_history(self):
        self.history_hashes.clear()
        self.history_list.clear()
        self._render_history()

    # ── Rendering helpers ────────────────────────────────────────────────

    def _reset_ui(self):
        self.score_lbl.config(text="—", fg=self.SUBTEXT)
        self.label_lbl.config(text="Enter a password", fg=self.SUBTEXT)
        self.crack_lbl.config(text="")
        self.entropy_lbl.config(text="")
        self.bar_fill.place_configure(width=0)
        for w in self.checks_frame.winfo_children():
            w.destroy()

    def _update_score(self, r: dict):
        self.score_lbl.config(text=str(r["score"]), fg=r["color"])
        self.label_lbl.config(text=r["label"], fg=r["color"])
        self.crack_lbl.config(text=f"Crack time: {r['crack_time']} at 10B guesses/sec")
        self.entropy_lbl.config(text=f"Entropy: {r['entropy']} bits")
        bar_w = int((r["score"] / 100) * (700 - 48 - 32 - 90))
        self.bar_fill.place_configure(width=bar_w)
        self.bar_fill.config(bg=r["color"])

    def _update_checks(self, checks: list):
        for w in self.checks_frame.winfo_children():
            w.destroy()
        cols = 2
        for i, (label, passed, warn, note) in enumerate(checks):
            row, col = divmod(i, cols)
            cell = tk.Frame(self.checks_frame, bg=self.PANEL)
            cell.grid(row=row, column=col, sticky="w", padx=(0, 20), pady=2)
            if passed:
                icon, color = "✓", "#4CAF50"
            elif warn:
                icon, color = "~", "#E0B839"
            else:
                icon, color = "✗", "#E24B4A"
            tk.Label(cell, text=icon, font=("Courier New", 11, "bold"),
                     bg=self.PANEL, fg=color, width=2).pack(side="left")
            display = f"{label}"
            if note:
                display += f"  ({note})"
            tk.Label(cell, text=display, font=("Courier New", 10),
                     bg=self.PANEL, fg=self.TEXT).pack(side="left")

    def _render_history(self):
        for w in self.hist_frame.winfo_children():
            w.destroy()
        if not self.history_list:
            tk.Label(self.hist_frame, text="No history yet.",
                     font=("Courier New", 10), bg=self.PANEL, fg=self.SUBTEXT).pack(anchor="w")
            return
        for item in self.history_list:
            row = tk.Frame(self.hist_frame, bg="#0d1b2a", pady=4, padx=10)
            row.pack(fill="x", pady=2)
            tk.Label(row, text=item["masked"], font=("Courier New", 11),
                     bg="#0d1b2a", fg=self.TEXT).pack(side="left")
            tk.Label(row, text=f"{item['label']}  ({item['score']})",
                     font=("Courier New", 10, "bold"),
                     bg="#0d1b2a", fg=item["color"]).pack(side="right")


# ── Entry point ───────────────────────────────────────────────────────────

if __name__ == "__main__":
    app = PasswordAnalyzerApp()
    app.mainloop()
