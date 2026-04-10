#!/usr/bin/env python3
"""
Password Strength Checker — Terminal Tool
Analyzes passwords for vulnerabilities, entropy, crack time, and more.
"""

import math
import sys
import re
import os
import getpass


# ──────────────────────────────────────────────
# ANSI Colors & Styles
# ──────────────────────────────────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"

    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    WHITE   = "\033[97m"
    GRAY    = "\033[90m"

    BG_RED    = "\033[41m"
    BG_YELLOW = "\033[43m"
    BG_GREEN  = "\033[42m"
    BG_CYAN   = "\033[46m"


def colored(text, *codes):
    return "".join(codes) + str(text) + C.RESET


def clear():
    os.system("cls" if os.name == "nt" else "clear")


# ──────────────────────────────────────────────
# Data
# ──────────────────────────────────────────────
def load_common_passwords (filepath = "10k-most-common.txt") :
    with open(filepath, "r",encoding="utf-8") as file :
        return {line.strip().lower() for line in file if line.strip()}

COMMON_PASSWORDS = load_common_passwords()

KEYBOARD_WALKS = [
    "qwerty", "asdfgh", "zxcvbn", "qazwsx", "1234567890",
    "poiuyt", "lkjhgf", "mnbvcx", "qweasd", "rfvtgb",
]


# ──────────────────────────────────────────────
# Analysis Functions
# ──────────────────────────────────────────────
def check_length(pw):
    n = len(pw)
    if n < 8:
        return False, f"Too short ({n} chars) — minimum 8"
    if n < 12:
        return True, f"{n} chars — acceptable (12+ recommended)"
    if n < 16:
        return True, f"{n} chars — good"
    return True, f"{n} chars — excellent"


def check_uppercase(pw):
    return bool(re.search(r'[A-Z]', pw)), "Contains uppercase letters"


def check_lowercase(pw):
    return bool(re.search(r'[a-z]', pw)), "Contains lowercase letters"


def check_digits(pw):
    return bool(re.search(r'[0-9]', pw)), "Contains numbers"


def check_special(pw):
    return bool(re.search(r'[^A-Za-z0-9]', pw)), "Contains special characters"


def find_repeated_chars(pw):
    """Finds characters repeated 3+ times consecutively."""
    found = []
    i = 0
    while i < len(pw):
        j = i
        while j < len(pw) and pw[j] == pw[i]:
            j += 1
        if j - i >= 3:
            found.append((pw[i], j - i))
        i = j
    return found


def has_sequential(pw):
    """Detects 3+ sequential alphabetic or numeric characters."""
    v = pw.lower()
    for i in range(len(v) - 2):
        a, b, c = ord(v[i]), ord(v[i+1]), ord(v[i+2])
        if b - a == 1 and c - b == 1:
            return True
        if a - b == 1 and b - c == 1:
            return True
    return False


def has_keyboard_walk(pw):
    v = pw.lower()
    for walk in KEYBOARD_WALKS:
        if walk[:4] in v:
            return True, walk[:4]
    return False, None


def is_common(pw):
    return pw.lower() in COMMON_PASSWORDS


def unique_ratio(pw):
    if not pw:
        return 0.0
    return len(set(pw)) / len(pw)


def calculate_entropy(pw):
    pool = 0
    if re.search(r'[a-z]', pw): pool += 26
    if re.search(r'[A-Z]', pw): pool += 26
    if re.search(r'[0-9]', pw): pool += 10
    if re.search(r'[^A-Za-z0-9]', pw): pool += 32
    if ' ' in pw: pool += 1
    if pool == 0: pool = 26
    return len(pw) * math.log2(pool)


def entropy_label(e):
    if e < 28:  return colored("Extremely weak", C.RED, C.BOLD)
    if e < 40:  return colored("Very weak",      C.RED)
    if e < 60:  return colored("Weak",           C.YELLOW)
    if e < 80:  return colored("Moderate",       C.CYAN)
    if e < 100: return colored("Strong",         C.GREEN)
    return colored("Very strong", C.GREEN, C.BOLD)


def estimate_crack_time(entropy):
    guesses_per_sec = 1e10  # 10 billion/s — offline GPU attack
    total_guesses   = 2 ** entropy
    seconds         = total_guesses / guesses_per_sec / 2

    if seconds < 1:
        return "Instantly"

    intervals = [
        (3.154e13, "millennium"),
        (3.154e10, "century"),
        (3.156e7,  "year"),
        (2.628e6,  "month"),
        (86400,    "day"),
        (3600,     "hour"),
        (60,       "minute"),
        (1,        "second"),
    ]
    for secs, label in intervals:
        if seconds >= secs:
            val = seconds / secs
            if val > 1e15: return f"> 1 quadrillion {label}s"
            if val > 1e12: return f"> 1 trillion {label}s"
            if val > 1e9:  return f"> 1 billion {label}s"
            if val > 1e6:  return f"> 1 million {label}s"
            if val > 1000: return f"> 1,000 {label}s"
            v = round(val)
            return f"{v} {label}{'s' if v != 1 else ''}"
    return "Instantly"


def score_password(pw):
    n              = len(pw)
    has_up         = bool(re.search(r'[A-Z]', pw))
    has_lo         = bool(re.search(r'[a-z]', pw))
    has_dig        = bool(re.search(r'[0-9]', pw))
    has_sp         = bool(re.search(r'[^A-Za-z0-9]', pw))
    entropy        = calculate_entropy(pw)
    common         = is_common(pw)
    repeated       = find_repeated_chars(pw)
    sequential     = has_sequential(pw)
    keyboard, _    = has_keyboard_walk(pw)
    u_ratio        = unique_ratio(pw)

    score = 0
    if n >= 8:  score += 10
    if n >= 12: score += 15
    if n >= 16: score += 10
    if has_up:  score += 10
    if has_lo:  score += 10
    if has_dig: score += 10
    if has_sp:  score += 15
    if entropy >= 60:  score += 10
    if entropy >= 80:  score += 10
    if u_ratio >= 0.7: score += 10

    if common:          score -= 40
    if repeated:        score -= 10
    if sequential:      score -= 8
    if keyboard:        score -= 10

    return max(0, min(100, score))


def classify(score):
    if score < 30: return "WEAK",   C.RED
    if score < 55: return "FAIR",   C.YELLOW
    if score < 75: return "GOOD",   C.GREEN
    return               "STRONG",  C.CYAN


def get_suggestions(pw):
    n          = len(pw)
    has_up     = bool(re.search(r'[A-Z]', pw))
    has_lo     = bool(re.search(r'[a-z]', pw))
    has_dig    = bool(re.search(r'[0-9]', pw))
    has_sp     = bool(re.search(r'[^A-Za-z0-9]', pw))
    entropy    = calculate_entropy(pw)
    common     = is_common(pw)
    repeated   = find_repeated_chars(pw)
    sequential = has_sequential(pw)
    kw, kw_ex  = has_keyboard_walk(pw)
    u_ratio    = unique_ratio(pw)

    tips = []
    if common:
        tips.append("This is one of the most breached passwords — change it immediately.")
    if n < 8:
        tips.append("Use at least 8 characters; 12 or more is strongly recommended.")
    elif n < 12:
        tips.append("Increase to 12+ characters for significantly better security.")
    if not has_up:
        tips.append("Add uppercase letters (A–Z).")
    if not has_lo:
        tips.append("Add lowercase letters (a–z).")
    if not has_dig:
        tips.append("Include at least one number (0–9).")
    if not has_sp:
        tips.append("Add special characters such as !, @, #, $, %, ^, &, *.")
    if repeated:
        chars = ", ".join(f'"{c}" ×{count}' for c, count in repeated)
        tips.append(f"Avoid repeating characters consecutively: {chars}.")
    if sequential:
        tips.append("Remove sequential patterns like abc, xyz, 123, 321.")
    if kw:
        tips.append(f'Avoid keyboard walk patterns (found: "{kw_ex}…").')
    if u_ratio < 0.6 and n > 5:
        tips.append("Too many duplicate characters — use more variety.")
    if entropy < 50 and not common:
        tips.append("Consider a passphrase: four or more random words joined together.")
    if not tips:
        tips.append("No major issues found — your password looks solid!")
    return tips


# ──────────────────────────────────────────────
# UI Helpers
# ──────────────────────────────────────────────
# TERM_WIDTH = min(os.get_terminal_size().columns if hasattr(os, 'get_terminal_size') else 72, 72)
try:
    TERM_WIDTH = min(os.get_terminal_size().columns, 72)
except OSError:
    TERM_WIDTH = 72

def hr(char="─"):
    print(colored(char * TERM_WIDTH, C.GRAY))


def header():
    clear()
    hr("═")
    title = "  🔐  PASSWORD STRENGTH CHECKER"
    print(colored(title, C.BOLD, C.WHITE))
    print(colored("  Analyze vulnerabilities · entropy · crack time · suggestions", C.GRAY))
    hr("═")
    print()


def strength_bar(score, width=40):
    label, color = classify(score)
    filled = round(score / 100 * width)
    bar    = "█" * filled + "░" * (width - filled)
    print(f"  Strength  {colored(bar, color)}  {colored(f'{score}/100', color, C.BOLD)}  {colored(label, color, C.BOLD)}")
    print()


def check_row(ok, label, detail=""):
    icon  = colored("✔", C.GREEN) if ok else colored("✘", C.RED)
    dlabel = colored(label, C.WHITE if ok else C.GRAY)
    ddetail = colored(f"  {detail}", C.GRAY) if detail else ""
    print(f"  {icon}  {dlabel}{ddetail}")


def section(title):
    print()
    print(colored(f"  {title}", C.BOLD, C.CYAN))
    hr()


# ──────────────────────────────────────────────
# Main Report
# ──────────────────────────────────────────────
def analyze(pw):
    if not pw:
        print(colored("  No password entered.", C.RED))
        return

    n           = len(pw)
    has_up      = bool(re.search(r'[A-Z]', pw))
    has_lo      = bool(re.search(r'[a-z]', pw))
    has_dig     = bool(re.search(r'[0-9]', pw))
    has_sp      = bool(re.search(r'[^A-Za-z0-9]', pw))
    entropy     = calculate_entropy(pw)
    common      = is_common(pw)
    repeated    = find_repeated_chars(pw)
    sequential  = has_sequential(pw)
    kw, kw_ex   = has_keyboard_walk(pw)
    u_ratio     = unique_ratio(pw)
    crack_time  = estimate_crack_time(entropy)
    score       = score_password(pw)
    label, clr  = classify(score)
    suggestions = get_suggestions(pw)
    u_count     = len(set(pw))

    # ── Strength bar
    strength_bar(score)

    # ── Common password warning
    if common:
        print(colored(f"  ⚠  COMMON PASSWORD — found in breach databases!", C.RED, C.BOLD))
        print()
    else:
        print(colored("  ✓  Not found in common password list", C.GREEN))
        print()

    # ── Stats row
    section("STATISTICS")
    stats = [
        ("Length",        str(n),                  "chars"),
        ("Entropy",       f"{entropy:.1f}",         "bits  → " + entropy_label(entropy)),
        ("Unique chars",  f"{u_count}/{n}",         f"({round(u_ratio*100)}% unique)"),
        ("Character pool",_pool_desc(pw),           ""),
        ("Time to crack", crack_time,               "at 10 billion guesses/sec"),
    ]
    for stat, val, note in stats:
        label_s = colored(f"{stat:<16}", C.GRAY)
        val_s   = colored(val, C.WHITE, C.BOLD)
        note_s  = colored(f"  {note}", C.GRAY) if note else ""
        print(f"  {label_s} {val_s}{note_s}")

    # ── Checks
    section("SECURITY CHECKS")
    len_ok, len_msg = check_length(pw)
    check_row(len_ok,      "Length",               len_msg)
    check_row(has_up,      "Uppercase letters",    "A–Z present" if has_up else "none found")
    check_row(has_lo,      "Lowercase letters",    "a–z present" if has_lo else "none found")
    check_row(has_dig,     "Numbers",              "0–9 present" if has_dig else "none found")
    check_row(has_sp,      "Special characters",   "present"     if has_sp else "none found")
    check_row(not repeated,"No repeated chars",    "" if not repeated else f'found: {"".join(c for c,_ in repeated)}')
    check_row(not sequential,"No sequential patterns", "e.g. abc, 123" if sequential else "")
    check_row(not kw,      "No keyboard walks",    f'e.g. {kw_ex}…' if kw else "")
    check_row(u_ratio >= 0.6,"Good character variety", f"{round(u_ratio*100)}% unique")

    # ── Suggestions
    section("SUGGESTIONS")
    for i, tip in enumerate(suggestions, 1):
        bullet = colored(f"  {i}.", C.CYAN)
        print(f"{bullet} {colored(tip, C.WHITE)}")

    print()
    hr("═")
    print()


def _pool_desc(pw):
    parts = []
    if re.search(r'[a-z]', pw): parts.append("a–z(26)")
    if re.search(r'[A-Z]', pw): parts.append("A–Z(26)")
    if re.search(r'[0-9]', pw): parts.append("0–9(10)")
    if re.search(r'[^A-Za-z0-9]', pw): parts.append("symbols(32)")
    total = sum(int(p.split("(")[1].rstrip(")")) for p in parts)
    return f"{' + '.join(parts)} = {total}"


# ──────────────────────────────────────────────
# Entry Point
# ──────────────────────────────────────────────
def main():
    header()

    # Allow password via command-line argument for scripting
    if len(sys.argv) > 1:
        pw = sys.argv[1]
        print(colored(f"  Analyzing provided password…", C.GRAY))
        print()
        analyze(pw)
        return

    # Interactive loop
    while True:
        try:
            print(colored("  Enter password to analyze", C.GRAY))
            print(colored("  (input is hidden — press Enter to submit, Ctrl+C to quit)\n", C.GRAY))

            try:
                pw = getpass.getpass(prompt=colored("  Password: ", C.CYAN))
            except Exception:
                pw = input(colored("  Password: ", C.CYAN))

            print("\n")
            analyze(pw)

            again = input(colored("  Analyze another password? [Y/n]: ", C.GRAY)).strip().lower()
            if again in ("n", "no", "q", "quit", "exit"):
                print("\n")
                print(colored("  Goodbye! Stay secure. 🔒", C.GREEN, C.BOLD))
                print("\n")
                break
            header()

        except KeyboardInterrupt:
            print("\n")
            print("\n")
            print(colored("  Goodbye! Stay secure. 🔒", C.GREEN, C.BOLD))
            print("\n")
            sys.exit(0)


if __name__ == "__main__":
    main()
