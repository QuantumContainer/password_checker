# 🔐 Password Strength Checker

A terminal-based password analysis tool written in Python. It checks your password for vulnerabilities, calculates entropy, estimates crack time, and gives you actionable suggestions to make it stronger — all from the command line with zero external dependencies.

---

## Features

- **Strength classification** — rates your password as Weak, Fair, Good, or Strong
- **Visual strength bar** — ASCII progress bar with color coding
- **Entropy calculation** — measures unpredictability in bits
- **Time to crack** — estimates crack time at 10 billion guesses per second (offline GPU attack)
- **Common password detection** — checks against a breached password list
- **Nine security checks** — length, uppercase, lowercase, digits, special characters, repeated characters, sequential patterns, keyboard walks, and character variety
- **Smart suggestions** — personalized tips based on exactly what your password is missing
- **Hidden input** — password is not shown on screen while typing
- **Interactive loop** — analyze multiple passwords in one session
- **CLI argument support** — pass a password directly for scripting

---

## Requirements

- Python 3.6 or higher
- No external libraries required — uses only the Python standard library

---

## Installation

No installation needed. Just download the file and run it.

```bash
# Clone or download the file, then run directly
python password_checker.py
```

---

## Usage

### Interactive mode

```bash
python password_checker.py
```

You will be prompted to enter a password. Input is hidden (not shown on screen). After the analysis, you can choose to analyze another password or quit.

### Command-line argument mode

```bash
python password_checker.py "YourPasswordHere"
```

Useful for scripting or piping into other tools. Note: passing passwords as arguments may expose them in shell history.

### Quit

Press `Ctrl+C` at any time, or type `n` when asked to analyze another password.

---

## Using a Custom Password List

By default, the tool checks against a built-in list of ~55 common passwords. To use your own list (recommended for better coverage), replace the `COMMON_PASSWORDS` set in the code with this:

```python
def load_common_passwords(filepath="common_passwords.txt"):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        print(colored(f"  ⚠  '{filepath}' not found — common password check disabled.", C.YELLOW))
        return set()

COMMON_PASSWORDS = load_common_passwords()
```

Then create `common_passwords.txt` in the same folder with one password per line.

**Recommended free wordlists:**
- [SecLists — Common Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials)
- [rockyou.txt](https://github.com/brannondorsey/naive-hashcat/releases) — 14 million breached passwords

---

## Output Explained

```
  Strength  ████████████████░░░░░░░░░░░░░░░░░░░░░░░░  62/100  GOOD

  ✓  Not found in common password list

  STATISTICS
  ────────────────────────────────────────────────────────────
  Length           12  chars
  Entropy          71.5  bits  → Moderate
  Unique chars     10/12  (83% unique)
  Character pool   a–z(26) + A–Z(26) + 0–9(10) = 62
  Time to crack    > 1,000 years  at 10 billion guesses/sec

  SECURITY CHECKS
  ────────────────────────────────────────────────────────────
  ✔  Length               12 chars — good
  ✔  Uppercase letters    A–Z present
  ✔  Lowercase letters    a–z present
  ✔  Numbers              0–9 present
  ✘  Special characters   none found
  ✔  No repeated chars
  ✔  No sequential patterns
  ✔  No keyboard walks
  ✔  Good character variety  83% unique

  SUGGESTIONS
  ────────────────────────────────────────────────────────────
  1. Add special characters such as !, @, #, $, %, ^, &, *.
```

---

## Scoring System

The score (0–100) is calculated by adding points for good properties and subtracting for bad ones:

| Condition | Points |
|-----------|--------|
| Length ≥ 8 | +10 |
| Length ≥ 12 | +15 |
| Length ≥ 16 | +10 |
| Has uppercase | +10 |
| Has lowercase | +10 |
| Has digits | +10 |
| Has special characters | +15 |
| Entropy ≥ 60 bits | +10 |
| Entropy ≥ 80 bits | +10 |
| Unique ratio ≥ 70% | +10 |
| Common password | −40 |
| Repeated characters | −10 |
| Sequential pattern | −8 |
| Keyboard walk | −10 |

| Score Range | Label |
|-------------|-------|
| 0–29 | WEAK |
| 30–54 | FAIR |
| 55–74 | GOOD |
| 75–100 | STRONG |

---

## Platform Notes

- Works on Windows, macOS, and Linux
- ANSI color codes are supported in most modern terminals (Windows Terminal, PowerShell, CMD with VT enabled, all Unix terminals)
- If running inside an IDE like VS Code or PyCharm, colors may not render — use an external terminal for the best experience

---

## License

MIT — free to use, modify, and distribute.
