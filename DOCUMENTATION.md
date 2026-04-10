# Password Strength Checker — Technical Documentation

## Table of Contents

1. [Project Overview](#1-project-overview)
2. [File Structure](#2-file-structure)
3. [Dependencies](#3-dependencies)
4. [Constants & Global Data](#4-constants--global-data)
5. [Class: C](#5-class-c)
6. [UI Helper Functions](#6-ui-helper-functions)
7. [Analysis Functions](#7-analysis-functions)
8. [Scoring & Classification](#8-scoring--classification)
9. [Report & Display Functions](#9-report--display-functions)
10. [Entry Point](#10-entry-point)
11. [Scoring Reference Table](#11-scoring-reference-table)
12. [Entropy Reference Table](#12-entropy-reference-table)
13. [Known Limitations](#13-known-limitations)
14. [Extending the Tool](#14-extending-the-tool)

---

## 1. Project Overview

`password_checker.py` is a single-file, zero-dependency Python 3 command-line tool that performs a comprehensive security analysis on a given password. It evaluates the password across multiple dimensions — character composition, entropy, vulnerability patterns, and commonness — then produces a color-coded terminal report with a numeric score, security checks, statistics, and improvement suggestions.

**Key design decisions:**

- All logic lives in one file for easy portability.
- No third-party libraries. Only `math`, `sys`, `re`, `os`, and `getpass` from the standard library are used.
- Input is hidden via `getpass` to prevent shoulder surfing.
- The tool supports both interactive and argument-based modes to allow scripting.

---

## 2. File Structure

```
password_checker.py
│
├── class C                     — ANSI color/style constants
├── colored()                   — Applies ANSI codes to a string
├── clear()                     — Clears the terminal screen
│
├── COMMON_PASSWORDS            — Set of known breached passwords
├── KEYBOARD_WALKS              — List of common keyboard row sequences
│
├── Analysis Functions
│   ├── check_length()
│   ├── check_uppercase()
│   ├── check_lowercase()
│   ├── check_digits()
│   ├── check_special()
│   ├── find_repeated_chars()
│   ├── has_sequential()
│   ├── has_keyboard_walk()
│   ├── is_common()
│   ├── unique_ratio()
│   ├── calculate_entropy()
│   ├── entropy_label()
│   ├── estimate_crack_time()
│   ├── score_password()
│   ├── classify()
│   └── get_suggestions()
│
├── UI Helper Functions
│   ├── TERM_WIDTH              — Terminal width constant
│   ├── hr()
│   ├── header()
│   ├── strength_bar()
│   ├── check_row()
│   └── section()
│
├── Report Function
│   ├── analyze()
│   └── _pool_desc()
│
└── main()                      — Entry point
```

---

## 3. Dependencies

| Module | Purpose |
|--------|---------|
| `math` | `math.log2()` for entropy calculation |
| `sys` | `sys.argv` for CLI arguments, `sys.exit()` for clean exit |
| `re` | Regular expressions for character class detection |
| `os` | `os.system()` for screen clear, `os.get_terminal_size()` for width |
| `getpass` | Hidden password input that doesn't echo to the terminal |

---

## 4. Constants & Global Data

### `COMMON_PASSWORDS`

```python
COMMON_PASSWORDS = { "password", "123456", ... }
```

A Python `set` of lowercase strings representing the most commonly used and breached passwords. Sets are used (not lists) because membership checks — `x in set` — are O(1) constant time regardless of size, making lookups instant even if the set is large.

All checks are done with `.lower()` normalization so "PASSWORD" and "Password" are both caught.

To load from a file instead, replace this with:

```python
def load_common_passwords(filepath="common_passwords.txt"):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return {line.strip().lower() for line in f if line.strip()}
    except FileNotFoundError:
        return set()

COMMON_PASSWORDS = load_common_passwords()
```

### `KEYBOARD_WALKS`

```python
KEYBOARD_WALKS = ["qwerty", "asdfgh", "zxcvbn", ...]
```

A list of common keyboard row sequences and diagonal patterns. The detection function checks for any 4-character substring from this list appearing inside the password.

---

## 5. Class: C

```python
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ...
```

A namespace class (not instantiated) that holds ANSI escape code constants. These codes are inserted into strings to change the color and style of text when printed to a terminal that supports ANSI.

| Constant | Effect |
|----------|--------|
| `RESET` | Clears all active formatting |
| `BOLD` | Bold text |
| `DIM` | Dimmed/faint text |
| `RED` | Bright red foreground |
| `YELLOW` | Bright yellow foreground |
| `GREEN` | Bright green foreground |
| `CYAN` | Bright cyan foreground |
| `GRAY` | Dark gray foreground |
| `WHITE` | Bright white foreground |
| `BG_*` | Background color variants (defined but available for future use) |

---

## 6. UI Helper Functions

### `colored(text, *codes)`

```python
def colored(text, *codes):
    return "".join(codes) + str(text) + C.RESET
```

Wraps a string with one or more ANSI codes and appends a reset code at the end. Multiple codes can be stacked (e.g., bold + red).

**Parameters:**
- `text` — The string to style
- `*codes` — One or more ANSI code strings from class `C`

**Returns:** A styled string ready for `print()`

**Example:**
```python
print(colored("Error!", C.RED, C.BOLD))
```

---

### `clear()`

```python
def clear():
    os.system("cls" if os.name == "nt" else "clear")
```

Clears the terminal screen. Uses `cls` on Windows (`os.name == "nt"`) and `clear` on macOS/Linux.

---

### `TERM_WIDTH`

```python
try:
    TERM_WIDTH = min(os.get_terminal_size().columns, 72)
except OSError:
    TERM_WIDTH = 72
```

A module-level constant that stores the terminal width, capped at 72 characters for readability. The `try/except OSError` handles environments where no real terminal is attached (e.g., IDEs, piped stdout on Windows), which would otherwise raise `WinError 6`.

---

### `hr(char="─")`

```python
def hr(char="─"):
    print(colored(char * TERM_WIDTH, C.GRAY))
```

Prints a horizontal rule (divider line) using the given character repeated across the terminal width. Uses `═` for section borders and `─` for inner dividers.

---

### `header()`

```python
def header():
    clear()
    hr("═")
    print(colored("  🔐  PASSWORD STRENGTH CHECKER", C.BOLD, C.WHITE))
    print(colored("  Analyze vulnerabilities · entropy ...", C.GRAY))
    hr("═")
```

Clears the screen and prints the tool's title banner. Called at startup and between analyses.

---

### `strength_bar(score, width=40)`

```python
def strength_bar(score, width=40):
    label, color = classify(score)
    filled = round(score / 100 * width)
    bar    = "█" * filled + "░" * (width - filled)
    print(f"  Strength  {colored(bar, color)}  ...")
```

Renders an ASCII progress bar representing the password score visually.

**Parameters:**
- `score` — Integer 0–100
- `width` — Total bar width in characters (default 40)

The bar fills proportionally: `filled = round(score / 100 * width)`. Filled positions use `█`, empty positions use `░`. The bar color matches the strength classification (red/yellow/green/cyan).

---

### `check_row(ok, label, detail="")`

```python
def check_row(ok, label, detail=""):
    icon = colored("✔", C.GREEN) if ok else colored("✘", C.RED)
    ...
```

Prints a single security check result row with a pass/fail icon, label, and optional detail string.

**Parameters:**
- `ok` — Boolean, whether the check passed
- `label` — Name of the check
- `detail` — Additional context shown in gray

---

### `section(title)`

```python
def section(title):
    print()
    print(colored(f"  {title}", C.BOLD, C.CYAN))
    hr()
```

Prints a bold cyan section heading followed by a horizontal rule. Used to separate Statistics, Security Checks, and Suggestions sections.

---

## 7. Analysis Functions

### `check_length(pw)`

**Returns:** `(bool, str)` — pass/fail and a human-readable message

Evaluates password length against these thresholds:

| Length | Result |
|--------|--------|
| < 8 | Fail — Too short |
| 8–11 | Pass — Acceptable |
| 12–15 | Pass — Good |
| 16+ | Pass — Excellent |

---

### `check_uppercase(pw)` / `check_lowercase(pw)` / `check_digits(pw)` / `check_special(pw)`

Each uses a regex search to detect the presence of its character class:

| Function | Regex | Character class |
|----------|-------|----------------|
| `check_uppercase` | `[A-Z]` | Capital letters |
| `check_lowercase` | `[a-z]` | Lowercase letters |
| `check_digits` | `[0-9]` | Numeric digits |
| `check_special` | `[^A-Za-z0-9]` | Anything not alphanumeric |

**Returns:** `(bool, str)`

---

### `find_repeated_chars(pw)`

```python
def find_repeated_chars(pw):
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
```

Detects runs of the same character appearing 3 or more times consecutively (e.g., `aaa`, `1111`).

Uses a two-pointer sliding approach: outer pointer `i` marks the start of a run, inner pointer `j` advances while the character matches. If the run length (`j - i`) is 3 or more, it is recorded.

**Returns:** A list of `(char, count)` tuples, e.g., `[('a', 4), ('1', 3)]`

---

### `has_sequential(pw)`

```python
def has_sequential(pw):
    v = pw.lower()
    for i in range(len(v) - 2):
        a, b, c = ord(v[i]), ord(v[i+1]), ord(v[i+2])
        if b - a == 1 and c - b == 1:  # ascending
            return True
        if a - b == 1 and b - c == 1:  # descending
            return True
    return False
```

Detects three or more consecutive characters in ascending or descending ASCII order. This catches patterns like `abc`, `xyz`, `123`, `321`, `nop`, etc.

Works by comparing the ASCII values (`ord()`) of every three adjacent characters. Both forward (`abc`) and reverse (`cba`) sequences are detected.

**Returns:** `bool`

---

### `has_keyboard_walk(pw)`

```python
def has_keyboard_walk(pw):
    v = pw.lower()
    for walk in KEYBOARD_WALKS:
        if walk[:4] in v:
            return True, walk[:4]
    return False, None
```

Checks whether any 4-character prefix of a known keyboard walk pattern appears in the password (case-insensitive). The threshold of 4 characters avoids false positives from short common words.

**Returns:** `(bool, str|None)` — match status and the matched pattern prefix if found

---

### `is_common(pw)`

```python
def is_common(pw):
    return pw.lower() in COMMON_PASSWORDS
```

Performs a constant-time O(1) set lookup to check if the lowercased password exists in the `COMMON_PASSWORDS` set.

**Returns:** `bool`

---

### `unique_ratio(pw)`

```python
def unique_ratio(pw):
    if not pw:
        return 0.0
    return len(set(pw)) / len(pw)
```

Calculates the ratio of unique characters to total characters. A ratio of 1.0 means every character is different; 0.5 means half are duplicates.

**Returns:** `float` between 0.0 and 1.0

---

### `calculate_entropy(pw)`

```python
def calculate_entropy(pw):
    pool = 0
    if re.search(r'[a-z]', pw): pool += 26
    if re.search(r'[A-Z]', pw): pool += 26
    if re.search(r'[0-9]', pw): pool += 10
    if re.search(r'[^A-Za-z0-9]', pw): pool += 32
    if ' ' in pw: pool += 1
    if pool == 0: pool = 26
    return len(pw) * math.log2(pool)
```

Calculates Shannon entropy using the formula:

```
entropy = length × log₂(pool_size)
```

The pool size is the number of possible characters that could appear at each position, determined by which character classes are present:

| Class present | Pool addition |
|---------------|--------------|
| Lowercase a–z | +26 |
| Uppercase A–Z | +26 |
| Digits 0–9 | +10 |
| Special characters | +32 |
| Space | +1 |

A higher pool size means more possible values per position, and longer passwords multiply that effect. Entropy is measured in bits — each additional bit doubles the number of guesses required to crack it.

**Returns:** `float` — entropy in bits

---

### `entropy_label(e)`

Maps an entropy value to a human-readable label with color coding:

| Entropy (bits) | Label |
|----------------|-------|
| < 28 | Extremely weak (red bold) |
| 28–39 | Very weak (red) |
| 40–59 | Weak (yellow) |
| 60–79 | Moderate (cyan) |
| 80–99 | Strong (green) |
| 100+ | Very strong (green bold) |

**Returns:** A pre-colored string

---

### `estimate_crack_time(entropy)`

```python
guesses_per_sec = 1e10
total_guesses   = 2 ** entropy
seconds         = total_guesses / guesses_per_sec / 2
```

Models an offline brute-force attack at 10 billion guesses per second (representative of a modern GPU hashcat attack on a fast hash like MD5). The `/2` accounts for the fact that on average the correct guess is found halfway through the search space.

The result in seconds is then converted to the largest applicable human-readable unit from seconds up to millennia.

**Returns:** `str` — e.g., `"3 hours"`, `"> 1 million years"`, `"Instantly"`

---

## 8. Scoring & Classification

### `score_password(pw)`

Computes a composite security score from 0 to 100 by gathering all analysis results and applying additive/subtractive rules:

**Positive contributions:**

| Condition | Points |
|-----------|--------|
| Length ≥ 8 | +10 |
| Length ≥ 12 | +15 |
| Length ≥ 16 | +10 |
| Has uppercase | +10 |
| Has lowercase | +10 |
| Has digits | +10 |
| Has special chars | +15 |
| Entropy ≥ 60 bits | +10 |
| Entropy ≥ 80 bits | +10 |
| Unique ratio ≥ 0.7 | +10 |

**Penalties:**

| Condition | Points |
|-----------|--------|
| Common password | −40 |
| Repeated chars found | −10 |
| Sequential pattern | −8 |
| Keyboard walk | −10 |

The final score is clamped with `max(0, min(100, score))` to prevent out-of-range values.

**Returns:** `int` in range 0–100

---

### `classify(score)`

Maps a score to a label and ANSI color code:

| Score | Label | Color |
|-------|-------|-------|
| 0–29 | WEAK | Red |
| 30–54 | FAIR | Yellow |
| 55–74 | GOOD | Green |
| 75–100 | STRONG | Cyan |

**Returns:** `(str, str)` — label and color code

---

### `get_suggestions(pw)`

Analyzes the password for every known weakness and builds an ordered list of improvement tips. Each tip is only added if the corresponding problem is detected, so suggestions are always specific to the password being analyzed.

The order of suggestions is intentional — most critical issues (common password, length) appear first.

**Returns:** `list[str]` — ordered list of suggestion strings. Returns a single "no issues" message if the password passes all checks.

---

## 9. Report & Display Functions

### `analyze(pw)`

The main orchestration function. Calls all analysis functions, assembles results, and prints the full terminal report in order:

1. Strength bar
2. Common password warning or confirmation
3. Statistics section (length, entropy, unique chars, pool, crack time)
4. Security checks section (nine check rows)
5. Suggestions section

**Parameters:**
- `pw` — The password string to analyze

**Returns:** Nothing (prints directly to stdout)

---

### `_pool_desc(pw)`

```python
def _pool_desc(pw):
    parts = []
    if re.search(r'[a-z]', pw): parts.append("a–z(26)")
    ...
    total = sum(int(p.split("(")[1].rstrip(")")) for p in parts)
    return f"{' + '.join(parts)} = {total}"
```

A private helper that builds a human-readable description of the character pool, e.g., `a–z(26) + A–Z(26) + 0–9(10) = 62`. Used only inside `analyze()` for the Statistics display.

**Returns:** `str`

---

## 10. Entry Point

### `main()`

The program's entry point. Handles two execution modes:

**Argument mode** — if a password is passed as `sys.argv[1]`, it is analyzed immediately and the program exits. Intended for scripting.

```bash
python password_checker.py "MyPassword123!"
```

**Interactive mode** — if no argument is given, the program enters a loop:
1. Prints the header
2. Prompts for a password using `getpass.getpass()` (hidden input)
3. Falls back to plain `input()` if `getpass` fails (some environments don't support it)
4. Calls `analyze()` with the entered password
5. Asks whether to analyze another password
6. Repeats or exits based on the response

`KeyboardInterrupt` (Ctrl+C) is caught at the loop level and exits cleanly with a goodbye message.

---

## 11. Scoring Reference Table

| Score | Classification | Typical characteristics |
|-------|---------------|------------------------|
| 0–10 | WEAK | Very short, common, or single character class |
| 11–29 | WEAK | Short, missing most character classes |
| 30–54 | FAIR | Moderate length, 2–3 character classes, some issues |
| 55–74 | GOOD | 12+ chars, most character classes, few issues |
| 75–100 | STRONG | 16+ chars, all character classes, high entropy, no patterns |

---

## 12. Entropy Reference Table

| Entropy | Crack time (10B/s) | Practical security |
|---------|-------------------|-------------------|
| < 28 bits | Milliseconds | None |
| 28–39 bits | Seconds to minutes | Extremely vulnerable |
| 40–59 bits | Hours to months | Weak against dedicated attack |
| 60–79 bits | Years to centuries | Moderate |
| 80–99 bits | Millions of years | Strong |
| 100+ bits | Astronomical | Very strong |

---

## 13. Known Limitations

- **No dictionary attack simulation** — the tool checks against exact matches in `COMMON_PASSWORDS`, not against words with substitutions like `p@ssw0rd` variants beyond those explicitly listed.
- **Entropy model is theoretical** — the calculation assumes a random uniform distribution across the character pool. Real passwords with predictable patterns have effectively lower entropy than the formula suggests.
- **Crack time assumes brute force** — real attackers use rule-based attacks and Markov models that can crack non-random passwords much faster than the theoretical time shown.
- **No unicode support** — characters outside ASCII are counted in the special character pool but edge cases may not be fully handled.
- **ANSI colors require a compatible terminal** — output may include raw escape codes in environments that don't support ANSI (e.g., older Windows CMD without VT mode enabled).

---

## 14. Extending the Tool

**Add a new check:**
1. Write an analysis function that returns `(bool, str)` or another appropriate type
2. Call it inside `analyze()` and display the result with `check_row()`
3. Add the corresponding penalty/bonus inside `score_password()`
4. Add a suggestion condition inside `get_suggestions()`

**Add file-based password list:**
Replace `COMMON_PASSWORDS` with `load_common_passwords("path/to/file.txt")` as shown in the README.

**Export results to JSON:**
Collect all analysis results inside `analyze()` into a dict and use `json.dump()` to write them to a file or print to stdout for use in pipelines.

**Batch mode:**
Modify `main()` to read passwords line by line from a file passed as a second argument, calling `analyze()` on each one.
