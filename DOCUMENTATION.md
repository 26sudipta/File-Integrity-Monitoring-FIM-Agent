# File Integrity Monitoring (FIM) Agent — Full Documentation

---

## WHAT is it?

A **File Integrity Monitor** is a security tool that watches over a folder of important files and raises an alarm the moment anything changes — a file is modified, a new file is sneaked in, or a file is deleted.

Think of it like a **seal on an envelope**. Before you send the envelope, you seal it. When it arrives, you check the seal. If the seal is broken or looks different, you know someone tampered with it. This tool does the exact same thing — but for files on a computer.

---

## WHY does it exist?

### The Problem it Solves

In the real world, attackers who break into a system don't just steal data — they also **modify files** to:
- Plant malware inside a trusted program
- Change configuration files to open backdoors
- Delete log files to hide their tracks

By the time a human notices something is wrong, the damage is done.

### Why FIM is the Solution

A FIM agent runs **before** and **after** any suspicious window. It takes a snapshot of every file's "fingerprint" when everything is known-good. Any time later, it re-checks those fingerprints. Even a single character change in a file produces a completely different fingerprint — so the agent catches it instantly.

This is used in real security tools like **Tripwire**, **OSSEC**, and **Wazuh**. This project is a simplified, educational version of the same concept.

---

## HOW does it work? (Step by Step)

The entire logic lives in one file: `fim_agent.py`. It is built in **4 modules**.

---

### Module 1 — Hashing (`calculate_sha256`)

**What is a hash?**
A hash is a mathematical function that takes any file (no matter how big) and produces a fixed-length string of letters and numbers. SHA256 always produces a 64-character string. The key property: **even one character change in the file produces a completely different 64-character string**.

Example:
```
"Hello"   → 185f8db32921bd46d35...
"hello"   → 2cf24dba5fb0a30e26e...  ← completely different!
```

**How the code does it:**

```python
def calculate_sha256(filepath: Path) -> str:
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as file:
        while chunk := file.read(4096):   # reads 4KB at a time
            hasher.update(chunk)
    return hasher.hexdigest()
```

- Opens the file in **binary mode** (`'rb'`) — works on every file type (text, image, exe, etc.)
- Reads it in **4KB chunks** — so even a 10GB file won't crash the program by loading into RAM all at once
- `hasher.update(chunk)` feeds each chunk into the SHA256 calculation
- `hexdigest()` returns the final 64-character fingerprint

---

### Module 2 — Baseline (`create_baseline` / `load_baseline`)

**What is the baseline?**
The baseline is the "known good" snapshot — a dictionary that maps every file's path to its hash, saved to a file called `baseline.json`.

**Creating the baseline:**

```python
def create_baseline(target_dir: Path):
    for filepath in target_dir.rglob('*'):   # walks ALL subfolders too
        if filepath.is_file():
            relative_path = str(filepath.relative_to(target_dir))
            file_hash = calculate_sha256(filepath)
            current_baseline[relative_path] = file_hash
    
    with open(BASELINE_FILENAME, 'w') as f:
        json.dump(current_baseline, f, indent=4)
```

- `rglob('*')` walks into subfolders recursively — no file gets missed
- Uses **relative paths** as keys (e.g., `test_config.txt` not `C:\Users\...\test_config.txt`) — this makes the baseline portable across Windows and Linux
- Saves everything into `baseline.json` in JSON format, which is human-readable

The saved `baseline.json` looks like this:
```json
{
    "test_config.txt": "3c4552375c53eb56f3c518a6a11daec7b5356ce622bfc97b3a0fa80fa1fdd997"
}
```

**Loading the baseline:**
`load_baseline()` simply reads that JSON file back into a Python dictionary. It handles two error cases: file not found (forgot to create baseline) and corrupted JSON.

---

### Module 3 — Monitoring (`check_integrity`)

This is the heart of the agent. It re-hashes every file and compares against the baseline to detect three types of incidents.

```python
def check_integrity(target_dir: Path, baseline: dict):
    incidents = { "modified": [], "added": [], "deleted": [] }
```

**Detection Logic:**

**1. Modified files** — file exists in both baseline and now, but hashes are different:
```python
if relative_path in baseline and current_hashes[relative_path] != baseline[relative_path]:
    incidents["modified"].append({ "file": ..., "baseline_hash": ..., "current_hash": ... })
```

**2. Added files** — file exists now but was NOT in the baseline (new file appeared):
```python
elif relative_path not in baseline:
    incidents["added"].append({ "file": ..., "current_hash": ... })
```

**3. Deleted files** — file was in the baseline but does NOT exist now:
```python
for path_in_baseline in baseline:
    if path_in_baseline not in current_hashes:
        incidents["deleted"].append({ "file": ..., "baseline_hash": ... })
```

The function returns the `incidents` dictionary for the next module to use.

---

### Module 4 — Reporting (`generate_forensic_report`)

If any incidents were found, this module writes a detailed JSON report to the `FIM_Incidents/` folder.

```python
timestamp_utc_aware = datetime.datetime.now(timezone.utc)
current_time = timestamp_utc_aware.strftime("%Y%m%d_%H%M%S")
report_filename = REPORT_DIR / f"Incident_{current_time}.json"
```

- Uses **UTC timezone** (not local time) — standard practice in security/forensics so reports from machines in different countries are always comparable
- Filename includes timestamp so multiple incidents are never overwritten: `Incident_20251124_070632.json`

The report looks like this:
```json
{
    "report_id": "INCIDENT-20251124_070632",
    "timestamp_utc": "2025-11-24T07:06:32.925143+00:00",
    "system_os": "Windows FIM Agent (Simulated)",
    "total_breaches": 1,
    "breach_details": {
        "modified": [
            {
                "file": "test_config.txt",
                "baseline_hash": "3c4552375c53...",
                "current_hash":  "26366b736ee6..."
            }
        ],
        "added": [],
        "deleted": []
    }
}
```

---

### Execution Flow (`__main__`)

When you run the script, this is the exact sequence:

```
python3 fim_agent.py --create-baseline
```
1. If `target_files/` doesn't exist → creates it with a sample file
2. Calls `create_baseline(TARGET_DIR)` → saves `baseline.json`

```
python3 fim_agent.py --monitor
```
1. If `target_files/` doesn't exist → creates it with a sample file
2. Calls `load_baseline()` → loads `baseline.json` into memory
3. Calls `check_integrity()` → compares current state vs baseline, returns incidents
4. If incidents > 0 → calls `generate_forensic_report()` → saves JSON report to `FIM_Incidents/`

---

## Complete Data Flow Diagram

```
[target_files/]          [baseline.json]
      |                        |
      | rglob all files        | load saved hashes
      v                        v
[calculate_sha256()]    [load_baseline()]
      |                        |
      +----------+-------------+
                 |
                 v
        [check_integrity()]
         compares hash by hash
                 |
         +-------+-------+
         |       |       |
      modified  added  deleted
         |       |       |
         +-------+-------+
                 |
        [generate_forensic_report()]
                 |
                 v
    [FIM_Incidents/Incident_TIMESTAMP.json]
```

---

## How to Run & Demonstrate

### Prerequisites
- Python 3.8 or higher installed
- A terminal / command prompt open in the project folder

---

### STEP 1 — First-Time Setup (Run the agent once to create the target folder)

```bash
python3 fim_agent.py --create-baseline
```

**What happens:**
- Since `target_files/` doesn't exist yet, it auto-creates it with one file: `test_config.txt`
- It then hashes that file and saves the fingerprint to `baseline.json`

**Expected output:**
```
[SETUP] Created initial test files in target_files
[*] Starting baseline creation for: target_files
    [+] Hashed test_config.txt

[SUCCESS] Baseline saved to baseline.json
```

**What got created:**
```
project/
├── fim_agent.py
├── baseline.json          ← NEW: stores the "known good" fingerprints
└── target_files/
    └── test_config.txt    ← NEW: the file being monitored
```

---

### STEP 2 — Verify Everything is Clean (No incidents)

```bash
python3 fim_agent.py --monitor
```

**Expected output:**
```
[INFO] Starting Monitoring Mode...

[*] Starting Integrity Check...
[SUCCESS] No integrity breaches detected.
```

Nothing changed, so no report is generated. This is the "all clear" state.

---

### STEP 3 — Simulate Attack 1: MODIFY a file

Open `target_files/test_config.txt` and change its content, OR run:

```bash
echo "Attacker's change made here." >> target_files/test_config.txt
```

Now run the monitor:

```bash
python3 fim_agent.py --monitor
```

**Expected output:**
```
[INFO] Starting Monitoring Mode...

[*] Starting Integrity Check...

[ALERT] Integrity Breaches Detected: 1 Total!

[REPORT] Forensic Report Generated Successfully!
         Location: /your/path/FIM_Incidents/Incident_20251124_070632.json
--------------------------------------------------
```

**What the report contains:**
```json
{
    "report_id": "INCIDENT-20251124_070632",
    "timestamp_utc": "2025-11-24T07:06:32.925143+00:00",
    "total_breaches": 1,
    "breach_details": {
        "modified": [
            {
                "file": "test_config.txt",
                "baseline_hash": "3c4552375c53eb56...",
                "current_hash":  "26366b736ee6e3c2..."
            }
        ],
        "added": [],
        "deleted": []
    }
}
```

---

### STEP 4 — Simulate Attack 2: ADD a new file

```bash
echo "I am a malicious script." > target_files/malware.exe
```

Run the monitor:

```bash
python3 fim_agent.py --monitor
```

**Expected output:**
```
[ALERT] Integrity Breaches Detected: 1 Total!
```

The report will show `malware.exe` under `"added"` — it wasn't there when the baseline was taken.

---

### STEP 5 — Simulate Attack 3: DELETE a file

```bash
rm target_files/test_config.txt
```

Run the monitor:

```bash
python3 fim_agent.py --monitor
```

**Expected output:**
```
[ALERT] Integrity Breaches Detected: 1 Total!
```

The report will show `test_config.txt` under `"deleted"` — it existed in the baseline but is now gone.

---

### STEP 6 — Reset and Start Fresh

After your demonstration, to reset everything back to a clean state:

```bash
# Remove all generated files
rm -rf target_files/ baseline.json FIM_Incidents/

# Re-run to start fresh
python3 fim_agent.py --create-baseline
```

---

### Full Demo Cheat Sheet

| Command | What it does |
|---|---|
| `python3 fim_agent.py --create-baseline` | Take a snapshot of all files |
| `python3 fim_agent.py --monitor` | Check for changes since snapshot |
| `echo "x" >> target_files/test_config.txt` | Simulate a file modification |
| `echo "x" > target_files/newfile.txt` | Simulate a file being added |
| `rm target_files/test_config.txt` | Simulate a file being deleted |
| `rm -rf target_files/ baseline.json FIM_Incidents/` | Full reset |

---

## Key Concepts Summary

| Concept | What it means here |
|---|---|
| SHA256 Hash | A unique 64-char fingerprint of a file's contents |
| Baseline | The saved "known good" state of all file hashes |
| Integrity Check | Re-hash everything and compare to baseline |
| Incident | Any file that was modified, added, or deleted |
| Forensic Report | A timestamped JSON record of every incident found |
