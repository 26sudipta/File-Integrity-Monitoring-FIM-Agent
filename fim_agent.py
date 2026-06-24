import hashlib
from pathlib import Path
import json
import sys
import time
import datetime
from datetime import timezone 

# --- Configuration ---
# NOTE: We use relative path here so it works on both Windows and Linux when testing.
TARGET_DIR = Path("target_files") 
BASELINE_FILENAME = "baseline.json"

# --- M O D U L E 1 : H A S H I N G ---

def calculate_sha256(filepath: Path) -> str:
    """Calculates the SHA256 hash of a file."""
    
    if not filepath.is_file():
        return ""
        
    hasher = hashlib.sha256()
    
    try:
        # Open the file in binary read mode ('rb')
        with open(filepath, 'rb') as file:
            # Read the file in chunks (4KB) to handle large files efficiently
            while chunk := file.read(4096):
                hasher.update(chunk)
        return hasher.hexdigest()
    except Exception as e:
        print(f"Error reading file {filepath}: {e}")
        return "ERROR"

# --- M O D U L E 2 : B A S E L I N E ---

def create_baseline(target_dir: Path):
    """
    Creates and saves the SHA256 baseline for all files in the target directory.
    """
    if not target_dir.is_dir():
        print(f"ERROR: Target directory '{target_dir}' does not exist.")
        return
        
    print(f"[*] Starting baseline creation for: {target_dir}")
    current_baseline = {}
    
    for filepath in target_dir.rglob('*'):
        if filepath.is_file():
            # Use relative path for cross-platform robustness
            relative_path = str(filepath.relative_to(target_dir))
            
            file_hash = calculate_sha256(filepath)
            
            current_baseline[relative_path] = file_hash
            print(f"    [+] Hashed {relative_path}")

    try:
        with open(BASELINE_FILENAME, 'w') as f:
            json.dump(current_baseline, f, indent=4)
        print(f"\n[SUCCESS] Baseline saved to {BASELINE_FILENAME}")
    except Exception as e:
        print(f"\n[ERROR] Could not save baseline file: {e}")

def load_baseline() -> dict:
    """
    Loads the baseline from the saved JSON file.
    """
    if not Path(BASELINE_FILENAME).exists():
        print(f"ERROR: Baseline file '{BASELINE_FILENAME}' not found. Please create a baseline first.")
        return {}
        
    try:
        with open(BASELINE_FILENAME, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        print(f"ERROR: Baseline file '{BASELINE_FILENAME}' is corrupted.")
        return {}

# --- M O D U L E 3 : M O N I T O R I N G ---

def check_integrity(target_dir: Path, baseline: dict):
    """
    Compares current file hashes against the loaded baseline to detect breaches.
    """
    
    current_hashes = {}
    incidents = {
        "modified": [],
        "added": [],
        "deleted": []
    }
    
    print("\n[*] Starting Integrity Check...")
    
    # 1. বর্তমান হ্যাশ তৈরি (Find Modification and Addition)
    for filepath in target_dir.rglob('*'):
        if filepath.is_file():
            relative_path = str(filepath.relative_to(target_dir))
            current_hashes[relative_path] = calculate_sha256(filepath)
            
            # 1a. Modification Check
            if relative_path in baseline and current_hashes[relative_path] != baseline[relative_path]:
                incidents["modified"].append({
                    "file": relative_path,
                    "baseline_hash": baseline[relative_path],
                    "current_hash": current_hashes[relative_path]
                })
                
            # 1b. Addition Check
            elif relative_path not in baseline:
                incidents["added"].append({
                    "file": relative_path,
                    "current_hash": current_hashes[relative_path]
                })

    # 2. Deletion Check
    for path_in_baseline in baseline:
        if path_in_baseline not in current_hashes:
            incidents["deleted"].append({
                "file": path_in_baseline,
                "baseline_hash": baseline[path_in_baseline]
            })

    # 3. সামারি প্রিন্ট করা
    total_incidents = sum(len(v) for v in incidents.values())
    if total_incidents == 0:
        print("[SUCCESS] No integrity breaches detected.")
    else:
        print(f"\n[ALERT] Integrity Breaches Detected: {total_incidents} Total!")
        
    return incidents

# --- M O D U L E 4 : R E P O R T I N G ---

def generate_forensic_report(incidents: dict):
    """
    Generates a detailed, timestamped JSON report for all detected incidents.
    """
    REPORT_DIR = Path("FIM_Incidents")
    if not REPORT_DIR.exists():
        REPORT_DIR.mkdir()
    
    # UTC TimeZone aware object ব্যবহার করা হয়েছে (Deprecation Warning দূর করার জন্য)
    timestamp_utc_aware = datetime.datetime.now(timezone.utc)
    
    current_time = timestamp_utc_aware.strftime("%Y%m%d_%H%M%S")
    report_filename = REPORT_DIR / f"Incident_{current_time}.json"
    
    report_data = {
        "report_id": f"INCIDENT-{current_time}",
        # ISO ফরম্যাটে time zone সহ সেভ করা হচ্ছে
        "timestamp_utc": timestamp_utc_aware.isoformat(), 
        "system_os": "Windows FIM Agent (Simulated)",
        "total_breaches": sum(len(v) for v in incidents.values()),
        "breach_details": incidents
    }

    try:
        with open(report_filename, 'w') as f:
            json.dump(report_data, f, indent=4)
        
        print(f"\n[REPORT] Forensic Report Generated Successfully!")
        print(f"         Location: {report_filename.resolve()}")
        print("-" * 50)
    except Exception as e:
        print(f"\n[ERROR] Could not save report: {e}")

# --- E X E C U T I O N ---

if __name__ == "__main__":
    
    # টার্গেট ফোল্ডার তৈরি ও ডামি ফাইল রাখুন
    if not TARGET_DIR.exists():
        TARGET_DIR.mkdir()
        (TARGET_DIR / "test_config.txt").write_text("This is the initial content.", encoding="utf-8")
        print(f"[SETUP] Created initial test files in {TARGET_DIR}")

    if len(sys.argv) > 1:
        if sys.argv[1] == '--create-baseline':
            create_baseline(TARGET_DIR)
        
        elif sys.argv[1] == '--monitor': 
            print("\n[INFO] Starting Monitoring Mode...")
            baseline_data = load_baseline()
            
            if baseline_data:
                # আউটপুট সেভ করুন (NameError ফিক্স করা হয়েছে)
                incidents = check_integrity(TARGET_DIR, baseline_data) 
                
                # রিপোর্ট তৈরি করুন 
                total_incidents = sum(len(v) for v in incidents.values())
                if total_incidents > 0:
                    generate_forensic_report(incidents) 
            
        else:
            print("\nUsage:")
            print("1. Create Baseline: python3 fim_agent.py --create-baseline")
            print("2. Monitor Files:   python3 fim_agent.py --monitor")
    else:
        print("\nUsage:")
        print("1. Create Baseline: python3 fim_agent.py --create-baseline")
        print("2. Monitor Files:   python3 fim_agent.py --monitor")