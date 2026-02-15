import requests
import json
import sys

BASE_URL = "http://localhost:8000/api/v1"
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASS = "admin123"

def debug_scan_creation():
    # 1. Login
    print(f"[-] Logging in as {ADMIN_EMAIL}...")
    try:
        resp = requests.post(f"{BASE_URL}/login/access-token", data={
            "username": ADMIN_EMAIL,
            "password": ADMIN_PASS
        })
    except Exception as e:
        print(f"[!] Login connection failed: {e}")
        return

    if resp.status_code != 200:
        print(f"[!] Login failed: {resp.text}")
        return
        
    token = resp.json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    print("[+] Login successful.")

    # 2. Test Scan Creation with minimal payload
    print("[-] Testing Scan Creation (POST /scans/)...")
    payload = {
        "target_url": "http://localhost:8000",
        "spec_url": "http://localhost:8000/api/v1/openapi.json",
        "config": {}
    }
    
    try:
        resp = requests.post(f"{BASE_URL}/scans/", json=payload, headers=headers)
        print(f"[-] Response Status: {resp.status_code}")
        print(f"[-] Response Body: {resp.text}")
        
        if resp.status_code == 200:
            print("[+] Scan creation SUCCESS")
        else:
            print("[!] Scan creation FAILED")
            
    except Exception as e:
        print(f"[!] Request exception: {e}")

if __name__ == "__main__":
    debug_scan_creation()