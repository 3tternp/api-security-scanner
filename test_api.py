import requests

try:
    print("Testing Login...")
    response = requests.post(
        "http://localhost:8001/api/v1/login/access-token",
        data={
            "username": "admin@example.com",
            "password": "admin123"
        }
    )
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    
    if response.status_code == 200:
        token = response.json()["access_token"]
        print("\nTesting Scans Endpoint...")
        scans_response = requests.get(
            "http://localhost:8001/api/v1/scans/",
            headers={"Authorization": f"Bearer {token}"}
        )
        print(f"Scans Status Code: {scans_response.status_code}")
        print(f"Scans Response: {scans_response.text}")

except Exception as e:
    print(f"Error: {e}")
