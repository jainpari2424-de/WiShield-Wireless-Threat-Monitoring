import requests

data = {
    "ip_address": "192.168.31.100",
    "mac_address": "AA:BB:CC:DD:EE:01"
}

response = requests.post(
    "http://127.0.0.1:5000/device",
    json=data
)

print(response.status_code)
print(response.json())