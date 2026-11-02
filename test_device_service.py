from device_service import save_device


ip_address = input("Enter IP address: ")
mac_address = input("Enter MAC address: ")

save_device(ip_address, mac_address)