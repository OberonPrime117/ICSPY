import requests
import argparse
  
print("[*] Welcome")
  
# Function to get the interface name
def get_arguments():
    
    # This will give user a neat CLI
    parser = argparse.ArgumentParser()
      
    # We need the MAC address
    parser.add_argument("-m", "--macaddress",
                        dest="mac_address",
                        help="MAC Address of the device. "
                        )
    options = parser.parse_args()
      
    # Check if address was given
    if options.mac_address:
        return options.mac_address
    else:
        parser.error("[!] Invalid Syntax. "
                     "Use --help for more details.")
  
  
def get_mac_details(mac_address):
      
    # We will use an API to get the vendor details
    url = "https://api.macvendors.com/"
      
    # Use get method to fetch details
    response = requests.get(url+mac_address)
    if response.status_code != 200:
        raise Exception("[!] Invalid MAC Address!")
    return response.content.decode()
  
# Driver Code
if __name__ == "__main__":
    mac_address = get_arguments()
    print("[+] Checking Details...")
      
    try:
        vendor_name = get_mac_details(mac_address)
        print("[+] Device vendor is "+vendor_name)
    except:
        
        # Incase something goes wrong
        print("[!] An error occured. Check "
              "your Internet connection.")