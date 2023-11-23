import socket
from utils import ethernet_head, arp_head
import threading
import json
import atexit
import os
import logging

dct = {}
lock = threading.Lock()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def update_dict(arp):
    with lock:
        sender_ip = arp[6]
        sender_mac = arp[5]

        if arp[4] == "ARP Request" or arp[4] == "ARP Reply":
            # Update the dictionary with the sender's IP and MAC address
            dct[sender_ip] = sender_mac

            # Check if the sender's IP already exists in the dictionary
            if sender_ip in dct and dct[sender_ip] != sender_mac:
                logger.warning(f"Possible ARP spoofing detected! IP: {sender_ip} is associated with multiple MAC addresses.")

def initiate_dict():
    try:
        with open("arp_dict.json", "r") as json_file:
            loaded_dict = json.load(json_file)
        return loaded_dict
    except FileNotFoundError:
        return {}
    except json.JSONDecodeError:
        logger.error("Error decoding JSON. Using an empty dictionary.")
        return {}

def save_dict_to_json():
    with lock:
        try:
            with open("arp_dict.json", "w") as json_file:
                json.dump(dct, json_file)
            logger.info("ARP dictionary saved to arp_dict.json.")
        except Exception as e:
            logger.error(f"Error saving dictionary to JSON: {e}")

def main():
    global dct
    try:
        if os.path.exists(f"{os.getcwd()}/arp_dict.json"):
            dct = initiate_dict()
            logger.info(f"Loaded ARP dictionary: {dct}")
        atexit.register(save_dict_to_json)
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        while True:
            raw_data, addr = s.recvfrom(65535)
            eth = ethernet_head(raw_data)
            if eth[2] == 1544:  # ARP
                arp = arp_head(eth[3])
                logger.debug('\t - ARP Packet:')
                logger.debug('\t\t - Hardware Type: {}, Protocol Type: {}'.format(arp[0], arp[1]))
                logger.debug('\t\t - Hardware Size: {}, Protocol Size: {}'.format(arp[2], arp[3]))
                logger.debug('\t\t - Operation: {}'.format(arp[4]))
                logger.debug('\t\t - Sender MAC: {}, Sender IP: {}'.format(arp[5], arp[6]))
                logger.debug('\t\t - Target MAC: {}, Target IP: {}'.format(arp[7], arp[8]))

                threading.Thread(target=update_dict, args=(arp,)).start()

    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt: Exiting program.")
        save_dict_to_json()

if __name__ == "__main__":
    main()
