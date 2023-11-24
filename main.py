import socket
from utils import ethernet_head, arp_head
import threading
import json
import atexit
import os
import logging
from datetime import datetime, timedelta

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super(DateTimeEncoder, self).default(obj)

dct = {}
lock = threading.Lock()

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
ARP_REPLY_THRESHOLD = 5  
TIMEOUT_SECONDS = 60  # 5 minutes timeout

def update_dict(arp, our_ip):
    with lock:
        sender_ip = arp[6]
        sender_mac = arp[5]
        target_ip = arp[8]
        arp_operation = arp[4]

        # Check if the sender is not our own IP
        if sender_ip != our_ip:
            # Initialize or retrieve the entry for the sender IP
            entry = dct.setdefault(sender_ip, {"mac": sender_mac, "reply_count": 0, "last_reply_time": None})

            # Check if the target IP is our own IP
            if target_ip == our_ip:
                # Check if it's an ARP Reply
                if arp_operation == "ARP Reply":
                    # Increment the ARP reply count for the sender
                    entry["reply_count"] += 1

                    # Check if the last reply was received more than TIMEOUT_SECONDS ago
                    if entry["last_reply_time"] is None or (datetime.now() - entry["last_reply_time"]).total_seconds() > TIMEOUT_SECONDS:
                        entry["reply_count"] = 1
                    else:
                        entry["reply_count"] += 1

                    # Check if the reply count exceeds the threshold
                    if entry["reply_count"] > ARP_REPLY_THRESHOLD:
                        logger.warning(f"Possible ARP spoofing detected! Received {entry['reply_count']} ARP replies from IP: {sender_ip}.")

                    # Update the last reply time
                    entry["last_reply_time"] = datetime.now()

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # doesn't even have to be reachable
        s.connect(('10.255.255.255', 1))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

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
                json.dump(dct, json_file, cls=DateTimeEncoder)
            logger.info("ARP dictionary saved to arp_dict.json.")
        except Exception as e:
            logger.error(f"Error saving dictionary to JSON: {e}")

def main():
    global dct
    try:
        local_ip = get_local_ip()
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

                threading.Thread(target=update_dict, args=(arp, local_ip)).start()

    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt: Exiting program.")
        save_dict_to_json()

if __name__ == "__main__":
    main()
