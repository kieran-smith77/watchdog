# Watchdog
Watchdog is a network monitoring tool to raise alerts when new devices are detected on the network.

It uses ARP to identify all devices on the network and records their current state. When a new device appears on the network, a slack message is sent to a predefined  


# Global installation

The following packages are required for the system to run:

* **scapy** (for the ARP scan)
* **python-nmap** (for the OS detection and host scanning)
* **slack-sdk** (for sending the slack messages)

To download the code, use these commands:
```bash
git clone https://github.com/kieran-smith77/Watchdog.git
cd Watchdog
```

To configure a new environment and installed the required packages, use these commands:
```bash
python3 -m venv venv/
source venv/bin/activate
pip3 install -r requirements.txt
```


After installing requirements, the program can be run by simply using the following commands:
```bash
SLACK_BOT_TOKEN='xoxb-...'
python3 main.py -i [interface] -n [network-address]
```

# Usage

At the moment, these options are implemented:

**-n network**: Specify the network CIDR address to be scanned.

**-i interface**: Specify the interface which should be used to scan the network.


# Disclaimer
This program is purely for research purposes and should not be relied upon in a production environment... Or any environment.
To be honest, you probably shouldn't even consider deploying this in your network. It might work in theory but I literally made this in a day, so there's probably a million bugs I haven't identified.

# Todo

* Email: setup alerts to be sent over email in addition to Slack
