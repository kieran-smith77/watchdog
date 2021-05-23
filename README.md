# Watchdog
Watchdog is a network monitoring tool to raise alerts when new devices are detected on the network.

It uses ARP to identify all devices on the network and records their current state. When a new device appears on the network, a slack message is sent to a predefined  


# Installation and Configuration

The following packages are required for the system to run:

* **scapy** (for the ARP scan)
* **python-nmap** (for the OS detection and host scanning)
* **slack-sdk** (for sending the slack messages)
* **yaml** (for interpreting the config file)

To download the code, use these commands:
```bash
git clone https://github.com/kieran-smith77/watchdog.git
cd watchdog
```

To  install the required packages, use these commands:
```bash
sudo pip3 install -r requirements.txt
```

The next step is to configure the options by editing the config file. Copy the below code into a file called `config.yml` and edit the values as needed (network details can be found by using the command `ip r` on a Linux system):
```yaml
network:
  interface: "eth0"
  CIDR: "192.168.1.0/24"
slack:
  token: "xoxb-111-222-xxxxx"
  channel: "#general"
  message:
    header: ""
    footer: ""
```

After installing requirements and configuring the `config.yml` file, the program can be run by simply using the following command:
```bash
sudo python3 main.py
```

# Usage

The program is designed to be run by a CRON job for the root user on a regular period. The below code can be used to add the program to the root user's crontab:

```bash
cd ..
mv watchdog /usr/local/sbin/
(crontab -l ; echo "*/10 * * * * /usr/local/sbin/watchdog/main.py") | sudo crontab -
```

  


# Disclaimer
This program is purely for research purposes and should not be relied upon in a production environment... Or any environment.
To be honest, you probably shouldn't even consider deploying this in your network. It might work in theory but I literally made this in a day, so there's probably a million bugs I haven't identified.

# Todo

* Tidy up: The current state of the code is poor. I need to spend some time tidying up and making it more easy to understand.
* Email: In addition to slack notifactions, I want to add email alerts for users who dont have/want slack.
* Slack response: As a second part to this, I want to add a response to the slack bot. This way, I can issue commands for the bot to take actions to protect the network from suspicious devices.