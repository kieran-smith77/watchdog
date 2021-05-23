#! /usr/bin/env python

from __future__ import absolute_import, division, print_function
import logging
import scapy.config
import scapy.layers.l2
import scapy.all
import socket
import math
import errno
import getopt
import time
import datetime
import pickle
import slack
import os
import csv
import config

logging.basicConfig(format='%(asctime)s %(levelname)-5s %(message)s', datefmt='%Y-%m-%d %H:%M:%S', level=logging.DEBUG)
logger = logging.getLogger(__name__)


def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        logger.warning("%s is too big. skipping" % net)
        return None
    print(net)
    return net


def scan_and_print_neighbors(net, interface, timeout=5):
    devices = {}
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    try:
        ans, unans = scapy.layers.l2.arping(net, iface=interface, timeout=timeout, verbose=False)
        for s, r in ans.res:
            device = r.sprintf("%Ether.src%")
            addr = r.sprintf("%ARP.psrc%")
            devices[device] = {'address': addr,'datetime': now}
    except socket.error as e:
        if e.errno == errno.EPERM:     # Operation not permitted
            logger.error("%s. Did you run as root?", e.strerror)
        else:
            raise
    return devices


def remove_old_data(devices):
    'Filters out all devices older than 1 month'
    max_age = datetime.datetime.today()
    for device in devices:
        time_since_insertion = (datetime.datetime.now() - datetime.datetime.strptime(devices[device]['datetime'], '%Y-%m-%d %H:%M')).days
        if time_since_insertion > 30:
            del devices[device]
    return devices


def alert(msg):
    # Send Email
    if config.get('slack.token') and config.get('slack.channel'):
        slack_message = """{}\n{}\n{}""".format(
            config.get('slack.message.header'),
            msg,
            config.get('slack.message.footer'))
        slack.send_alert(slack_message)
    else:
        logger.warning("No slack bot token. System is unable to send messages to slack")


def get_data():
    try:
        devices = pickle.load(open("devices.p", "rb"))
        devices = remove_old_data(devices)
    except FileNotFoundError:
        devices = {}
    return devices


def store_data(records):
    pickle.dump( records, open( "devices.p", "wb" ) )


def check_controlled_device(device):
    device=device.upper()
    with open('controlled_devices.csv') as f:
        csv_list = [[val.strip() for val in r.split(",")] for r in f.readlines()]
    (_, *header), *data = csv_list
    devices = {}
    for row in data:
        key, *values = row
        devices[key] = {key: value for key, value in zip(header, values)}
    if device in devices:
        return devices[device]
    return None


def nmap_pp(output, mac):
    message = "NEW DEVICE DETECTED\nDevice IP: {}\nDevice MAC: {}\n".format(output['addresses']['ipv4'],mac)

    if len(output['hostnames']) > 1:
        message += "Hostnames:\n"
        for hostname in output['hostnames']:
            message += str("\t", hostname['name'],"\n")
    elif len(output['hostnames']) == 1:
        if output['hostnames'][0]['name']:
            message += "Hostname: {}\n".format(output['hostnames'][0]['name'])

    if output['vendor']:
        for nic in output['vendor']:
            message += "Vendor: {}\n".format(output['vendor'][nic])

    if 'tcp' in output:
        ports = []
        for port in output['tcp']:
            if output['tcp'][port]['state'] == 'open':
                ports.append(str(port))
        message += "Open Ports: {}\n".format(', '.join(ports))

    if len(output['osmatch']) == 1:
        message += "OS: {}\n".format(output['osmatch'][0]['name'])
    elif len(output['osmatch']) > 1:
        message += "Possible OS's:\n"
        for os in output['osmatch']:
            message += "\t{} ({}%)\n".format(os['name'],os['accuracy'])
    return message


def scan(address, mac):
    import nmap
    nm = nmap.PortScanner()
    output = nm.scan(address, arguments='-O')
    if not address in output['scan']:
            output['scan'] = {address: {'addresses': {'ipv4': address}, 'hostnames':[],'vendor':[], 'osmatch':[]}}
    results = nmap_pp(output['scan'][address], mac)
    return results


def process_results(devices):
    records = get_data()
    if records: live = True
    else: live = False
    for device in devices:
        if device in records:
            if devices[device]['address'] == records[device]['address']:
                records[device]['datetime'] = devices[device]['datetime']
                continue
            else:
                # Device has changed IP
                controlled_device = check_controlled_device(device)
                if controlled_device:
                    if devices[device]['address'] != controlled_device['Address']:
                        msg = '''
The device {} has a changed IP.\n
The new IP address is {}\n
But it should be {}.\n
The MAC address is {}'''.format(controlled_device['Name'], devices[device]['address'], controlled_device['Address'], device.upper())
                        alert(msg = msg)
                records[device]['address'] = devices[device]['address']
                records[device]['datetime'] = devices[device]['datetime']
                continue
        else:
            # New Device
            if live:
                logger.info("New Device")
                details = scan(devices[device]['address'], device)
                alert(msg = details)
            records[device] = devices[device]
            continue
    store_data(records)


def main(net=None, interface=None):
    if os.geteuid() != 0:
        exit("You need to have root privileges to run this script.\nPlease try again, this time using 'sudo'.")

    if net and interface:
        devices = {}
        for _ in range(1):
            devices.update(scan_and_print_neighbors(net, interface))
            time.sleep(1)
    process_results(devices)


if __name__ == "__main__":
    interface = config.get('network.interface')
    net = config.get('network.CIDR')
    main(net,interface)
