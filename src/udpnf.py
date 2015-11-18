import argparse
import json
from types import *


def print_use():
    print "Usage: udpnf.py [-h] path/to/file.t [destination_site]"
    print "UDP packets producer with Scapy"
    print "  Positional arguments:"
    print "    path/to/file.t    Config json file of the UPD packet"
    print "    destination site  destination site."
    print "  Optional arguments:"
    print "    -h, --help        show this help message and exit"


def generate_udp(conf_dic):
    pass


def send_packet_udp_to(udp_packet, destination):
    pass


def main():
    parser = argparse.ArgumentParser(description='UDP packets producer with scapy')
    parser.add_argument('filename_conf', nargs='?',
                        metavar='path/to/file.t',
                        help='Config json file of the UPD packet')
    parser.add_argument('destination', nargs='?',
                        metavar='destination site',
                        help='destination site.')
    args = parser.parse_args()

    if args.filename_conf and args.destination:
        try:
            template_file = open(args.filename_conf)
        except EOFError:
            print "Cannot open json config file %s" % (args.filename_conf)
            return
    else:
        print_use()
        return

    print "Destination site: %s" % (args.destination)

    json_dic = {}
    json_dic = json.load(template_file)
    template_file.close()

    udp_packet = generate_udp(json_dic)

    # send the packet to 'destination site'
    send_packet_udp_to(udp_packet, args.destination)

if __name__ == '__main__':
    main()
