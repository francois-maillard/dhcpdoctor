import argparse
import binascii
import sys
import threading
import time
from random import randint

from scapy.all import (
    BOOTP,
    DHCP,
    DHCP6,
    DUID_LL,
    IP,
    UDP,
    AnsweringMachine,
    DHCP6_Advertise,
    DHCP6_RelayForward,
    DHCP6_Request,
    DHCP6_Reply,
    DHCP6_Solicit,
    DHCP6OptClientId,
    DHCP6OptClientFQDN,
    DHCP6OptServerId,
    DHCP6OptElapsedTime,
    DHCP6OptIA_NA,
    DHCP6OptIAAddress,
    DHCP6OptRelayMsg,
    Ether,
    IPv6,
    conf,
    get_if_addr,
    get_if_addr6,
    get_if_hwaddr,
    get_if_raw_hwaddr,
    send,
    sendp,
    sniff,
)

from dhcpdoctor import settings

__version__ = '1.0.0'

OK = 0
WARNING = 1
CRITICAL = 2
UNKNOWN = 3


def mac_str_to_bytes(mac):
    """Converts string representation of a MAC address to bytes
    
    Args:
        mac (str): String representation of a MAC address. Can contain
            colones, dots and dashes which will be stripped.
    
    Raises:
        TypeError: if a given mac is not a sting

    Returns:
        (bytes): MAC address in bytes form
    """
    if isinstance(mac, bytes):
        return mac
    if not isinstance(mac, str):
        raise TypeError('MAC address given must be a string')
    mac = mac.replace(':', '').replace('-', '').replace('.', '')
    return binascii.unhexlify(mac)


def sniffer(dhcp_client):
    """Starts scapy sniffer and stops when a timeout is reached or a valid packet
        is received.
    
    Args:
        dhcp_client (DHCPClient): Instance of DHCPClient class that implements
            `is_matching_reply` method
    """

    def show_packet(x):
        if settings.DEBUG:
            x.summary()

    sniff(
        prn=show_packet,
        timeout=settings.TIMEOUT,
        stop_filter=dhcp_client.is_matching_reply,
    )


class DHCPClient:
    def __init__(self):
        self.xid = randint(0, (2 ** 24) - 1)  # BOOTP 4 bytes, DHCPv6 3 bytes
        self.request = None
        self.reply = None
        self.dhcp_discover = None
        self.dhcp_offer = None
        self.dhcp_request = None
        self.dhcp_ack = None
        self.sniffer = None
        self.offered_address = None
        self.hostname = None
        self.server_id = None

    def craft_request(self, dhcp_type='discover', *args, **kwargs):
        if dhcp_type == 'discover':
            self.dhcp_discover = self.craft_discover(*args, **kwargs)
            self.request = self.dhcp_discover
        elif dhcp_type == 'request':
            self.dhcp_request = self.craft_dhcp_request(*args, **kwargs)
            self.request = self.dhcp_request

        if settings.RELAY_MODE:
            self.add_relay(
                self.request, settings.SERVER_ADDRESS, settings.RELAY_ADDRESS
            )
        if settings.DEBUG:
            print(self.request.show())
        return self.request

    def craft_discover(self, hw=None):
        raise NotImplementedError

    def craft_dhcp_request(self, hw=None):
        raise NotImplementedError

    def add_relay(self, p, srv_ip, relay_ip=None):
        raise NotImplementedError

    def send(self):
        if settings.RELAY_MODE:
            # sending unicast, let scapy handle ethernet
            send(self.request, verbose=settings.DEBUG)
        else:
            # sending to local link, need to set Ethernet ourselves
            sendp(
                Ether(dst=self._get_ether_dst()) / self.request, verbose=settings.DEBUG
            )

    def sniff_start(self):
        """Starts listening for packets in a new thread"""
        self.sniffer = threading.Thread(target=sniffer, args=[self])
        self.sniffer.start()

    def sniff_stop(self):
        """Waits for sniffer thread to finish"""
        self.sniffer.join()

    def is_matching_reply(self, reply):
        """Checks that we got reply packet

        Called for each packet captured by sniffer.
        
        Args:
            reply (scapy.packet.Packet): Packet received by sniffer
        
        Returns:
            bool: True if packet matches
        """
        is_offer = self.is_offer_type(reply)
        is_ack = self.is_ack_type(reply)

        if is_offer or is_ack:
            self.reply = reply
            if settings.DEBUG:
                print(reply.show())

            if is_offer:
                self.dhcp_offer = self.reply
            elif is_ack:
                self.dhcp_ack = self.reply

            self.offered_address = self.get_offered_address()
            self.hostname = self.get_hostname()
            self.server_id = self.get_server_id()
            return True
        return False

    def is_offer_type(self, packet):
        raise NotImplementedError

    def is_ack_type(self, packet):
        raise NotImplementedError

    def get_offered_address(self):
        raise NotImplementedError

    def get_hostname(self):
        raise NotImplementedError

    def get_server_id(self):
        raise NotImplementedError

    def _get_ether_dst(self):
        raise NotImplementedError


class DHCPv4Client(DHCPClient):
    MAC_BROADCAST = 'FF:FF:FF:FF:FF:FF'

    def craft_discover(self, hw=None):
        """Generates a DHCPDICSOVER packet
        
        Args:
            hw (str|bytes, optional): Defaults to MAC of Scapy's `conf.iface`.
                Client MAC address to place in `chaddr`.
        
        Returns:
            scapy.layers.inet.IP: DHCPDISCOVER packet
        """

        if not hw:
            _, hw = get_if_raw_hwaddr(conf.iface)
        else:
            hw = mac_str_to_bytes(hw)
        dhcp_discover = (
            IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=hw, xid=self.xid, flags=0x8000)
            / DHCP(options=[("message-type", "discover"), "end"])
        )
        # TODO: param req list
        if settings.DEBUG:
            print(dhcp_discover.show())
        return dhcp_discover

    def craft_dhcp_request(self, hw=None):
        """Generates a DHCPREQUEST packet
        
        Args:
            hw (str|bytes, optional): Defaults to MAC of Scapy's `conf.iface`.
                Client MAC address to place in `chaddr`.
        
        Returns:
            scapy.layers.inet.IP: DHCPREQUEST packet

        https://www.freesoft.org/CIE/RFC/2131/24.htm
        """

        if not hw:
            _, hw = get_if_raw_hwaddr(conf.iface)
        else:
            hw = mac_str_to_bytes(hw)

        # server identifier => DHCP server that sent the DHCPOFFER
        # Client inserts the address of the selected server in 'server
        # identifier', 'ciaddr' MUST be zero, 'requested IP address' MUST be
        # filled in with the yiaddr value from the chosen DHCPOFFER. 
        options = [
            ("message-type", "request"),
            ("server_id", self.server_id),
            ("requested_addr", self.offered_address),
            "end"
        ]
        dhcp_request = (
            IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(sport=68, dport=67)
            / BOOTP(chaddr=hw, xid=self.xid, flags=0x8000)
            / DHCP(options=options)
        )
        # TODO: param req list
        if settings.DEBUG:
            print(dhcp_request.show())
        return dhcp_request

    def add_relay(self, p, srv_ip, relay_ip=None):
        """Modify passed DHCP client packet as if a DHCP relay would
        
        Add giaddr, update UDP src port and set IP dest address.
        
        Args:
            p (scapy.packet.Packet): DHCP client packet
            srv_ip (str): IP address of server to relay to
            relay_ip (str, optional): Defaults to dhcpdoctor's IP. IP address of relay.
        """

        if not relay_ip:
            relay_ip = get_if_addr(conf.iface)
        p[BOOTP].giaddr = relay_ip
        p[BOOTP].flags = 0  # unset broadcast flag
        p[UDP].sport = 67
        p[IP].src = relay_ip
        p[IP].dst = srv_ip
        if settings.DEBUG:
            print(p.show())

    def is_offer_type(self, packet):
        """Checks that packet is a valid DHCPOFFER(2)
        Args:
            reply (scapy.packet.Packet): Packet to check
        
        Returns:
            bool: True if packet matches
        """
        return self.is_specific_type(packet, 2)

    def is_ack_type(self, packet):
        """Checks that packet is a valid DHCPACK(5)
        Args:
            reply (scapy.packet.Packet): Packet to check
        
        Returns:
            bool: True if packet matches
        """
        return self.is_specific_type(packet, 5)

    def is_specific_type(self, packet, dhcp_type):
        """Checks that packet is a valid DHCP message of type dhcp_type

        The following are checked:
        * packet contains BOOTP and DHCP layers
        * BOOTP xid matches request
        * DHCP message-type must match dhcp_type

        Args:
            reply (scapy.packet.Packet): Packet to check
            dhcp_type: the DHCP message-type

        Returns:
            bool: True if packet matches
        """
        if not packet.haslayer(BOOTP):
            return False
        if packet[BOOTP].op != 2:
            return False
        if packet[BOOTP].xid != self.xid:
            return False
        if not packet.haslayer(DHCP):
            return False
        req_type = [x[1] for x in packet[DHCP].options if x[0] == 'message-type'][0]
        if req_type in [dhcp_type]:
            return True
        return False

    def get_offered_address(self):
        return self.reply[BOOTP].yiaddr

    def _get_option(self, key):
        must_decode = ['hostname', 'domain', 'vendor_class_id']
        try:
            for i in self.reply[DHCP].options:
                if i[0] == key:
                    # If DHCP Server Returned multiple name servers
                    # return all as comma seperated string.
                    if key == 'name_server' and len(i) > 2:
                        return ",".join(i[1:])
                    # domain and hostname are binary strings,
                    # decode to unicode string before returning
                    elif key in must_decode:
                        return i[1].decode()
                    else:
                        return i[1]
        except Exception as e:
            print(e)
            return None

    def get_hostname(self):
        return self._get_option('hostname')

    def get_server_id(self):
        return self._get_option('server_id')

    def _get_ether_dst(self):
        return self.MAC_BROADCAST


class DHCPv6Client(DHCPClient):
    MAC_MCAST = '33:33:00:00:00:02'

    def craft_discover(self, hw=None):
        """Generates a DHCPv6 Solicit packet
        
        Args:
            hw (str|bytes, optional): Defaults to MAC of Scapy's `conf.iface`.
                Client MAC address to use for DUID LL.
        
        Returns:
            scapy.layers.inet.IPv6: DHCPv6 Solicit packet
        """
        if not hw:
            _, hw = get_if_raw_hwaddr(conf.iface)
        else:
            hw = mac_str_to_bytes(hw)

        dhcp_solicit = (
            IPv6(dst="ff02::1:2")
            / UDP(sport=546, dport=547)
            / DHCP6_Solicit(trid=self.xid)
            / DHCP6OptElapsedTime()
            / DHCP6OptClientId(duid=DUID_LL(lladdr=hw))
            / DHCP6OptIA_NA(iaid=0)
        )
        if settings.DEBUG:
            print(dhcp_solicit.show())
        return dhcp_solicit

    def craft_dhcp_request(self, hw=None):
        """Generates a DHCPv6 Request packet
        
        Args:
            hw (str|bytes, optional): Defaults to MAC of Scapy's `conf.iface`.
                Client MAC address to use for DUID LL.
        
        Returns:
            scapy.layers.inet.IPv6: DHCPv6 Request packet
        """
        if not hw:
            _, hw = get_if_raw_hwaddr(conf.iface)
        else:
            hw = mac_str_to_bytes(hw)

        # TODO
        # Request Message
        # - sent by clients
        # - includes a server identifier option
        # - the content of Server Identifier option must match server's DUID
        # - includes a client identifier option
        # - must include an ORO Option (even with hints) p40
        # - can includes a reconfigure Accept option indicating whether or
        #   not the client is willing to accept Reconfigure messages from
        #   the server (p40)
        # - When the server receives a Request message via unicast from a
        # client to which the server has not sent a unicast option, the server
        # discards the Request message and responds with a Reply message
        # containing Status Code option with the value UseMulticast, a Server
        # Identifier Option containing the server's DUID, the client
        # Identifier option from the client message and no other option.
        dhcp_request = (
            IPv6(dst="ff02::1:2")
            / UDP(sport=546, dport=547)
            / DHCP6_Request(trid=self.xid)
            / DHCP6OptServerId(duid=self.server_id)
            / DHCP6OptElapsedTime()
            / DHCP6OptClientId(duid=DUID_LL(lladdr=hw))
            / DHCP6OptIA_NA(iaid=0)
        )
        if settings.DEBUG:
            print(dhcp_request.show())
        return dhcp_request

    def add_relay(self, p, srv_ip, relay_ip=None):
        """Modify passed DHCP client packet as if a DHCP relay would
        
        Encapsulate DHCPv6 request message into DHCPv6 RelayForward, update UDP
            src port and set IP dest address.
        
        Args:
            p (scapy.packet.Packet): DHCP client packet
            srv_ip (str): IPv6 address of server to relay to
            relay_ip (str, optional): Defaults to dhcpdoctor's IPv6. IPv6 address
                of relay.
        """
        if not relay_ip:
            relay_ip = get_if_addr6(conf.iface)

        # get payload of UDP to get whatever type of DHCPv6 request it is and
        # replace it with our relay data
        dhcp_request = p[UDP].payload
        assert isinstance(dhcp_request, DHCP6)
        p[UDP].remove_payload()
        p[UDP].add_payload(
            DHCP6_RelayForward(linkaddr=relay_ip, peeraddr=p[IPv6].src)
            / DHCP6OptRelayMsg(message=dhcp_request)
        )

        p[UDP].sport = 547
        p[IPv6].src = relay_ip
        p[IPv6].dst = srv_ip
        if settings.DEBUG:
            print(p.show())

    def is_offer_type(self, packet):
        """Checks that a packet is a valid DHCPv6 reply
        
        The following are checked:
        * packet contains DHCPv6 Advertise or Reply
        * Transaction ID matches request
        * packet contains IA_NA option
        
        Args:
            packet (scapy.packet.Packet): Packet to check
        
        Returns:
            bool: True if packet matches
        """

        if not packet.haslayer(DHCP6_Advertise):
            return False
        if packet[DHCP6_Advertise].trid != self.xid:
            return False
        if not packet.haslayer(DHCP6OptIA_NA):
            return False
        return True

    def is_ack_type(self, packet):
        if not packet.haslayer(DHCP6_Reply):
            return False
        if packet[DHCP6_Reply].trid != self.xid:
            return False
        if not packet.haslayer(DHCP6OptIA_NA):
            return False
        return True

    def get_offered_address(self):
        return self.reply[DHCP6OptIAAddress].addr

    def get_hostname(self):
        return self.reply[DHCP6OptClientFQDN].fqdn

    def get_server_id(self):
        return self.reply[DHCP6OptServerId].duid

    def _get_ether_dst(self):
        return self.MAC_MCAST


def run_test():
    """Runs test and exits with appropriate exit code"""

    # configure default scapy interface
    conf.iface = settings.IFACE or conf.iface

    if settings.PROTOCOL == 4:
        dhcp_client = DHCPv4Client()
    elif settings.PROTOCOL == 6:
        dhcp_client = DHCPv6Client()

    dhcp_client.craft_request(hw=settings.CLIENT_ID)
    dhcp_client.sniff_start()
    ts = time.time()
    dhcp_client.send()
    dhcp_client.sniff_stop()
    te = time.time()

    if dhcp_client.reply:
        print(
            'OK: got reply with address {} | response_time={:0.3f}s'.format(
                dhcp_client.offered_address, te - ts
            )
        )
        sys.exit(OK)
    else:
        print('CRITICAL: no reply received | response_time=U')
        sys.exit(CRITICAL)


def parse_cmd_args():
    """Parse command line arguments

    Sets settings accordingly.
    """
    parser = argparse.ArgumentParser(
        description='Tool for testing IPv4 and IPv6 DHCP services'
    )
    parser.add_argument(
        '-V', '--version', action='version', version='%(prog)s {}'.format(__version__)
    )
    parser.add_argument('-d', dest='DEBUG', action='store_true', help='debugging mode')
    proto_group = parser.add_mutually_exclusive_group()
    proto_group.add_argument(
        '-4', dest='PROTOCOL', action='store_const', const=4, help='IPv4 mode'
    )
    proto_group.add_argument(
        '-6', dest='PROTOCOL', action='store_const', const=6, help='IPv6 mode'
    )
    parser.add_argument(
        '-i',
        '--interface',
        dest='IFACE',
        type=str,
        required=False,
        help='interface to send requests via',
    )
    parser.add_argument(
        '-c',
        '--client-id',
        dest='CLIENT_ID',
        type=str,
        required=False,
        help='MAC address or DUID of client to send in request. Defaults to MAC address of interface requests are sent from.',
    )
    parser.add_argument(
        '-r',
        '--relay',
        dest='SERVER_ADDRESS',
        type=str,
        required=False,
        help='send requests to specified server instead of broadcasting them on the local network',
    )
    parser.add_argument(
        '-f',
        '--relay-from',
        dest='RELAY_ADDRESS',
        type=str,
        required=False,
        help='send relayed requests from specified address. Defaults to address of the interface requests are sent from.',
    )
    parser.add_argument(
        '--timeout',
        dest='TIMEOUT',
        type=int,
        required=False,
        help='Time to wait for response from server before giving up.',
    )
    parser.set_defaults(
        PROTOCOL=settings.PROTOCOL,
        TIMEOUT=settings.TIMEOUT,
        CLIENT_ID=settings.CLIENT_ID,
    )
    args = parser.parse_args()
    # argument validation
    if args.RELAY_ADDRESS and not args.SERVER_ADDRESS:
        parser.error(
            'The --relay-from [-f] argument can only be used with --relay [-r] argument.'
        )
    settings.DEBUG = args.DEBUG
    settings.IFACE = args.IFACE
    settings.CLIENT_ID = args.CLIENT_ID
    settings.TIMEOUT = args.TIMEOUT
    settings.PROTOCOL = args.PROTOCOL
    if args.SERVER_ADDRESS:
        settings.RELAY_MODE = True
        settings.SERVER_ADDRESS = args.SERVER_ADDRESS
        if args.RELAY_ADDRESS:
            settings.RELAY_ADDRESS = args.RELAY_ADDRESS


def main():
    parse_cmd_args()
    run_test()


if __name__ == "__main__":
    main()
