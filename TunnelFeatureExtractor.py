from scapy.all import *

from PcapFeatures import PcapFeatures
from CapLibrary import CapLibrary

import logging

class TunnelFeatureExtractor(object):

    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        # self.logger.setLevel(logging.INFO)
        # self.logger.setLevel(logging.WARNING)
        self.logger.debug("Testing debug message")
        #print("Passed logging message")

        self.capLib = CapLibrary()

        path_list = self.capLib.get_paths_from_specific_lib_in_pcap_base('HTTPovDNS')
        self.logger.debug('First Path: %s ' % str(path_list[0]).strip())
        pcap_feat = PcapFeatures(str(path_list[0]).strip(), 'HTTP')
        self.logger.debug("Packet Length List-len: %i" % len(pcap_feat.getDnsReqLens()))
        #pcap_feat.test_pkt_Reader()
        pcap_feat.doPlot(pcap_feat.getDnsReqLens(), 'r', 'DNS Req Entropy', 'Pkt #', 'Entropy')

        # for count, single_file_path in enumerate(self.capLib.get_paths_from_specific_lib_in_pcap_base('HTTPovDNS')):
        #     self.logger.debug("Pcap File Path #: %i" % count)
        #     pcap_feat = PcapFeatures(single_file_path, 'HTTPovDNS')
        #
        #     self.logger.debug("Req Len seq len: %i" % len(pcap_feat.getDnsPktEntropy()))
        #
        #     pcap_feat.doPlot(pcap_feat.getDnsReqLens(), 'r', 'DNS Req Entropy', 'Pkt #', 'Entropy')




featureExt = TunnelFeatureExtractor()