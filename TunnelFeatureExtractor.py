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

    def make_sure_path_exists(self, path):
        try:
            os.makedirs(path)
            print("Path Created: ", path)
        except OSError as exception:
            if exception.errno != errno.EEXIST:
                raise

    def test_feature_extraction(self):
        # # Either: ==> Test first pcap
        path_list = self.capLib.get_paths_from_specific_lib_in_pcap_base('HTTPovDNS')
        self.logger.debug('First Path: %s ' % str(path_list[0]).strip())
        pcap_feat = PcapFeatures(str(path_list[2]).strip(), 'HTTP')
        lens_seq = pcap_feat.getDnsReqLens()
        self.logger.debug("Packet Length List-len: %i" % len(lens_seq))
        self.logger.debug("First Pkt Length: %i" % lens_seq[0])
        self.logger.debug("Second Pkt Length: %i" % lens_seq[1])
        #pcap_feat.test_pkt_Reader()
        pcap_feat.doPlot(lens_seq, 'red', 'DNS Req Entropy', 'Pkt #', 'Entropy')

        # # or: ==> Test multiple pcaps
        # for count, single_file_path in enumerate(self.capLib.get_paths_from_specific_lib_in_pcap_base('HTTPovDNS')):
        #     self.logger.debug("Pcap File Path #: %i" % count)
        #     pcap_feat = PcapFeatures(single_file_path, 'HTTPovDNS')
        #     lens_seq = pcap_feat.getDnsReqLens()
        #
        #     self.logger.debug("Req Len seq len: %i" % len(lens_seq))
        #
        #     pcap_feat.doPlot(lens_seq, 'r', 'DNS Req Entropy', 'Pkt #', 'Entropy')

    def get_feature_vectors(self, protocolLabel):
        feat_vect_seq = None
        for count, single_file_path in enumerate(self.capLib.get_paths_from_specific_lib_in_pcap_base(protocolLabel)):
            self.logger.debug("Pcap File Path #: %i" % count)
            pcap_feat = PcapFeatures(single_file_path, protocolLabel)
            feat_vect_seq = pcap_feat.getDnsReqLens()

            self.logger.debug("Req Len seq len: %i" % len(feat_vect_seq))
        return feat_vect_seq

    def write_feature_vector_instance_to_file(self, feature_vect_list, protocolLabel):
        # Check if directory exists (i.e. feature_base, and sub directory of HTTPovDNS / FTPovDNS)
        self.make_sure_path_exists("feature_base/" + protocolLabel)

        # Check if file exists

        # Write to file


featureExt = TunnelFeatureExtractor()
#featureExt.test_feature_extraction()

featureExt.write_feature_vector_instance_to_file(featureExt.get_feature_vectors("HTTPovDNS"), "HTTPovDNS")