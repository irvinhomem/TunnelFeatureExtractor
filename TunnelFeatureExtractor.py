from scapy.all import *

from MetaPacketCap import MetaPacketCap
from CapLibrary import CapLibrary

import logging

class TunnelFeatureExtractor(object):

    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.WARNING)
        self.logger.debug("Testing debug message")
        #print("Passed logging message")



featureExt = TunnelFeatureExtractor()