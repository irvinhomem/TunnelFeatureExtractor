from scapy.all import *

import logging

class TunnelFeatureExtractor(object):

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.logger.debug("Testing debug message")



featureExt = TunnelFeatureExtractor()