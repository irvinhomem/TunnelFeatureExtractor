from scapy.all import *

from PcapFeatures import PcapFeatures
from CapLibrary import CapLibrary

import logging
import errno
# import csv
import json

class TunnelFeatureExtractorJSON(object):

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

    def get_feature_vectors_and_write_to_file(self, protoLabel, featureName):
        # Check if directory exists (i.e. feature_base, and sub directory of HTTPovDNS / FTPovDNS)
        self.make_sure_path_exists("feature_base/JSON/" + protoLabel+ "/" + featureName)

        # curr_feature_filename = ""
        # # Check if file exists
        # if featureName == "DNS-Req-Lens":
        #     curr_feature_filename = "DNS_Layer_Req_Lengths.csv"
        # elif featureName == "IP-Req-Lens":
        #     curr_feature_filename = "IP_Layer_Req_Lengths.csv"
        # elif featureName == "DNS-Req-Qnames":
        #     curr_feature_filename = "DNS_Layer_Req_Query_names.csv"

        # curr_feature_filePath = "feature_base/JSON/" + protoLabel + "/" + curr_feature_filename
        # curr_feature_filePath = "feature_base/JSON/" + protoLabel + "/" + featureName + '/' + featureName + '.json'

        curr_pcap_file_name = 'Not yet set.'
        try:
            feature_vect_list = None
            json_obj_list = []
            for count, single_file_path in enumerate(self.capLib.get_paths_from_specific_lib_in_pcap_base(protoLabel)):
                self.logger.debug('-----------------------------')
                self.logger.debug("Pcap File Path #: %i" % count)
                curr_pcap_file_name = str(single_file_path).rsplit('/', 1)[1].strip()
                self.logger.debug("Current PCAP File name: %s" % curr_pcap_file_name)

                curr_feature_filePath = "feature_base/JSON/" + protoLabel + "/" + featureName + '/' + curr_pcap_file_name + '.json'
                pcap_feat = PcapFeatures(single_file_path, protoLabel)

                feature_dict_list = []
                #feature_dict = {}
                #Choose the Feature to be extracted
                # Get all features into one file
                # if featureName == "All":
                #     DNS_Req_Len_vect_list = pcap_feat.getDnsReqLens()
                #     IP_Req_Len_vect_list = pcap_feat.get_ip_pkt_lengths()

                # # Get only Specific Feature
                if featureName == "DNS-Req-Lens" or featureName == "All":
                    feature_vect_list = pcap_feat.getDnsReqLens()
                    self.logger.debug("DNS-Req-Lens #: %i" % len(feature_vect_list))
                    feature_dict_list.append({'feature_name': "DNS-Req-Lens", 'values': feature_vect_list})
                if featureName == "IP-Req-Lens" or featureName == "All":
                    #feature_vect_list = pcap_feat.test_pkt_Reader()
                    feature_vect_list = pcap_feat.get_ip_pkt_lengths()
                    self.logger.debug("IP-Req-Lens #: %i" % len(feature_vect_list))
                    feature_dict_list.append({'feature_name': "IP-Req-Lens", 'values': feature_vect_list})
                if featureName == "DNS-Req-Qnames-Enc-Comp-Hex" or featureName == "All":
                    feature_vect_list = pcap_feat.getDnsReqQnames_upstream()
                    self.logger.debug("DNS-Req-Qnames-Enc-Comp-Hex #: %i" % len(feature_vect_list))
                    feature_dict_list.append({'feature_name': "DNS-Req-Qnames-Enc-Comp-Hex", 'values': feature_vect_list})
                if featureName == "DNS-Req-Qnames-Enc-Comp-Entropy" or featureName == "All":
                    feature_vect_list = pcap_feat.getDnsReqQnameEntropy_upstream()
                    self.logger.debug("DNS-Req-Qnames-Enc-Comp-Entropy #: %i" % len(feature_vect_list))
                    feature_dict_list.append({'feature_name': "DNS-Req-Qnames-Enc-Comp-Entropy", 'values': feature_vect_list})
                if featureName == "DNS-Req-Qnames-Enc-Comp-Entropy-50-bytes" or featureName == "All":
                    feature_vect_list = pcap_feat.getDnsReqQnameEntropy_upstream_x_bytes(50)
                    self.logger.debug("DNS-Req-Qnames-Enc-Comp-Entropy-50-bytes #: %i" % len(feature_vect_list))
                    feature_dict_list.append({'feature_name': "DNS-Req-Qnames-Enc-Comp-Entropy-50-bytes", 'values': feature_vect_list})
                if featureName == "DNS-Req-Qnames-Enc-Comp-Entropy-20-bytes" or featureName == "All":
                    feature_vect_list = pcap_feat.getDnsReqQnameEntropy_upstream_x_bytes(20)
                    self.logger.debug("DNS-Req-Qnames-Enc-Comp-Entropy-20-bytes #: %i" % len(feature_vect_list))
                    feature_dict_list.append({'feature_name': "DNS-Req-Qnames-Enc-Comp-Entropy-20-bytes", 'values': feature_vect_list})
                # HTTP Related Features
                if featureName == "HTTP-Req-Bytes-Hex" or featureName == "All-HTTP":
                    feature_vect_list = pcap_feat.getHttpReqBytesHex()
                    self.logger.debug("HTTP-Req-Bytes-Hex #: %i" % len(feature_vect_list))
                    feature_dict_list.append({'feature_name': "HTTP-Req-Bytes-Hex", 'values': feature_vect_list})
                # FTP Related Features
                if featureName == "FTP-Req-Bytes-Hex" or featureName == "All-FTP":
                    feature_vect_list = pcap_feat.getFtpReqBytesHex()
                    self.logger.debug("FTP-Req-Bytes-Hex #: %i" % len(feature_vect_list))
                    feature_dict_list.append({'feature_name': "FTP-Req-Bytes-Hex", 'values': feature_vect_list})
                # HTTP-S Related Features
                if featureName == "HTTP-S-Req-Bytes-Hex" or featureName == "All-HTTP-S":
                    feature_vect_list = pcap_feat.getHttp_S_ReqBytesHex()
                    self.logger.debug("HTTP-S-Req-Bytes-Hex #: %i" % len(feature_vect_list))
                    feature_dict_list.append({'feature_name': "HTTP-S-Req-Bytes-Hex", 'values': feature_vect_list})
                # POP3 Related Features
                if featureName == "POP3-Req-Bytes-Hex" or featureName == "All-POP3":
                    feature_vect_list = pcap_feat.getPop3ReqBytesHex()
                    self.logger.debug("POP3-Req-Bytes-Hex #: %i" % len(feature_vect_list))
                    feature_dict_list.append({'feature_name': "POP3-Req-Bytes-Hex", 'values': feature_vect_list})


                self.logger.debug("Req Len seq len: %i" % len(feature_vect_list))
                self.logger.debug("Number of features being captured <feature_dict_list>: %i" % len(feature_dict_list))
                if len(feature_dict_list) > 0:
                    self.logger.debug("First Feature: %s" % feature_dict_list[0]['feature_name'])
                    # self.logger.debug("First Feature: %s" % feature_dict_list[0]['feature_name_1'])
                    #self.logger.debug("2nd Feature: %s" % feature_dict_list[1]['feature_name_2'])

                self.logger.debug("Populating feature vector from PCAP [%s]" % (curr_pcap_file_name))
                #Add PCAP file name as primary key (at the head of the list)
                # feature_vect_row = [pcapFilename] + feature_vect_list      #<==== Also works but stackoverflow says code below is faster
                #feature_vect_list.insert(0, curr_pcap_file_name)

                #vect_csv_writer = csv.writer(csv_feature_file, delimiter=',')

                # writerow takes a list i.e. []
                # vect_csv_writer.writerow(feature_vect_row)
                #vect_csv_writer.writerow(feature_vect_list)

                # if featureName == 'All':
                json_obj_str = {'filename': curr_pcap_file_name,
                                'pcap-Md5-hash': '',
                                'protocol': protoLabel,
                                'props': feature_dict_list}
                                # 'props': features_json_str}
                                # 'props': feature_dict_list} #features_json_str
                # else:
                #     json_obj_str = {'filename': curr_pcap_file_name,
                #                'pcap-Md5-hash': '',
                #                'protocol': protoLabel,
                #                'props': [{'feature-name': featureName,
                #                          'values': feature_vect_list}]}
                #     # Ideally for the values i'd need square brackets [], but since it's a list it is recognized

                with open(curr_feature_filePath, mode='w') as json_feature_file:
                    json.dump(json_obj_str, json_feature_file, indent=4, sort_keys=True)
                # # Add each json_obj_str from an individual pcap file into a list containing all specific features in json format
                # json_obj_list.append(json_obj_str)
                # # Encode the list into a single file containing features of each pcap (comma separated for each pcap)
                # json.dump(json_obj_list, json_feature_file, indent=4, sort_keys=True)

        except IOError:
            self.logger.debug("File IOError ... with: %s : %s" % (featureName, curr_pcap_file_name))

            #self.write_feature_vector_instance_to_file(feat_vect_seq, protoLabel, curr_pcap_file_name)
        # return feat_vect_seq


featureExt = TunnelFeatureExtractorJSON()
#featureExt.test_feature_extraction()

#featureExt.write_feature_vector_instance_to_file(featureExt.get_feature_vectors("HTTPovDNS"), "HTTPovDNS")

# featureExt.get_feature_vectors_and_write_to_file("HTTPovDNS", "DNS-Req-Lens")      # <---- Works
# featureExt.get_feature_vectors_and_write_to_file("HTTPovDNS", "IP-Req-Lens")       # <---- Works
# featureExt.get_feature_vectors_and_write_to_file("HTTPovDNS", "DNS-Req-Qnames-Enc-Comp-Hex")        # <---- Works
# featureExt.get_feature_vectors_and_write_to_file("HTTPovDNS", "All")      # <---- Works

#featureExt.get_feature_vectors_and_write_to_file("HTTP-Plain", "HTTP-Req-Bytes-Hex")
#featureExt.get_feature_vectors_and_write_to_file("HTTP-ovDNS-v-Plain-SIZE", "DNS-Req-Qnames-Enc-Comp-Hex")     # <---- Works

# featureExt.get_feature_vectors_and_write_to_file("HTTPovDNS-Static", "DNS-Req-Lens")      # <---- Works
# featureExt.get_feature_vectors_and_write_to_file("HTTPovDNS-Static", "IP-Req-Lens")       # <---- Works
# featureExt.get_feature_vectors_and_write_to_file("HTTPovDNS-Static", "DNS-Req-Qnames-Enc-Comp-Hex")        # <---- Works
# featureExt.get_feature_vectors_and_write_to_file("HTTPovDNS-Static", "All")      # <---- Works

# featureExt.get_feature_vectors_and_write_to_file("FTPovDNS-UL", "All")      # <---- Works
# featureExt.get_feature_vectors_and_write_to_file("FTPovDNS-DL", "All")      # <---- Works

# featureExt.get_feature_vectors_and_write_to_file("HTTP-S-ovDNS-Static", "All")      # <---- Works
# featureExt.get_feature_vectors_and_write_to_file("HTTP-S-ovDNS-Dyn", "All")      # <---- Works

# featureExt.get_feature_vectors_and_write_to_file("POP3ovDNS-DL", "All")      # <---- Works
# featureExt.get_feature_vectors_and_write_to_file("POP3ovDNS-DL-5-ATT", "All")      # <---- Works
# featureExt.get_feature_vectors_and_write_to_file("POP3ovDNS-DL-3emails-ATT", "All")      # <---- Works
# featureExt.get_feature_vectors_and_write_to_file("POP3ovDNS-DL-7emails-ATT", "All")      # <---- Works
# featureExt.get_feature_vectors_and_write_to_file("POP3ovDNS-DL-5txt-ATT", "All")      # <---- Works
featureExt.get_feature_vectors_and_write_to_file("POP3ovDNS-DL-Mixed", "All")      # <---- Works


# # Ground truths for old experiments (and their extensions with the new data set)
# # HTTP
#featureExt.get_feature_vectors_and_write_to_file("HTTP-ground", "HTTP-Req-Bytes-Hex")
# # FTP
# featureExt.get_feature_vectors_and_write_to_file("FTP-ground", "FTP-Req-Bytes-Hex")
# # HTTP-S
# featureExt.get_feature_vectors_and_write_to_file("HTTP-S-ground", "HTTP-S-Req-Bytes-Hex")
# # POP3
# featureExt.get_feature_vectors_and_write_to_file("POP3-ground", "POP3-Req-Bytes-Hex")

# Data set for old experiments
# # HTTP-ovDNS
# featureExt.get_feature_vectors_and_write_to_file("http-ovDNS-test2", "All")
# # FTP-ovDNS
# featureExt.get_feature_vectors_and_write_to_file("ftp-ovDNS-test-old", "All")