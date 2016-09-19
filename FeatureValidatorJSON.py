import os
import json
import logging

class FeatureValidatorJSON(object):

    def __init__(self):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        # self.logger.setLevel(logging.INFO)
        # self.logger.setLevel(logging.WARNING)
        self.logger.debug("Testing debug message")

        self.all_json_objs = None

    def validate_JSON_Aggr_documents(self, protoLabel, featureName):
        feature_base_path = str(os.getcwd() + '/' + 'feature_base/JSON/' + protoLabel + '/' +
                                featureName + '/' + featureName + '.json')
        self.logger.debug('Feature Base path: %s' % feature_base_path)

        json_objs = None
        with open(feature_base_path) as json_data_file:
            try:
                json_objs = json.load(json_data_file)
                self.logger.debug("JSON Obj filename: %s" % json_objs[0]['filename'])
                self.logger.debug("JSON Obj filename: %s" % json_objs[1]['filename'])
            except json.decoder.JSONDecodeError as err:     # A sub-class of ValueError
                self.logger.debug('Error: %s' % (str(err)))
                self.logger.debug('Error: MSG: %s | Line #: %s | Col #: %s' % (str(err.msg), str(err.lineno), str(err.colno)))

        return json_objs


my_validator = FeatureValidatorJSON()

my_validator.validate_JSON_Aggr_documents('HTTPovDNS', 'DNS-Req-Lens')
my_validator.validate_JSON_Aggr_documents('HTTPovDNS', 'IP-Req-Lens')

