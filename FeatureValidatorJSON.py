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

    def recursive_read_json(self, feat_base_path):
        with open(feat_base_path) as json_data_file:
            try:
                single_json_obj = json.load(json_data_file)
                self.logger.debug("JSON Obj filename: %s" % single_json_obj['filename'])
            except json.decoder.JSONDecodeError as err:
                self.logger.debug('Error: %s' % (str(err)))
                self.logger.debug('Error: MSG: %s | Line #: %s | Col #: %s' % (str(err.msg), str(err.lineno), str(err.colno)))

    def validate_JSON_documents(self, protoLabel, featureName):
        feature_base_path = str(os.getcwd() + '/' + 'feature_base/JSON/' + protoLabel + '/' +
                                featureName + '/' + featureName + '.json')
        self.logger.debug('Feature Base path: %s' % feature_base_path)

        self.recursive_read_json(feature_base_path)






my_validator = FeatureValidatorJSON()

my_validator.validate_JSON_documents('HTTPovDNS', 'DNS-Req-Lens')

