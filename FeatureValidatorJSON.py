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

    def validate_JSON_documents(self, protoLabel, featureName):
        feature_base_path = str(os.getcwd() + '/' + 'feature_base/JSON/' + protoLabel + '/' +
                                featureName + '/' + featureName + '.json')
        json_data_objs = []
        with open(feature_base_path) as json_data_file:
            #json_data = json.load(json_data_file)
            #for count, line in enumerate(json_data_file):
            for line in json_data_file:
                # self.logger.debug("Json line: %s " % str(line))
                # if count == 20: exit()
                single_json_obj = None
                while True:
                    try:
                        single_json_obj = json.loads(line)
                        break
                    except ValueError:
                        # Not yet a complete JSON  object
                        # self.logger.debug("Not yet complete object")
                        line += next(json_data_file)
                        #yield
                else:
                    self.logger.debug("JSON objs #: %i " % len(json_data_objs))
                    json_data_objs.append(single_json_obj)


        # self.logger.debug('Filename 0 : %s' % json_data[0]['filename'])
        self.logger.debug('Filename 0 : %s' % json_data_objs[0]['filename'])
        # self.logger.debug('Properties 0 Feature Name: %s' % json_data_objs[0]['props']['feature-name'])
        # self.logger.debug('Properties 1; first feature value : %s' % json_data_objs['props'][1]['values'][0])

my_validator = FeatureValidatorJSON()

my_validator.validate_JSON_documents('HTTPovDNS', 'DNS-Req-Lens')

