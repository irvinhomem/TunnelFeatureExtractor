from tkinter import filedialog
import pathlib
import logging

class MetaCapBase(object):

    def __init__(self, base_location=None):
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)

        self.packetBase = []
        self.base_loc = base_location

        if base_location is None:
            #Check for config file
            p = pathlib.Path('base_loc_config.conf')
            try:
                with p.open('r') as rf:
                    for line in rf:
                        self.base_loc = line
                        if self.base_loc == '':
                            self.base_loc == filedialog.askdirectory(initialdir='')
            except:
                self.logger.warning("base_loc_config does not exist. Create base_loc_config file")
                #If config file doesn't exist create it
                self.base_loc = filedialog.askdirectory(initialdir='')
                with p.open('a+') as f:
                    f.write(self.base_loc)
                    f.close()

    def add_lib_to_base(self, newMetaCapLib):
        self.packetBase.append(newMetaCapLib)

    def set_base_location(self, base_location):
        self.base_loc = base_location
        return

    def get_base_loc(self):
        return self.base_loc
