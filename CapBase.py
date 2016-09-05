from tkinter import filedialog
import pathlib
import logging
import os

class CapBase(object):

    def __init__(self, base_location=None):
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)
        #self.logger.setLevel(logging.INFO)
        self.logger.setLevel(logging.DEBUG)
        #self.logger.setLevel(logging.WARNING)

        self.packetBase = []
        self.base_loc = str(base_location).strip()

        #self.logger.debug("Testing logger debug message")
        #print("Logger Level: %s", str(self.logger.getEffectiveLevel()))

        if base_location is None:
            #Check for config file
            p = pathlib.Path('base_loc_config.conf')
            try:
                if os.stat(str(p)).st_size == 0:
                    self.logger.warning("base_loc_config file is empty")
                    self.base_loc == filedialog.askdirectory(initialdir='', title='Select Base Location home-dir')
                    with p.open('a+') as f:
                        f.write(self.base_loc)
                        f.close()
                else:
                    with p.open('r') as rf:
                        for line in rf:
                            self.base_loc = line
                            if self.base_loc == '':
                                self.base_loc == filedialog.askdirectory(initialdir='', title='Select Base Location home-dir')
                            else:
                                self.logger.debug("Loaded CapBase path: %s", self.base_loc)
                                # self.logger.info("test info")
                                # self.logger.warning("test warning")
                                #print('test')
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
        self.base_loc = str(base_location).strip()
        return

    def get_base_loc(self):
        return self.base_loc
