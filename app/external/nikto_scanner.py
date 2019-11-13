import os
from .external_scanner import ExternalScanner
from .tool_checker import is_tool_available
import logging
import sys


class NiktoScanner(ExternalScanner):
    NAME = 'nikto'

    def __init__(self, host, ports, service, target_directory):
        self.host = host
        self.ports = ','.join(list(map(str, ports)))
        self.log_file_name = f'{self.ports}_{service}_{self.NAME}.log'
        self.target_directory = target_directory

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setLevel(logging.INFO)
        stream_handler.setFormatter(logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s'))
        self.logger.addHandler(stream_handler)

    def call(self):
        if not is_tool_available(NiktoScanner.NAME):
            return

        self.logger.info(f'Started {self.NAME} scan...')
        output = os.popen(f'{self.NAME} -host {self.host} -p {self.ports}').read()
        with open(f'{self.target_directory}/{self.log_file_name}', 'w+') as log_file:
            log_file.write(output)
        self.logger.info(f'Finished {self.NAME} scan...')
