import os
from .external_scanner import ExternalScanner
from .tool_checker import is_tool_available
import logging
import sys


class SnmpcheckScanner(ExternalScanner):
    NAME = 'snmp-check'

    def __init__(self, host, port, service, target_directory):
        self.host = host
        self.log_file_name = f'{port}_{service}_{self.NAME}.log'
        self.target_directory = target_directory

        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.setLevel(logging.INFO)
        stream_handler = logging.StreamHandler(sys.stdout)
        stream_handler.setLevel(logging.INFO)
        stream_handler.setFormatter(logging.Formatter('[%(asctime)s] - %(levelname)s - %(message)s'))
        self.logger.addHandler(stream_handler)

    def call(self):
        if not is_tool_available(self.NAME):
            return

        self.logger.info(f'Started {self.NAME} scan...')
        output = os.popen(f'{self.NAME} {self.host}').read()
        with open(f'{self.target_directory}/{self.log_file_name}', 'w+') as log_file:
            log_file.write(output)
        self.logger.info(f'Finished {self.NAME} scan...')
