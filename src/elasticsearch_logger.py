import logging
from elasticsearch import Elasticsearch
import os

class ElasticsearchLogger:
    def __init__(self, filename):
        uname = os.getenv("ES_UNAME")
        pwd = os.getenv("ES_PWD")

        self.es = Elasticsearch([f'http://{uname}:{pwd}@localhost:9200'])
        self.filename = filename
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        
        es_handler = self.ElasticsearchHandler(self.es, self.filename)  # Pass es to ElasticsearchHandler
        es_handler.setLevel(logging.INFO)
        
        formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        es_handler.setFormatter(formatter)
        
        self.logger.addHandler(es_handler)

    class ElasticsearchHandler(logging.Handler):
        def __init__(self, es, filename):
            super().__init__()
            self.es = es
            self.filename = filename

        def emit(self, record):
            log_entry = self.format(record)
            self.es.index(index='syscall_logs', body={'message': log_entry, 'filename':self.filename})

    def get_logger(self):
        return self.logger

