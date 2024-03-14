import logging
from elasticsearch import Elasticsearch
import os
from datetime import datetime

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
      
        self.logger.addHandler(es_handler)
        
    def set_log_level(self, log_level):
        self.logger.setLevel(log_level)

    class ElasticsearchHandler(logging.Handler):
        def __init__(self, es, filename):
            super().__init__()
            self.es = es
            self.filename = filename

        def emit(self, record):
            log_body = {
                '@timestamp': datetime.utcnow(),  # Store timestamp separately
                'level': record.levelname,  # Store logging level separately
                'message': record.getMessage(),  # Store log message separately
                'filename': self.filename  # Optionally store filename
            }
            self.es.index(index='syscall_logs', body=log_body)

    def get_logger(self):
        return self.logger

