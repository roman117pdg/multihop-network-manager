
import logging

def create_custome_logger(name):
    custome_logger = logging.getLogger(name)
    # start with default verbosity level
    custome_logger.setLevel(logging.NOTSET)       
    return custome_logger 


def enable_print_terminal(custome_logger):    
    """Enable printing to treminal."""
    stream_handler = logging.StreamHandler()
    stream_formatter = logging.Formatter(fmt='(%(asctime)s) [%(levelname)5s] - %(module)19s - %(funcName)19s() : %(message)s')
    stream_handler.setFormatter(stream_formatter)
    custome_logger.addHandler(stream_handler)
    return custome_logger


def enable_print_file(custome_logger):    
    """Enable printing to file "logger.log".""" 
    file_handler = logging.FileHandler('logger.log', 'w+')
    file_formatter = logging.Formatter(fmt='(%(asctime)s) [%(levelname)5s] - %(module)19s - %(threadName)-10s - %(funcName)19s() : %(message)s')
    file_handler.setFormatter(file_formatter)
    custome_logger.addHandler(file_handler)
    return custome_logger


