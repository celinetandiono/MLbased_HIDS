import os
import argparse
import json

def get_path(name):
    relative_path = os.path.join(os.path.dirname(__file__), name)
    absolute_path = os.path.abspath(relative_path)  
    return absolute_path

def initialize_parser():
    parser = argparse.ArgumentParser(description="Intialize argument parser for systemcall_tracer.py")
    parser.add_argument("-l", "--loglevel",type=str, choices=["DEBUG","INFO","WARNING","ERROR","CRITICAL"],help="Log level to show in Kibana. Default is INFO")
    return parser
    
def get_syscalls_mapping():  
    with open(get_path("../data/train_syscalls_map.json"), 'r') as file:
        syscalls_mapping = json.load(file)
    return syscalls_mapping