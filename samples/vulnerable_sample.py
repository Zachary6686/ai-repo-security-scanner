import os
import pickle
import yaml


def run(cmd):
    os.system(cmd)


def load_data(data):
    return pickle.loads(data)


def parse_yaml(text):
    return yaml.load(text)


def unsafe_eval(x):
    eval(x)

