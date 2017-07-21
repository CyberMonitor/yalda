#!/usr/bin/python
__description__ = "Analyze mime encoded files to extract malicious data"
__author__="Gita Ziabari"
__version__="0.0.1"
__date__="04/24/2017"

"""
Source code put in Fidelis GitHub by Gita Ziabari, no Copyright
Use at your own risk
"""
import os, sys
import yara

sys.path.append("../src/")
from config_file import *
sys.path.append(bin_dir)
from functions_lib  import *


def run_yara_rules(file_path, yara_rules_dir):
    matched_tbl = {}
    rule_dict = build_file_path_tbl(yara_rules_dir)
    rules = yara.compile(filepaths=rule_dict)
    matches = rules.match(file_path)
    if len(matches) == 0:
       return matched_tbl
    matched_tbl[file_path] = matches
    return matched_tbl


def build_file_path_tbl(yara_rules_dir):
    rule_dict = {}
    for rule in os.listdir(yara_rules_dir):
        rand_key = get_random()
        rule_dict[rand_key] = yara_rules_dir+rule
    return rule_dict


if __name__ == "__main__":
   for file_name in os.listdir("/work/samples/pcap/VT_FILES_HTML15-7-2017/"):
       file_path = "/work/samples/pcap/VT_FILES_HTML15-7-2017/"+file_name
       print file_path
       matched = run_yara_rules(file_path, yara_rules_dir)
       print matched
