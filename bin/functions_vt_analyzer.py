#!/usr/bin/python
__description__ = "Analyze mime encoded files to extract malicious data"
__author__="Gita Ziabari"
__version__="0.0.1"
__date__="04/24/2017"

"""
Source code put in Fidelis GitHub by Gita Ziabari, no Copyright
Use at your own risk
"""

import os, sys, re
import json

sys.path.append("../src/")
from config_file import *


def get_report_all_info(md5):
    import requests
    report_dict = {}
    params = {'resource': md5, 'apikey': vt_key, 'allinfo': 1}
    try:
       response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
       data = {"response_code":0}
       status = response.status_code
       if status !=200:
          return None, None
       response_json = response.json()
       positive = response_json["positives"]
       paramalink = response_json["permalink"]
    except: 
       return None, None
    return positive, paramalink

if __name__ == "__main__":
   pos, param = get_report_all_info("23b3aa7dcbb6f8525c112eb2a5e4dbb8")
   print pos, param
