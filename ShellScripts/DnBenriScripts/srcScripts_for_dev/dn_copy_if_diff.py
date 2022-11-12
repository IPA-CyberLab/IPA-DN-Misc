import os
import json
import subprocess
import inspect
import sys
import time as systime
import argparse
import shutil

def IsSameFile(a: str, b: str):
    if not os.path.exists(a):
        return False

    if not os.path.exists(b):
        return False

    with open(a, mode='rb') as f:
        src_data = f.read()
    
    with open(b, mode='rb') as f:
        dst_data = f.read()
    
    if len(src_data) != len(dst_data):
        return False
    
    return src_data == dst_data

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("src", metavar="<src>", type=str, help="Source filename")
    parser.add_argument("-d", dest="dst", required=True,
                        type=str, help="Destination filename")

    args = parser.parse_args()
    src = args.src
    dst = args.dst

    try:
        isSame = IsSameFile(src, dst)
    except:
        isSame = False

    if not isSame:
        shutil.copyfile(src, dst)
    
    
    


