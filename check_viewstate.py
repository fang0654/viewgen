#!/usr/bin/env python3

#from viewgen import ViewGen

import argparse
import pdb
import binascii
from urllib.parse import unquote
import importlib
import os
import sys

def import_path(path):
    module_name = os.path.basename(path).replace('-', '_')
    spec = importlib.util.spec_from_loader(
        module_name,
        importlib.machinery.SourceFileLoader(module_name, path)
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    sys.modules[module_name] = module
    return module

viewgen = import_path('viewgen')
ViewGen = viewgen.ViewGen

def parse_burp(fname, keys):

    import xmltodict
    from base64 import b64decode as bd
    

    for req in xmltodict.parse(open(fname).read())['items']['item']:
        url = req['url']
        resp = bd(req['response']['#text']).decode()

        if '__VIEWSTATEGENERATOR' in resp and '"__VIEWSTATE"' in resp:
            payload = unquote(resp.split('"__VIEWSTATE" value="')[1].split('"')[0])
            modifier = unquote(resp.split('"__VIEWSTATEGENERATOR" value="')[1].split('"')[0])

            res = check_payload(payload, modifier, keys)

            if res:
                print(f"Known key found at {url} ")
                print(f"{res[0]}:{res[1]} / {res[2]}:{res[3]}")

def check_url(url, keys, headers=None):
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    res = requests.get(url, headers=headers, verify=False)
    
    resp = res.text

    if '__VIEWSTATEGENERATOR' in resp and '"__VIEWSTATE"' in resp:
        payload = unquote(resp.split('"__VIEWSTATE" value="')[1].split('"')[0])
        modifier = unquote(resp.split('"__VIEWSTATEGENERATOR" value="')[1].split('"')[0])

        res = check_payload(payload, modifier, keys)

        if res:
            print(f"Known key found at {url} ")
            print(f"{res[0]}:{res[1]} / {res[2]}:{res[3]}")

def check_payload(payload, modifier, keys):
    hash_types = ["SHA1","MD5","SHA256", "SHA384","SHA512"]
    crypto_types = ["DES", "3DES", "AES"]

    for h in hash_types:
        for c in crypto_types:
            
            for v, d in keys:
                for t in [True, False]:
                    try:
                        viewgen = ViewGen(binascii.unhexlify(v), h, binascii.unhexlify(d), c, modifier, t)

                        viewstate, sa = viewgen.decode(payload)
                        encoded = viewgen.encode(viewstate, reuse_iv=True)
                        viewstate, sb = viewgen.decode(encoded)
                        
                        if sa == sb:
                            return c, d, h, v
                            
                    except Exception as e:
                        # print(e)
                        pass



if __name__ == "__main__":

    parser = argparse.ArgumentParser()

    parser.add_argument("-p", "--payload", help="Payload to check")
    parser.add_argument('-m', '--modifier', help="Modifier (Generator)")

    parser.add_argument('--keys', help="File of keys to try (default MachineKeys.txt)", default="MachineKeys.txt")
    parser.add_argument('--burp', help="Burp Suite XML File to look through")

    parser.add_argument('-u', '--url', help="URL to pull Viewstate info from")
    parser.add_argument('--header', help="Header strings (pipe delim). ie 'Cookie: blah|User-Agent: blah'")
    args = parser.parse_args()


    keys = [k.split(',') for k in open(args.keys).read().split('\n') if k]

    if args.burp:
        parse_burp(args.burp, keys)

    elif args.payload and args.modifier:

        res = check_payload(args.payload, args.modifier, keys)    

        if res:
            print(f"Success: {res[0]}:{res[1]}, {res[2]}:{res[3]}")

    elif args.url:
        header_data = {}
        if args.header:
        
            for header in args.header.split('|'):
                header_data[header.split(': ')[0]] = ': '.join(header.split(': ')[1:])

        check_url(args.url, keys, header_data)
        
    else:
        parser.print_usage()
