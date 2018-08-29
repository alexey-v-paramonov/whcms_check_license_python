#!/usr/bin/python3
import os
import time
import json
import base64
import random
import hashlib
import requests
import datetime
from bs4 import BeautifulSoup


def check_license(hostname, hostip, licensekey, localkey=None):

    WHMCSURL = "YOUR URL"
    verifyfilepath = 'modules/servers/licensing/verify.php'
    licensing_secret_key = 'YOUR SECRET KEY'
    localkeydays = 1
    allowcheckfaildays = 1

    check_token = "{}{}".format(
        int(time.time()),
        hashlib.md5("{}{}".format(
            random.randint(1000000000, 9999999999), licensekey).encode('utf-8')
        ).hexdigest()
    )
    localkeyvalid = False
    domain = hostname
    usersip = hostip
    dirpath = os.path.dirname(os.path.abspath(__file__))
    results = {}
    checkdate = datetime.date.today().strftime('%Y%m%d')

    if localkey:
        localdata = localkey[0:-32]
        md5hash = localkey[-32:]
        data_hash = hashlib.md5("{}{}".format(localdata, licensing_secret_key).encode('utf-8')).hexdigest()
        if md5hash == data_hash:
            localdata = localdata[::-1]
            md5hash = localdata[:32]
            localdata = localdata[32:]
            localdata = base64.b64decode(localdata).decode('ascii')
            try:
                localkeyresults = json.loads(localdata)
            except:
                return results

            originalcheckdate = localkeyresults['checkdate']
            data_hash = hashlib.md5("{}{}".format(originalcheckdate, licensing_secret_key).encode('utf-8')).hexdigest()

            if md5hash == data_hash:
                originalcheckdate = datetime.datetime.strptime(localkeyresults['checkdate'], '%Y%m%d')
                localexpiry = (datetime.datetime.today() - datetime.timedelta(days=localkeydays)).replace(hour=0, minute=0, second=0, microsecond=0)
                if originalcheckdate > localexpiry:
                    localkeyvalid = True
                    results = localkeyresults

                    validdomains = results['validdomain'].split(',')
                    if domain not in validdomains:
                        localkeyvalid = False
                        localkeyresults['status'] = "Invalid"
                        results = {}

                    validips = results['validip'].split(',')
                    if usersip not in validips:
                        localkeyvalid = False
                        localkeyresults['status'] = "Invalid"
                        results = {}

                    validdirs = results['validdirectory'].split(',')
                    if dirpath not in validdirs:
                        localkeyvalid = False
                        localkeyresults['status'] = "Invalid"
                        results = {}

    if not localkeyvalid:
        postfields = {
            'licensekey': licensekey,
            'domain': domain,
            'ip': usersip,
            'dir': dirpath,
            'check_token': check_token,
        }
        url = "{}{}".format(WHMCSURL, verifyfilepath)
        response = requests.post(url, data=postfields, timeout=30, allow_redirects=True)
        if not response.ok:
            localexpiry = (datetime.datetime.today() - datetime.timedelta(days=localkeydays + allowcheckfaildays)).replace(hour=0, minute=0, second=0, microsecond=0)
            if originalcheckdate > localexpiry:
                results = localkeyresults
            else:
                results = {}
                results['status'] = "Invalid"
                results['description'] = "Remote Check Failed"
                return results
        else:
            soup = BeautifulSoup(response.content, "html.parser")
            results = {tag.name: tag.text for tag in soup.find_all()}

            if not results:
                return results

            if 'md5hash' in results and results['md5hash']:
                if results['md5hash'] != hashlib.md5("{}{}".format(licensing_secret_key, check_token).encode('utf-8')).hexdigest():
                    results['status'] = "Invalid"
                    results['description'] = "MD5 Checksum Verification Failed"
                    return results
            if results['status'] == "Active":
                results['checkdate'] = checkdate
                data_encoded = json.dumps(results)
                data_encoded = base64.b64encode(data_encoded.encode('ascii'))
                data_encoded = data_encoded.decode('ascii')
                data_encoded = "{}{}".format(
                    hashlib.md5("{}{}".format(checkdate, licensing_secret_key).encode('utf-8')).hexdigest(),
                    data_encoded
                )
                data_encoded = data_encoded[::-1]
                data_encoded = "{}{}".format(
                    data_encoded,
                    hashlib.md5("{}{}".format(data_encoded, licensing_secret_key).encode('utf-8')).hexdigest()

                )
                results['localkey'] = data_encoded

            results['remotecheck'] = True
            return results
