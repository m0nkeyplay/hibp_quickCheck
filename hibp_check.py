#!/usr/bin/env python3
#
#   author:		https://github.com/m0nkeyplay
#   August 26, 2019 - original script written
#   Updated April 23, 2020 - see README for updates
#   Free to use
#   Free to modify and make better
#   ./hibp_check.py -h for help
#   Use of the have i been pwned API now requires a m0nkeyplay
#   I am not requiring a key, but the script won't run without it.
#   Get a key here:
#   Paste it in below headers['hibp-api-key']=''

import requests
import json
import os
import time
import datetime
import signal
import argparse

ap = argparse.ArgumentParser()
ap.add_argument("-b", "--breach", action="store_true")
ap.add_argument("-p", "--paste", action="store_true")
ap.add_argument("-e", "--email", required=False, help="Search for just one email")
ap.add_argument("-f", "--file", required=False, help="grab emails from a list of files -f /path/to/file")
args = vars(ap.parse_args())

#   CTRL+C handler - from https:/gist.github.com/mikerr/6389549
def handler(signum, frame):
    print("\n^^^^^^Task aborted by user.  Some cleanup may be necessary.")
    exit(0)

signal.signal(signal.SIGINT,handler)

#  Banner Info
def show_banner():
  print('####################################################################')
  print('###              have i been pwned  Quick Check                  ###')
  print('###                                                              ###')
  print('###  Usage: hibp_check.py --breach|--paste -e email|-f textFile  ###')
  print('###                                                              ###')
  print('###  Use and modify at will.                                     ###')
  print('###  All data from:                                              ###')
  print('###  https://haveibeenpwned.com/                                 ###')
  print('###                                                              ###')
  print('###  *Note that using a file will take some time since the       ###')
  print('###  API we are calling is rate limited.                         ###')
  print('####################################################################')

# Short Help Menu
def show_help():
    print('\n::Help with argument usage::\n')
    print('Which check do you want to do?  breach or paste')
    print('Are you searching one or many emails?')
    print('-e  or -f with textFile having one email per line')
    print('$: Breach+Email: hibp_check_.py -b -e my@email.com')
    print('$: Breach+List of emails: hibp_check_.py -b -f ./path/to/file')


if args['breach']:
    hibpCheck = 'breachaccount'
elif args['paste']:
    hibpCheck = 'pasteaccount'
else:
    show_banner()
    show_help()
    exit()

if args['email']:
      chkType = 'email'
      chkIt = args['email']
elif args['file']:
      chkType = 'file'
      chkIt = args['file']
else:
    show_banner()
    show_help()
    exit()   

# Hopefully got through the arg checks, let's build this check
headers = {}
headers['content-type']= 'application/json'
headers['api-version']= '3'
headers['User-Agent']='the-monkey-playground-script'
#   Place that API key here
headers['hibp-api-key']='https://haveibeenpwned.com/API/Key'

# Check Breach
def check_breach(eml):
    url = 'https://haveibeenpwned.com/api/v3/breachedaccount/'+eml+'?truncateResponse=false'
    r = requests.get(url, headers=headers)
    if r.status_code == 404:
        print("%s not found in a breach."%eml)
    elif r.status_code == 200:
        data = r.json()
        print('Breach Check for: %s'%eml)
        for d in data:
            #   Simple info
            breach = d['Name']
            domain = d['Domain']
            breachDate = d['BreachDate']
            sensitive = d['IsSensitive']
            print('Account: %s\nBreach: %s\nSensitive: %s\nDomain: %s\nBreach Date:%s\n'%(eml,breach,sensitive,domain,breachDate))
            #   or to print out the whole shebang comment above and uncomment below
            #for k,v in d.items():
            #    print(k+":"+str(v))
    else:
        data = r.json()
        print('Error: <%s>  %s'%(str(r.status_code),data['message']))
        exit()

# Check Paste
def check_paste(eml):
    url = 'https://haveibeenpwned.com/api/v3/pasteaccount/'+eml
    print(url)
    r = requests.get(url, headers=headers)
    if r.status_code == 404:
        print("%s not found in a breach."%eml)
    elif r.status_code == 200:
        data = r.json()
        print('Paste Check for: %s'%eml)
        for d in data:
            source = d['Source']
            id = str(d['Id'])
            pasteDate = d['Date']
            #   Uncomment and add these if you like
            #title = str(d['Title'])
            #EmailCount = str(d['EmailCount'])
            print('Paste Source: %s\nID: %s\nDate: %s\n\n'%(source,id,pasteDate))
    else:
        data = r.json()
        print('Error: <%s>  %s'%(str(r.status_code),data['message']))
        exit()

# Get started
if __name__ == '__main__':
    show_banner()
    # Single Checks
    if headers['hibp-api-key']=='https://haveibeenpwned.com/API/Key':
        print("ERROR: Setup still required.\nPlease register an API key to start using this script.\nRegister @ %s"%headers['hibp-api-key'])
        exit()
    if chkType == 'email':
        if hibpCheck == 'breachaccount':
            check_breach(chkIt)
        else:
            check_paste(chkIt)
    # File Checks
    elif chkType == 'file':
        if not os.path.isfile(chkIt):
            print('\n\nWe can\'t find/open %s.  Please check that it\'s a valid file.\n\n'%chkIt)
        else:
            get_emails = open(chkIt, 'r')
            for line in get_emails:
                cleanEmail = line.strip()
                if hibpCheck == 'breachaccount':
                    check_breach(cleanEmail)
                    time.sleep(2)
                else:
                    check_paste(cleanEmail)
                    time.sleep(2)
            get_emails.close()
    # Something really interesting happened
    else:
        print('We in trouble.  We should not be here.')
