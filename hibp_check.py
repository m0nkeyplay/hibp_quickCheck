#!/usr/bin/env python3
#
#   author:		https://github.com/m0nkeyplay
#   August 26, 2019 - original script written
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
from sys import argv
import signal

#   CTRL+C handler - from https:/gist.github.com/mikerr/6389549
def handler(signum, frame):
    print("\n^^^^^^Task aborted by user.  Some cleanup may be necessary.")
    exit(0)

signal.signal(signal.SIGINT,handler)

#  Banner Info
def show_banner():
  print('################################################################')
  print('###              have i been pwned  Quick Check              ###')
  print('###                                                          ###')
  print('###  Usage: hibp_check.py breach|paste -e email|-f textFile  ###')
  print('###                                                          ###')
  print('###  Use and modify at will.                                 ###')
  print('###  Using the HIBP API v3                                   ###')
  print('###  https://haveibeenpwned.com/API/v3                       ###')
  print('###                                                          ###')
  print('###  *Note that using a file will take some time since the   ###')
  print('###  API we are calling is rate limited.                     ###')
  print('################################################################')

# Short Help Menu
def show_help():
    print('\n::Help with argument usage::\n')
    print('Which check do you want to do?  breach or paste')
    print('Are you searching one or many emails?')
    print('-e  or -f with textFile having one email per line')
    print('$: Breach+Email: hibp_check_.py breach -e my@email.com')
    print('$: Breach+List of emails: hibp_check_.py breach -f ./path/to/file')

# Arg Check
# Sanity Needs to be added
if len(argv) < 3:
    show_banner()
    try:
        argv[1]
    except IndexError:
        print('hibp_check.py -h for help')
        exit()
    else:
        show_help()
        exit()
else:
    chk=argv[1]
    if chk == 'breach':
        hibpCheck = 'breachaccount'
    elif chk == 'paste':
        hibpCheck = 'pasteaccount'
    else:
        show_banner()
        print('Check your check type.  The API doesn\'t allow us to search for a %s.'%chk)
        exit()
    if argv[2] == '-e':
      chkType = 'email'
      chkIt = argv[3]
    elif argv[2] == '-f':
      chkType = 'file'
      chkIt = argv[3]
    else:
      print('Something is missing - check usage details above.')
      exit()

# Hopefully got through the arg checks, let's build this check
headers = {}
headers['content-type']= 'application/json'
headers['api-version']= '3'
headers['User-Agent']='the-monkey-playground-script'
headers['hibp-api-key']=''

# We get status codes when it fails - Let's explain
# API tells us this
def show_status_code(code):
    code = str(code)
    if code == '400':
        inglish = 'Bad request — the account does not comply with an acceptable format (i.e. it\'s an empty string)'
    elif code == '400':
        inglish = 'Unauthorised — the API key provided was not valid'
    elif code == '403':
        inglish = 'Forbidden — no user agent has been specified in the request'
    elif code == '404':
        inglish = 'Not found — the account could not be found and has therefore not been pwned'
    elif code == '429':
        inglish = 'Too Many requests — the rate limit has been exceeded'
    else:
        inglish = 'We don\t know.  Check the response codes for HIBP @ https://haveibeenpwned.com/API/v3#ResponseCodes for '+code
    print(inglish)

# Check Breach
def check_breach(eml):
    print('Breach Check for: %s'%eml)
    url = 'https://haveibeenpwned.com/api/v3/breachedaccount/'+eml+'?truncateResponse=false'
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        for d in data:
            breach = d['Name']
            title = d['Title']
            domain = d['Domain']
            breachDate = d['BreachDate']
            print('Breach: %s\nTitle: %s\nDomain: %s\nBreach Date:%s\n\n'%(breach,title,domain,breachDate))
    else:
        show_status_code(r.status_code)

# Check Paste
def check_paste(eml):
    print('Paste Check for: %s'%eml)
    url = 'https://haveibeenpwned.com/api/v3/pasteaccount/'+eml
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        for d in data:
            source = d['Source']
            id = str(d['Id'])
            pasteDate = d['Date']
            print('Paste Source: %s\nID: %s\nDate: %s\n\n'%(source,id,pasteDate))
    else:
        show_status_code(r.status_code)

# Get started
show_banner()
# Single Checks
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
