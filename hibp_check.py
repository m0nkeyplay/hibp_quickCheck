#!/usr/bin/python3
#
#  author:		https://github.com/m0nkeyplay
#  March 14, 2019 - original script written
#  Free to use
#  Free to modify and make better
#  ./hibp_check.py -h for help

import requests
import json
import os
import time
import datetime
from sys import argv

#  Banner Info
def show_banner():
  print('################################################################')
  print('###              have i been pwned  Quick Check              ###')
  print('###                                                          ###')
  print('###  Usage: hibp_check.py breach|paste -e email|-f textFile  ###')
  print('###                                                          ###')
  print('###  Use and modify at will.                                 ###')
  print('###  Using the HIBP API v2                                   ###')
  print('###  https://haveibeenpwned.com/API/v2                       ###')
  print('###                                                          ###')
  print('###  *Note that using a file will take some time since the   ###')
  print('###  API we are calling is rate limited.                     ###')
  print('################################################################')

# Short Help Menu
def show_help():
    print('\n\nHelp with argument usage\n')
    print('Which check do you want to do?  breach or paste')
    print('Are you searching one or many emails?')
    print('-e  or -f with textFile having one email per line')
    print('Example:\nBreach+Email: hibp_check_.py -breach -e my@email.com')
    print('Example:\nBreach+List of emails: hibp_check_.py -breach -f ./path/to/file')

# Arg Check
# Sanity Needs to be added
if len(argv) < 3:
    show_banner()
    if argv[1] == '-h':
        show_help()
        exit()
    else:
        print('Something is missing\nWe need 3 variables to do this.\nCheck usage details above.')
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
headers['api-version']= '2'
headers['User-Agent']='My-Litle-Python-Script'

# We get status codes when it fails - Let's explain
def show_status_code(code):
  code = str(code)
  if code == '400':
      engrish = 'Bad request — the account does not comply with an acceptable format (i.e. it\'s an empty string)'
  elif code == '403':
      engrish = 'Forbidden — no user agent has been specified in the request'
  elif code == '404':
      engrish = 'Not found — the account could not be found and has therefore not been pwned'
  elif code == '429':
      engrish = 'Too Tany requests — the rate limit has been exceeded'
  else:
      engrish = 'We don\t know.  Check the response codes for HIBP @ https://haveibeenpwned.com/API/v2#ResponseCodes for '+code
  print(engrish)

def check_breach(eml):
    print('Breach Check for: %s'%eml)
    url = 'https://haveibeenpwned.com/api/breachedaccount/'+eml
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

def check_paste(eml):
    print('Paste Check for: %s'%eml)
    url = 'https://haveibeenpwned.com/api/pasteaccount/'+eml
    r = requests.get(url, headers=headers)
    if r.status_code == 200:
        data = r.json()
        for d in data:
            source = d['Source']
            id = str(d['Id'])
            pasteDate = d['Date']
            print('Paste Source: %s\nID: %s <-- use with source to find\nDate: %s\n\n'%(source,id,pasteDate))
    else:
        show_status_code(r.status_code)

# Get started
show_banner()

if chkType == 'email':
    if hibpCheck == 'breachaccount':
        check_breach(chkIt)
    else:
        check_paste(chkIt)
elif chkType == 'file':
    get_emails = open(chkIt, 'r')
    for line in get_emails:
        cleanEmail = line.strip()
        if hibpCheck == 'breachaccount':
            check_breach(cleanEmail)
            time.sleep(2)
        else:
            check_paste(cleanEmail)
            time.sleep(2)
else:
    print('We in trouble.  We should not be here.')
