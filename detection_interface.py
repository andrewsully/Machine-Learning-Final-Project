

import re
from random import randint
from urllib.parse import urlparse, urlsplit
import pickle

import pandas as pd
import tld
import numpy as np

from collections import defaultdict

from tkinter import *


#functions called but are already defined in the file
def abnormal_url(url):
    hostname = urlparse(url).hostname
    hostname = str(hostname)
    match = re.search(hostname, url)
    if match:
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0
def http_secure(url):
    http = urlparse(url).scheme
    match = str(http)
    if match=='https':
        # print match.group()
        return 1
    else:
        # print 'No matching pattern found'
        return 0
def parse_url_words(url):
    parsed_url = tld.parse_tld(url)
    parsed_url = [word for word in parsed_url if word is not None]
    parsed_url = [word for word in parsed_url if word != "www"]
    parsed_url = [word for word in parsed_url if not tld.is_tld(word)]
    parsed_url = [word.strip() for word in parsed_url]
    parsed_url = [word for word in parsed_url if word != '']
    parsed_url = None if len(parsed_url) == 0 else parsed_url
    return parsed_url
def count_words_in_common(left_group, right_group):
    if left_group is not None:
        left_group = set(left_group)
        right_group = set(right_group)

        intersection = left_group.intersection(right_group)

        return len(intersection)
    else:
        return 0
def get_tld(url):
    try:
        return tld.get_tld(url, fail_silently=True, fix_protocol=True)
    except ValueError:
        return None

symbols = ['@','?','-','=','.','#','%','+','$','!','*',',','//']
top_phishing_words = ['pastehtml',
 'sharepoint',
 'id8-eu',
 'id-app7',
 'eu-id3',
 'srv-woa1',
 'mail',
 'firebasestorage',
 '000webhostapp',
 'naylorantiques']

top_defacement_words = ['allaroundrental',
 'bruynzeelmultipanel',
 'ninopizzaria',
 'javadoplant',
 'sikobv',
 'slaviacapital',
 'rendeck',
 'tandemimmobilier',
 'zibae',
 'iremshrine']

top_malware_words = ['9779',
 'mixh',
 'mitsui-jyuku',
 'apbfiber',
 'pastebin',
 'toulousa',
 'grasslandhotel',
 'hotlinegsm',
 '3cf',
 'chinesevie']

top_benign_words = ['torcache',
 'olx',
 'thenextweb',
 'distractify',
 'extratorrent',
 'babal',
 'twitter',
 'mic',
 'tobogo',
 'motthegioi']

tld_of_interest = ['com', 'other', 'org', 'net', 'edu', 'co.uk', 'de', 'com.br', 'ru',
       'com.au', 'fr', 'ca', 'it', 'info', 'nl', 'ac.uk', 'pl',
       'blogspot.com', 'co.za', 'gov', 'in', 'se', 'tk', 'jp', 'eu', 'es',
       'gr', 'ch', 'cz', 'at', 'ro']

def test(input):
    data = pd.DataFrame([input], columns=['url'])
    data["url_length"] = data["url"].apply(lambda url : len(url))
    #all symbols
    for symbol in symbols:
        data[symbol] = data['url'].apply(lambda i: i.count(symbol))
    #abnormal_url
    data['abnormal_url'] = data['url'].apply(lambda i: abnormal_url(i))
    data["https"] = data["url"].apply(lambda x : http_secure(x))
    data["words"] = data["url"].apply(lambda x : parse_url_words(x))
    data["phishing_words_count"] = data["words"].apply(lambda x: count_words_in_common(x,top_phishing_words))
    data["defacement_words_count"] = data["words"].apply(lambda x: count_words_in_common(x,top_defacement_words))
    data["malware_words_count"] = data["words"].apply(lambda x: count_words_in_common(x,top_malware_words))
    data["benign_words_count"] = data["words"].apply(lambda x: count_words_in_common(x,top_benign_words))
    data["tld"] = data["url"].apply(lambda x: get_tld(x))
    for tld in tld_of_interest:
        data[tld] = data["tld"].apply(lambda x : 1 if x == tld else 0)
    data.drop(['url', 'tld', 'words'], inplace=True, axis=1)
    
    return data


# Importing serialised model
rf = pickle.load(open('tuned_rf.sav', 'rb'))


def get_pred(row):

    if row[0] == 1:
        return "#FF0000",'This is most likely a PHISHING scheme!'
    elif row[1] == 1:
        return "#FFA500", 'This link may carry intrusive software!'
    elif row[2] == 1:
        return "#FFA500", 'Someone may be trying\n to vandalise your website!'
    else:
        return "#228B22", 'Safe!'




ws = Tk()
ws.title("Malicious URL detection")
ws.geometry('600x500')
ws['bg'] = '#E7E0D3'


output = Label(ws, 
            text=" ",
            font=("Helvetica", 30),
            foreground="#E7E0D3", 
            bg='#E7E0D3'
            )
            
output.pack(pady=40)

def remove_text():
    output.config(text=" ")

def printValue():

    URL = url.get()
    remove_text()
    pred_key = rf.predict(test(URL))[0]
    text_color, prediction = get_pred(pred_key)
    output.config(text=prediction, foreground=text_color)


url = Entry(ws)
url.pack(pady=100)

Button(
    ws,
    text="Check my URL",
    padx=25,
    pady=10,
    command=printValue
    ).pack()

ws.mainloop()



