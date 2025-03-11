import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning 
from urllib.parse import urlparse
import re

def getFileFullPath(archivos, url):
    print('ToDo')
    # // full url but use same schema as url in param            as seen on view-source:https://juice-shop.herokuapp.com/#/contact
    # / absolute path
    # ./../ relative path


def getJsFilesFromHTML(bodyHTML):
    regexp= re.compile(r"([\"'])(/[^\"']+\.js)\1")
    matches = regexp.findall(bodyHTML)
    return list(zip(*matches))[1]


parser = argparse.ArgumentParser(prog='jsSecrets', description='search for secrets in Js files')
parser.add_argument('-u','--url',  type=str, nargs='?', help='Url to hunt for js files and scan the secrets within, ie: https://brokencrystals.com/')
parser.add_argument('-p', '--path', type=str, nargs='?', help='Path to the file to scan for nasty secrets')
params = parser.parse_args()

if not(params.url) and  not(params.path):
    parser.print_help()
    exit (-1)
elif not(bool(params.url) ^  bool(params.path)):
    print('it is -u or -p not boths')
    parser.print_help()
    exit (-1) 

if params.url:
    
    validation = urlparse(params.url)
    if not validation.netloc or not validation.scheme:
        print('Error: Url is not valid')
    elif  validation.netloc and  validation.scheme:
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        try:
            page = requests.get(params.url ,  verify=False, allow_redirects=True)
        except:
            print("Error: url not alive")
        else:
            if page.status_code==200:
                absolutePath = validation.scheme + '://' + validation.hostname
                relativePath = validation.scheme + '://' + validation.hostname + '/' + validation.path
                FilesFromHTML = getJsFilesFromHTML(page.text)
                print(FilesFromHTML)
            else:
                print("Error: ", page.reason)
elif params.path:
    print('scan file')


# ToDo
# get full request body
# find js files
# analize files
#recieve headers, cookies, tokens, etc to scan within login sector

  