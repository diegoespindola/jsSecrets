import argparse
import requests
from urllib3.exceptions import InsecureRequestWarning 
from urllib.parse import urlparse, urlsplit
import re

def getFileFullPath(archivos, urlparsed):
    lista = list(map(lambda x: 
                     '1' + x if x[:4] == 'http' # ruta fija
                     else
                        '2 ' + urlparsed.scheme + ':' + x if x[:2] == '//'  # schema only
                        else 
                            '3 '  + urlparsed.scheme + '://' + urlparsed.hostname + '/' + x if x[:1] == '/'   #absolute path
                            else 
                                '4 ' + urlparsed.scheme + '://' + urlparsed.netloc + '/' + (urlparsed.path if urlparsed.path != '/' else '') + x  #relative path
                     , archivos))
    return(lista)
 
def getJsFilesFromHTML(bodyHTML):
    regexp= re.compile(r"([\"'])([^\"']+\.js)\1")  # ToDo: must say src before the js file, or will fail like in  "https://es.wikipedia.org/wiki/Leon_Czolgosz#Referencias"
    matches = regexp.findall(bodyHTML)
    return [] if not matches else   list(zip(*matches))[1]


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
    
    urlparsed = urlparse(params.url)
    if not urlparsed.netloc or not urlparsed.scheme:
        print('Error: Url is not valid')
    elif  urlparsed.netloc and  urlparsed.scheme:
        requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
        try:
            page = requests.get(params.url ,  verify=False, allow_redirects=True)
        except:
            print("Error: url not alive")
        else:
            if page.status_code==200:
                filesFromHTML = getJsFilesFromHTML(page.text)
                fullPathFilesFromHTML = getFileFullPath(filesFromHTML, urlparsed)
                print(*fullPathFilesFromHTML, sep='\n')
            else:
                print("Error: ", page.reason)
elif params.path:
    print('Work in progress, please be patient')


# ToDo:
# analize files
#recieve headers, cookies, tokens, etc to scan within login sector

  