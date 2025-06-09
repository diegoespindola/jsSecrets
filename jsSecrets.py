import argparse
import logging
import requests
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urljoin
from urllib.parse import urlparse, urlsplit
import re

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logging.basicConfig()
logger = logging.getLogger('logger')

def setLoggingLevel(level):
    logger.setLevel({2: logging.ERROR, 1: logging.WARNING, 0: logging.INFO}.get(level, logging.DEBUG))

def getJsFilesFromHTML(html):
    regexps = [
        r'<script[^>]+src\s*?=\s*?[\"\']([^\"\']+\.js)[\"\']',
        r'<meta[^>]+content\s*?=\s*?[\"\']([^\"\']+\.js)[\"\']',
        r'<link[^>]+href\s*?=\s*?[\"\']([^\"\']+\.js)[\"\']',
        r'[\"\']([^\"\']+\.js)[\"\']'
    ]
    matches = []
    for pattern in regexps:
        matches += re.findall(pattern, html, re.IGNORECASE)
    return list(set(matches))


def getFileFullPath(urlparsed, jsFiles):
    lista = list(map(lambda x: 
                     x if x[:4] == 'http' # ruta fija
                     else
                        urlparsed.scheme + ':' + x if x[:2] == '//'  # schema only
                        else 
                            urlparsed.scheme + '://' + urlparsed.hostname  + x if x[:1] == '/'   #absolute path
                            else 
                                urlparsed.scheme + '://' + urlparsed.netloc + '/' + (urlparsed.path if urlparsed.path != '/' else '') + x  #relative path
                     , jsFiles))
    return(lista)


def seekJsSecrets(jsUrl, session=None):
    logger.debug(f'Scanning {jsUrl}')
    try:
        res = requests.get(jsUrl, allow_redirects=True, timeout=10, verify=False)
    except Exception as e:
        logger.warning(f'Could not fetch {jsUrl}: {e}')
        return []

    if res.status_code != 200:
        logger.warning(f'Non-200 for {jsUrl}: {res.status_code}')
        return []

    secrets = []
    patterns = [
        r'(?i)(api_key|apikey|token|access_token|auth|secret|password|username)\s*[:=]\s*["\']([^"\']{10,})["\']',
        r'(?i)["\'](sk_live_[0-9a-zA-Z]{20,})["\']',
    ]
    for p in patterns:
        found = re.findall(p, res.text)
        secrets.extend(found)
    return secrets


def parseRawRequest(requestPpath):
    with open(requestPpath, 'r') as f:
        raw = f.read()

    headerPart, body = raw.split('\\n\\n', 1) if '\\n\\n' in raw else (raw, '')
    lines = headerPart.splitlines()
    method, path, _ = lines[0].split()
    headers = dict(line.split(': ', 1) for line in lines[1:] if ': ' in line)
    scheme = 'https' if headers.get('Host', '').startswith('https') else 'http'
    url = f'{scheme}://{headers['Host']}{path}'
    session = requests.Session()
    session.headers.update(headers)
    return session, url, method.upper(), body


def main():
    parser = argparse.ArgumentParser(prog='jsSecrets', description='search for secrets in Js files')
    parser.add_argument('-u', '--url', help='Url to hunt for js files and scan the secrets within, ie: https://brokencrystals.com/')
    parser.add_argument('-r', '--req', help='Raw request File Path'  )
    parser.add_argument('-v', '--verbose', type=int, default=0, help='Vervose mode (0-3) default 0')
    args = parser.parse_args()

    setLoggingLevel(args.verbose)

    if args.req:
        session, url, method, body = parseRawRequest(args.req)
        logger.info(f'Requesting via {method}: {url}')
        try:
            resp = session.request(method, url, data=body if method == 'POST' else None, allow_redirects=True, verify=False)
        except Exception as e:
            logger.error(f'Error fetching: {e}')
            return
    elif args.url:
        url = args.url
        logger.info(f'GET {url}')
        try:
            resp = requests.get(url, allow_redirects=True, verify=False)
        except Exception as e:
            logger.error(f'Error: {e}')
            return
    else:
        parser.print_help()
        return

    if resp.status_code != 200:
        logger.warning(f'Status {resp.status_code}')
        return
    urlparsed = urlparse(args.url)
    scripts = getJsFilesFromHTML(resp.text)
    fullUrls = getFileFullPath(urlparsed, scripts)
    for jsUrl in fullUrls:
        logger.info(f'Found JS: {jsUrl}')
        secrets = seekJsSecrets(jsUrl)
        if(secrets):
            for secret in secrets:
                print(f'[{jsUrl}] {secret}')
        else:
            print(' No secrets Found')
if __name__ == '__main__':
    main()