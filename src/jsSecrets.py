import argparse
import logging
import requests
from urllib3.exceptions import InsecureRequestWarning
from urllib.parse import urljoin, urlparse, urlsplit
import re
import sys

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

logging.basicConfig()
logger = logging.getLogger('logger')

def set_logging_level(level):
    logger.setLevel({2: logging.ERROR, 1: logging.WARNING, 0: logging.INFO}.get(level, logging.DEBUG))

def get_js_files_from_html(html):
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

def getFileFullPath(urlparsed, js_files):
    lista = list(map(lambda x: 
                     x if x[:4] == 'http' # ruta fija
                     else
                        urlparsed.scheme + ':' + x if x[:2] == '//'  # schema only
                        else 
                            urlparsed.scheme + '://' + urlparsed.hostname  + x if x[:1] == '/'   #absolute path
                            else 
                                urlparsed.scheme + '://' + urlparsed.netloc + '/' + (urlparsed.path if urlparsed.path != '/' else '') + x  #relative path
                     , js_files))
    return lista

def seekJsSecrets(js_url, session=None):
    logger.debug(f'Scanning {js_url}')
    try:
        res = requests.get(js_url, allow_redirects=True, timeout=10, verify=False)
    except Exception as e:
        logger.warning(f'Could not fetch {js_url}: {e}')
        return []

    if res.status_code != 200:
        logger.warning(f'Non-200 for {js_url}: {res.status_code}')
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

def parseRawRequest(request_path):
    with open(request_path, 'r') as f:
        raw = f.read()

    header_part, body = raw.split('\n\n', 1) if '\n\n' in raw else (raw, '')
    lines = header_part.splitlines()
    method, path, _ = lines[0].split()
    headers = dict(line.split(': ', 1) for line in lines[1:] if ': ' in line)
    scheme = 'https' if headers.get('Host', '').startswith('https') else 'http'
    url = f'{scheme}://{headers['Host']}{path}'
    session = requests.Session()
    session.headers.update(headers)
    return session, url, method.upper(), body

def analyze_js_urls(js_urls):
    for js_url in js_urls:
        js_url = js_url.strip()
        if not js_url:
            continue
        secrets = seekJsSecrets(js_url)
        if secrets:
            for secret in secrets:
                print(f'[FOUND][{js_url}] {secret}')
        else:
            logger.debug(f'[{js_url}] No secrets found')

def main():
    parser = argparse.ArgumentParser(prog='jsSecrets', description='search for secrets in Js files')
    parser.add_argument('-u', '--url', help='Url to hunt for js files and scan the secrets within, ie: https://brokencrystals.com/')
    parser.add_argument('-r', '--req', help='Raw request File Path')
    parser.add_argument('-v', '--verbose', type=int, default=0, help='Verbose mode (0-3), default 0')
    args = parser.parse_args()

    set_logging_level(args.verbose)

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
            matches = re.finditer(r'javascript', resp.headers['Content-Type'], re.MULTILINE | re.IGNORECASE)
            tipoURL = 'js' if len(list(matches)) > 0  else 'url'  
        except Exception as e:
            logger.error(f'Error: {e}')
            return
    elif not sys.stdin.isatty():
        logger.info('Reading URLs from stdin...')

        stdin_urls = sys.stdin.read().splitlines()
        for url in stdin_urls :

            try:
                resp = requests.get(url, allow_redirects=True, verify=False)
                matches = re.finditer(r'javascript', resp.headers['Content-Type'], re.MULTILINE | re.IGNORECASE)
                tipoURL = 'js' if len(list(matches)) > 0  else 'url'  
            except Exception as e:
                logger.error(f'Error: {e}')
                return
            if tipoURL == 'url' :
                urlparsed = urlparse(url)
                scripts = get_js_files_from_html(resp.text)
                fullUrls = getFileFullPath(urlparsed, scripts)
                analyze_js_urls(fullUrls)
            elif tipoURL == 'js' :
                analyze_js_urls([url])
        return
    else:
        parser.print_help()
        return

    if resp.status_code != 200:
        logger.warning(f'Status {resp.status_code}')
        return
    
    print (tipoURL)
    if tipoURL == 'url' :
        urlparsed = urlparse(url)
        scripts = get_js_files_from_html(resp.text)
        fullUrls = getFileFullPath(urlparsed, scripts)
        analyze_js_urls(fullUrls)
    elif tipoURL == 'js' :
        analyze_js_urls([url])

if __name__ == '__main__':
    main()
