# jsSecrets

**jsSecrets** it is a tool that goes to a given url and scan the html code in order to find any js file to seek for nasty secrets within them.

## Installation

### PyP

     pip install jssecrets
## verify
    jssecrets --help
    
    

### From GitHub

    git clone https://github.com/diegoespindola/jsSecrets.git
    cd jsSecrets
    pip install -r requirements.txt

## verify

    python3 jssecrets --help

## Usage

    jssecrets --help
    
    usage: jsSecrets [-h] [-u URL] [-r REQ] [-v VERBOSE]

    search for secrets in Js files

    options:
    -h, --help            show this help message and exit
    -u, --url URL         Url to hunt for js files and scan the secrets within, ie: https://brokencrystals.com/
    -r, --req REQ         Raw request File Path
    -v, --verbose VERBOSE



### Raw Request File usage

In order to reuse the cookies and other configuration you can use a raw request file to connect to the url.

Instead of use the -u option, you can use the -r option with a raw request file, like the request in caido, or burpsuite 

the raw request file must look similar to this:

    GET / HTTP/1.1
    Host: brokencrystals.com
    Connection: keep-alive
    sec-ch-ua: "Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"
    sec-ch-ua-mobile: ?0
    sec-ch-ua-platform: "Linux"
    Upgrade-Insecure-Requests: 1
    User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
    Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
    Sec-Fetch-Site: none
    Sec-Fetch-Mode: navigate
    Sec-Fetch-User: ?1
    Sec-Fetch-Dest: document
    Accept-Encoding: gzip, deflate, br, zstd
    Accept-Language: en-US,en;q=0.9
    Cookie: connect.sid=MLefXrUukm1SAKlCMfxeE7ZkUoG7flj3.c6qWoC5p%2FL6RMPEzs4FPOhLgseH5T0KC9c%2FRCojRf1Y
    If-None-Match: W/"bd7-196cf51b668"
    If-Modified-Since: Wed, 14 May 2025 15:02:41 GMT
