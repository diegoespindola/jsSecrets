import argparse
import validators

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
    
    validation = validators.url(params.url, public=True)
    if not validation:
        print('Error: Url is not valid')
    else:
        print(validation)


elif params.path:
    print('scan file')

print('End')


### ToDo:
# validate url
# get full request body
# find js files
# analize files
#

  