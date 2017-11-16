import os
import sys
import hashlib
import argparse
from binaryornot.check import is_binary

hasher = hashlib.sha256()
parser = argparse.ArgumentParser()

parser.add_argument('--project', help="Full path to project folder", \
	required=True)
args = parser.parse_args()
ignore_dirs = ['.git']
sys.stdout = open('output.yaml' , 'w')

print("binaries:")
for root, dirs, files in os.walk(args.project):
    dirs[:] = [d for d in dirs if d not in ignore_dirs]
    for file in files:
        path = os.path.join(root, file)
        if is_binary(path):
            with open(path, 'rb') as afile:
                buf = afile.read()
                hasher.update(buf)
                print "  {}".format(file)
                sum = hasher.hexdigest()
                print "    - {}".format(sum)

print("script run complete, now copy and paste contents of output.yaml into \
	your project exception yaml file")
