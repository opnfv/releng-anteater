#!/bin/bash
##############################################################################
# Copyright (c) 2017 Luke Hinds <lhinds@redhat.com>, Red Hat
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
##############################################################################

GERRITUSER="lukehinds"
REPO_DIR="/home/luke/repos/opnfv"
FORMATED_DIR=$(echo $REPO_DIR |sed 's./.\\/.g')

help (){
echo ""
echo -e "This script is used to generate a patchset list to allow local tests of anteater against a submitted patch set"
echo -e "in the same way as happens at gate.\n"
echo -e "You will need to pass the following arguments.\n"
echo -e "--project <project>\n"
echo -e "for example:"
echo -e "--project releng\n"
echo -e "    * note that the project name has to be the same as the git repository name for the project\n"
echo -e "--patch <patch_number>\n"
echo -e "for example:"
echo -e "--patch 39741\n"
echo -e "    * note that the patchset can be retreived from the URL, e.g https://gerrit.opnfv.org/gerrit/#/c/39741/\n"
exit
}

# GetOpts

usage() {
    echo "Usage: $0 [--project <project>] [--patch <patch_number>] [--help>]" 1>&2; exit 1;
}

for arg in "$@"; do
  shift
  case "$arg" in
    "--project") set -- "$@" "-p" ;;
    "--patch") set -- "$@" "-n" ;;
    "--help") set -- "$@" "-h" ;;
    *)        set -- "$@" "$arg"
  esac
done


while getopts ":p:n:h" arg; do
    case "${arg}" in
        p)
            p=${OPTARG}
            ;;
        n)
            n=${OPTARG}
            ;;
        h)
            help
            ;;
        *)
            usage
            ;;
    esac
done
shift $((OPTIND-1))


if [ -z "${p}" ] || [ -z "${n}" ]; then
    usage
fi

ssh -p 29418 ${GERRITUSER}@gerrit.opnfv.org gerrit query \
    --current-patch-set ${n} \
    --files|grep file:|sed 's/file:\s\/COMMIT_MSG//;s/file://'| \
    sed '/^\s*$/d'| \
    sed -e "s/^/${FORMATED_DIR}\/${p}\//"| tr -d " \t\r" \
    > /tmp/patchset_${n}

echo -e "Patchset created as /tmp/patchset_${n}"
echo -e "You can now run: $ anteater --project ${p} --patchset /tmp/patchset_${n}"