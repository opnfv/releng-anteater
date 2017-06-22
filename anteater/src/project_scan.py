#!/usr/bin/env python
# -*- coding: utf-8 -*-
##############################################################################
# Copyright (c) 2017 Luke Hinds <lhinds@redhat.com>, Red Hat
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
##############################################################################

"""
    Accepts the --path argument and iterates the root directory using os.walk
    If a file is a binary, or contains a blacklisted string. If any violations
    are found, the script adds the violation to a log file.
"""

from __future__ import division, print_function, absolute_import
import ConfigParser
import os
import re
import anteater.utils.anteater_logger as antlog
import anteater.src.get_lists as get_lists
from binaryornot.check import is_binary

logger = antlog.Logger(__name__).getLogger()
config = ConfigParser.RawConfigParser()
config.read('anteater.conf')
reports_dir = config.get('config', 'reports_dir')
master_list = config.get('config', 'master_list')
ignore_dirs = ['.git']


def prepare_project(project, project_dir):
    """ Generates blacklists / whitelists and calls main functions """

    # Get Various Lists / Project Waivers
    lists = get_lists.GetLists()

    # Get binary white list
    binary_list, binary_project_list = lists.binary_list(project)

    # Get file name black list and project waivers
    file_audit_list, file_audit_project_list = lists.file_audit_list(project)

    # Get file content black list and project waivers
    file_content_list, project_content_list = lists.file_content_list(project)

    # Get Licence Lists
    licence_ext = lists.licence_extensions()
    licence_ignore = lists.licence_ignore()

    # Perform rudimentary scans
    scan_file(project_dir, project, binary_list, binary_project_list,
              file_audit_list, file_audit_project_list, file_content_list,
              project_content_list)

    # Perform licence header checks
    licence_check(licence_ext, licence_ignore, project, project_dir)
    licence_root_check(project_dir, project)


def scan_file(project_dir, project, binary_list, binary_project_list,
              file_audit_list, file_audit_project_list, file_content_list,
              project_content_list):
    """Searches for banned strings and files that are listed """
    for root, dirs, files in os.walk(project_dir):
        # Filter out ignored directories from list.
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for items in files:
            full_path = os.path.join(root, items)
            # Check for Blacklisted file names
            if file_audit_list.search(full_path) and not \
                    file_audit_project_list.search(full_path):
                match = file_audit_list.search(full_path)
                logger.error('Blacklisted filename: %s', full_path)
                logger.error('Matched String: %s', match.group())
                with open(reports_dir + "file-names_" + project + ".log",
                          "a") as gate_report:
                            gate_report. \
                                write('Blacklisted filename: {0}\n'.
                                      format(full_path))
                            gate_report. \
                                write('Matched String: {0}'.
                                      format(match.group()))

            if not is_binary(full_path):
                fo = open(full_path, 'r')
                lines = fo.readlines()
                for line in lines:
                    # Check for sensitive content in project files
                    if file_content_list.search(line) and not \
                            project_content_list.search(line):
                        match = file_content_list.search(line)
                        logger.error('File contains violation: %s', full_path)
                        logger.error('Flagged Content: %s', line.rstrip())
                        logger.error('Matched String: %s', match.group())
                        with open(reports_dir + "contents-" + project + ".log",
                                  "a") \
                                as gate_report:
                                    gate_report. \
                                        write('File contains violation: {0}\n'.
                                              format(full_path))
                                    gate_report. \
                                        write('Flagged Content: {0}'.
                                              format(line))
                                    gate_report. \
                                        write('Matched String: {0}\n'.
                                              format(match.group()))
            else:
                # Check if Binary is whitelisted
                if not binary_list.search(full_path) \
                        and not binary_project_list.search(full_path):
                    logger.error('Non Whitelisted Binary: %s', full_path)
                    with open(reports_dir + "binaries-" + project + ".log",
                              "a") \
                            as gate_report:
                        gate_report.write('Non Whitelisted Binary: {0}\n'.
                                          format(full_path))


def licence_root_check(project_dir, project):
    if os.path.isfile(project_dir + '/LICENSE'):
        logger.info('LICENSE file present in: %s', project_dir)
    else:
        logger.error('LICENSE file missing in: %s', project_dir)
        with open(reports_dir + "licence-" + project + ".log",
                  "a") \
                as gate_report:
            gate_report.write('LICENSE file missing in: {0}\n'.
                              format(project_dir))


def licence_check(licence_ext, licence_ignore, project, project_dir):
    """ Peform basic checks for the presence of licence strings """
    for root, dirs, files in os.walk(project_dir):
        dirs[:] = [d for d in dirs if d not in ignore_dirs]
        for file in files:
            if file.endswith(tuple(licence_ext)) \
                    and file not in licence_ignore:
                full_path = os.path.join(root, file)
                if not is_binary(full_path):
                    fo = open(full_path, 'r')
                    content = fo.read()
                    # Note: Hardcoded use of 'copyright' & 'spdx' is the result
                    # of a decision made at 2017 plugfest to limit searches to
                    # just these two strings.
                    if re.search("copyright", content, re.IGNORECASE):
                        logger.info('Licence string present: %s', full_path)
                    elif re.search("spdx", content, re.IGNORECASE):
                        logger.info('Licence string present: %s', full_path)
                    else:
                        logger.error('Licence header missing: %s', full_path)
                        with open(reports_dir + "licence-" + project + ".log",
                                  "a") \
                                as gate_report:
                            gate_report.write('Licence header missing: {0}\n'.
                                              format(full_path))
