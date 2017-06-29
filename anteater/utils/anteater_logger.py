#!/usr/bin/env python
# -*- coding: utf-8 -*-
##############################################################################
# Copyright (c) 2017 jose.lausuch@ericsson.com
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
##############################################################################

from __future__ import absolute_import

import logging

import os
import six.moves.configparser

config = six.moves.configparser.RawConfigParser()
config.read('anteater.conf')
anteater_log = config.get('config', 'anteater_log')


class Logger:
    def __init__(self, logger_name):
        self.logger = logging.getLogger(logger_name)
        self.logger.propagate = 0
        self.logger.setLevel(logging.DEBUG)

        ch = logging.StreamHandler()
        formatter = logging.Formatter('%(asctime)s - %(name)s - '
                                      '%(levelname)s - %(message)s')
        ch.setFormatter(formatter)
        ch.setLevel(logging.DEBUG)
        self.logger.addHandler(ch)

        # create the directory if not existed
        path = os.path.dirname(anteater_log)
        if ( False == os.path.exists(path)):
            try:
                os.makedirs(path)
            except OSError as e:
                raise e

        handler = logging.FileHandler(anteater_log)
        handler.setFormatter(formatter)
        handler.setLevel(logging.DEBUG)
        self.logger.addHandler(handler)

    def getLogger(self):
        return self.logger
