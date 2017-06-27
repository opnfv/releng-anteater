##############################################################################
# Anteater Dockerfile
##############################################################################
# Copyright (c) 2017 Luke Hinds <lhinds@redhat.com>, Red Hat
#
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Apache License, Version 2.0
# which accompanies this distribution, and is available at
# http://www.apache.org/licenses/LICENSE-2.0
##############################################################################

FROM centos:latest
MAINTAINER Luke Hinds <lhinds@redhat.com>
LABEL version="0.1" description="Anteater - OPNFV Gerrit Security Gate Checks"

# enviroment variables
ARG ANTEATER_USER=opnfv
ENV HOME /home/${ANTEATER_USER}
ENV ANTEATER_HOME ${HOME}/anteater
RUN mkdir -p ${ANTEATER_HOME}

# Packaged dependencies
RUN yum -y install epel-release
RUN yum -y update
RUN yum -y install git python-devel python-pip
RUN yum clean all

# Commands to clone and install
RUN git clone https://gerrit.opnfv.org/gerrit/releng-anteater ${ANTEATER_HOME}
WORKDIR ${ANTEATER_HOME}
RUN /usr/bin/pip install -r ${ANTEATER_HOME}/requirements.txt
RUN python ${ANTEATER_HOME}/setup.py install
