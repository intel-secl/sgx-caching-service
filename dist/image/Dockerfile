# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM centos:8

COPY out/scs /usr/bin/scs

RUN mkdir -p /opt/scs/dbscripts/

COPY out/installer/libPCKCertSelection.so /usr/lib64/libPCKCertSelection.so

RUN chmod 755 /usr/lib64/libPCKCertSelection.so

COPY out/installer/db_rotation.sql /opt/scs/dbscripts/

COPY dist/image/entrypoint.sh /entrypoint.sh

RUN touch /.container-env && chmod 0700 /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
