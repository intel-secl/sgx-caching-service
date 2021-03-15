# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM centos:8

COPY out/scs /usr/bin/scs

COPY out/libPCKCertSelection.so /usr/lib64/libPCKCertSelection.so

RUN chmod 755 /usr/lib64/libPCKCertSelection.so

COPY dist/image/entrypoint.sh /entrypoint.sh

RUN touch /.container-env && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
