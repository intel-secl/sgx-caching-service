# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM ubuntu:focal

RUN apt-get update -y

RUN apt-get install ca-certificates openssl -y

COPY out/scs /usr/bin/scs

COPY out/libPCKCertSelection.so /usr/lib/libPCKCertSelection.so

RUN chmod 755 /usr/lib/libPCKCertSelection.so

RUN apt-get clean && apt-get autoclean

COPY dist/image/entrypoint.sh /entrypoint.sh

RUN touch /.container-env && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
