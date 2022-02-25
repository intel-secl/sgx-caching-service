# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

FROM ubuntu:focal

LABEL org.label-schema.name="SGX Caching Service" \
      org.label-schema.vendor="Intel Corporation" \
      org.label-schema.license="BSD-3-Clause" \
      org.label-schema.url="https://github.com/intel-secl/intel-secl"

RUN apt-get update -y

RUN apt-get install ca-certificates openssl -y

COPY out/scs /usr/bin/scs

COPY out/libPCKCertSelection.so /usr/lib/libPCKCertSelection.so

RUN chmod 755 /usr/lib/libPCKCertSelection.so

RUN apt-get clean && apt-get autoclean

COPY dist/image/entrypoint.sh /entrypoint.sh

RUN touch /.container-env && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
