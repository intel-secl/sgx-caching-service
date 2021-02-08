FROM centos:8

#RUN useradd -u 1001 --comment "SGX Caching Service" --home /opt/scs  --shell /bin/false scs

COPY out/scs /usr/bin/scs

RUN mkdir -p /opt/scs

RUN mkdir /opt/scs/dbscripts/

COPY out/installer/libPCKCertSelection.so /usr/lib64/libPCKCertSelection.so

RUN chmod 755 /usr/lib64/libPCKCertSelection.so

COPY out/installer/db_rotation.sql /opt/scs/dbscripts/

#RUN chown scs:scs /opt/scs/dbscripts/*

COPY dist/image/entrypoint.sh /entrypoint.sh

RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
