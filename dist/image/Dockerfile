FROM centos:8

COPY out/scs /usr/bin/scs

RUN mkdir -p /opt/scs

RUN mkdir /opt/scs/dbscripts/

COPY out/installer/libPCKCertSelection.so /usr/lib64/libPCKCertSelection.so

RUN chmod 755 /usr/lib64/libPCKCertSelection.so

COPY out/installer/db_rotation.sql /opt/scs/dbscripts/

COPY dist/image/entrypoint.sh /entrypoint.sh

RUN touch /.container-env && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
