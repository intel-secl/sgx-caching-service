#!/bin/bash

USER_ID=$(id -u)
LOG_PATH=/var/log/scs
CONFIG_PATH=/etc/scs
CERTS_DIR=${CONFIG_PATH}/certs
TRUSTED_CERTS=${CERTS_DIR}/trustedca
ROOT_CA_DIR=${CERTS_DIR}/cms-root-ca
CERTDIR_TRUSTEDJWTCERTS=${CERTS_DIR}/trustedjwt
TOKEN_SIGN_DIR=${CERTS_DIR}/tokensign
DB_SCRIPT_PATH=/opt/scs/dbscripts

if [ ! -f $CONFIG_PATH/.setup_done ]; then
  for directory in $LOG_PATH $CONFIG_PATH $CERTS_DIR $TRUSTED_CERTS $ROOT_CA_DIR $CERTDIR_TRUSTEDJWTCERTS $TOKEN_SIGN_DIR $DB_SCRIPT_PATH; do
    mkdir -p $directory
    if [ $? -ne 0 ]; then
      echo "Cannot create directory: $directory"
      exit 1
    fi
    chown -R $USER_ID:$USER_ID $directory
    echo "After creating directory"
    chmod 700 $directory
  done
  scs setup all
  if [ $? -ne 0 ]; then
    exit 1
  fi
  touch $CONFIG_PATH/.setup_done
fi
if [ ! -z $SETUP_TASK ]; then
  IFS=',' read -ra ADDR <<< "$SETUP_TASK"
  for task in "${ADDR[@]}"; do
    scs setup $task --force
    if [ $? -ne 0 ]; then
      exit 1
     fi
  done
fi
scs run
