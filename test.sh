#!/bin/sh

op="$1"
env="$2"

if [[ "x$2" = "x" ]]; then
	env="scs"
fi

subscription_key=9e0153b3f0c948d9ade866635f039e1e

v_encppid="d2378f3bbccd82b3de684c455de692ffba12c78bac4fba5e107c68b936d4f863a3a01f529936ae35285db3526349fb77c37e593c7b155b19870ecd6b1e174e22641a4e40504ea2102e2718a2463ee2841141bca2ed7e357e29b00b38468c9cfc2e1c290737722ec2a4f0b48bef73a19f6efa8d32927642caa80b100a6f5a0eea6e239553d76ccc27b51aed563dfc89f79281741bce392b047bca52d68acda326ec7dae89578a0845fd8b2325e10f0a6c967854f75884d6327dc50f551ea90bd9e27bacd43bdd8fc682e66ac86595162bf42026a059fb51c0d68786c799e88b6b72370608aad1505a6a816c0273a257258ef45ed8682a192da385f624b4adf59158dd1e375f74236c0e9a5a0ed0dfb241057f75842b792b53d25af9d9725e62782cb609737ac244cf583d00d07f39f9a66b17a0315666637d0063a00b00ef81dc96780c09fc4e7319ab8492c27c8c82cdcc89f6401b100d1478f11b0f46b6fe4418a1284aa23597f9b3f197a416a5d431049ed7a4786513a604f729458957da09"

Bearer_token="eyJhbGciOiJSUzM4NCIsImtpZCI6ImM4NjE1MTJkMzQxYjUxMzYxOTU0NTkwMjNlZGIzZGM1NzkxMjNhZmUiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkNNUyIsIm5hbWUiOiJDZXJ0QXBwcm92ZXIiLCJjb250ZXh0IjoiQ049QUFTIEpXVCBTaWduaW5nIENlcnRpZmljYXRlO0NFUlRUWVBFPUpXVC1TaWduaW5nIn0seyJzZXJ2aWNlIjoiQ01TIiwibmFtZSI6IkNlcnRBcHByb3ZlciIsImNvbnRleHQiOiJDTj1BQVMgVExTIENlcnRpZmljYXRlO1NBTj0xMjcuMC4wLjEsbG9jYWxob3N0O0NFUlRUWVBFPVRMUyJ9XSwiZXhwIjoxNTg0Mjk0MzY3LCJpYXQiOjE1ODQyNzk5NjcsImlzcyI6IkNNUyBKV1QgU2lnbmluZyIsInN1YiI6IkNNUyBKV1QgVG9rZW4ifQ.SItajmhk17FAXFR974hmVfbTMU_IpZwo_Gv8DGqeJVAFUaDcmsFX6iX4KklWKuytgsW3fh54Vypn1ruK2udIbiEtg4x1GUGtLJcysEI2B8qfAiNE3IU7udOQ2NdNfB7LfBsWq0N3a99msjxOrC860l5uiN_54QNYyHwjy-CwE5dly_CMIL4ihxHBESOWO60Aq8oHUnzEu05BI973jMQuMNuYDW0uttVKDDczJeUkki5RH-Iz2sPgvt3rkeMz0dcvkJU-5nzO6quVdlQAig-vtJoSXV0GtjYjiUiXNyaTbTjLgXqyiBucC5XQTn6qpEzICTLhhaqI2srOQA5MsERYayoZjT8LfoxvgwcgO2pBhlKD4Q9gQ5cL1LKjJQkfXRU3101x5YPchjwcV1EyWV1fqh9yjxXe504vWnmv5OA7CS10ptd7y-0SAOf6R_e33BURRU7CI2wBPcHM5fBzSd7AYM1giFvaWo2C1stdbGxVJvV0GvVZEjY8GGOA_KkJGN4P"

intel_pcs_server="https://sbx.api.trustedservices.intel.com/sgx/certification/v2/"

v_cpusvn="020e0205ff8000000000000000000000"
v_pcesvn="0900"
v_pceid="0000"
v_qeid="6b3aac1825616a93523e75decc5de603"
v_ca="processor"
v_fmspc="10906ec10000"

hostname="127.0.0.1"
port=9443

if [ "$op" = "pckcert" ] && [ "$env" = "scs" ]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/pckcert?encrypted_ppid=$v_encppid&cpusvn=$v_cpusvn&pcesvn=$v_pcesvn&pceid=$v_pceid&qeid=$v_qeid" -k
elif [ "$op" = "pckcert" ] && [ "$env" = "intel" ]; then
	curl -v -H "Ocp-Apim-Subscription-Key: $subscription_key" "${intel_pcs_server}/pckcert?encrypted_ppid=$v_encppid&pceid=$v_pceid&pcesvn=$v_pcesvn&cpusvn=$v_cpusvn"
elif [ "$op" = "pckcerts" ] && [ "$env" = "intel" ]; then
	curl -v -H "Ocp-Apim-Subscription-Key: $subscription_key" "${intel_pcs_server}/pckcerts?encrypted_ppid=$v_encppid&pceid=$v_pceid"
fi

if [ "$op" = "pckcrl" ] && [ "$env" = "scs" ]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/pckcrl?ca=$v_ca" -k
elif [ "$op" = "pckcrl" ] && [ "$env" = "intel" ]; then
	curl -v "${intel_pcs_server}/pckcrl?ca=$v_ca"
fi

if [ "$op" = "qe" ] && [ "$env" = "scs" ]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/qe/identity" -k
elif [ "$op" = "qe" ] && [ "$env" = "intel" ]; then
	curl -v "${intel_pcs_server}/qe/identity"
fi

if [ "$op" = "tcb" ] && [ "$env" = "scs" ]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/tcb?fmspc=$v_fmspc" -k
elif [ "$op" = "tcb" ] && [ "$env" = "intel" ]; then
	curl -v "${intel_pcs_server}/tcb?fmspc=$v_fmspc"
fi

if [[ "$op" = "push" ]]; then
	PF_CREATE_JSON_FILE=./.platform_info_create.json
printf "{
\"enc_ppid\": \"$v_encppid\",
\"cpu_svn\": \"$v_cpusvn\",
\"pce_svn\": \"$v_pcesvn\",
\"pce_id\": \"$v_pceid\",
\"qe_id\": \"$v_qeid\"
}" > $PF_CREATE_JSON_FILE
	curl -X POST --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/push" -H "Content-Type: application/json" --data @$PF_CREATE_JSON_FILE -k
fi

if [[ "$op" = "refresh" ]]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/refresh" -H "Content-Type: application/json" -k
fi

if [[ "$op" = "tcbstatus" ]]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/tcbstatus?qeid=$v_qeid" -H "Content-Type: application/json" -k
fi
