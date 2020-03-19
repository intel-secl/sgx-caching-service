#!/bin/sh

op="$1"
env="$2"

if [[ "x$2" = "x" ]]; then
	env="scs"
fi

subscription_key=ec73a0f55ca348cb9f02371f2b9ca614

v_encppid="4db4fcec33e995665f8c74c989bf1ab5b0f02772fcd1fc59a19356b2ded012c1fbab8cbea97fefaf27b3f92960827dbe016ce48c34d365a0f956ab4cada16810435ffb350c88e0137c682334a6e17ca059b66685aa7d90c08c72e0dbb49fbcf268f0ac5d5afcf2429fec2f3e412c9c955dcba0e3f3014e4a9245f271ec40a9ba820ffe19dccde18caa85981dbdbb30929eaba610e67ac12441648934b6184a7140152fc7a254f7d20f0a814f1350d03657e59098b0ba0a1c76071275ecfa3e5d14a5063cae7a89da60244d6ba2bb3dcd2754df559d6bda17db1b8a3ccf357b70bb6513b265e3e0061e0a508aaac2f0fc86ac401ff53c468549d4dd5a99a3cb2902d48d0d3a5de486713d7ce6b4c15caeea97922b8e9077f33c9e02c5c45830865395f52f77bb6b5761c6f29cee81d0ca4061633991ac8c3cebc3e76c2e1fe03e681ee38a394ee78159b3e1a418521c29856e5709988fdc3251b00928f53b6d931c8410458971288d1f949db266702da5678eaef1ae1a9347710333276387fc15"

Bearer_token="eyJhbGciOiJSUzM4NCIsImtpZCI6ImM4NjE1MTJkMzQxYjUxMzYxOTU0NTkwMjNlZGIzZGM1NzkxMjNhZmUiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkNNUyIsIm5hbWUiOiJDZXJ0QXBwcm92ZXIiLCJjb250ZXh0IjoiQ049QUFTIEpXVCBTaWduaW5nIENlcnRpZmljYXRlO0NFUlRUWVBFPUpXVC1TaWduaW5nIn0seyJzZXJ2aWNlIjoiQ01TIiwibmFtZSI6IkNlcnRBcHByb3ZlciIsImNvbnRleHQiOiJDTj1BQVMgVExTIENlcnRpZmljYXRlO1NBTj0xMjcuMC4wLjEsbG9jYWxob3N0O0NFUlRUWVBFPVRMUyJ9XSwiZXhwIjoxNTg0Mjk0MzY3LCJpYXQiOjE1ODQyNzk5NjcsImlzcyI6IkNNUyBKV1QgU2lnbmluZyIsInN1YiI6IkNNUyBKV1QgVG9rZW4ifQ.SItajmhk17FAXFR974hmVfbTMU_IpZwo_Gv8DGqeJVAFUaDcmsFX6iX4KklWKuytgsW3fh54Vypn1ruK2udIbiEtg4x1GUGtLJcysEI2B8qfAiNE3IU7udOQ2NdNfB7LfBsWq0N3a99msjxOrC860l5uiN_54QNYyHwjy-CwE5dly_CMIL4ihxHBESOWO60Aq8oHUnzEu05BI973jMQuMNuYDW0uttVKDDczJeUkki5RH-Iz2sPgvt3rkeMz0dcvkJU-5nzO6quVdlQAig-vtJoSXV0GtjYjiUiXNyaTbTjLgXqyiBucC5XQTn6qpEzICTLhhaqI2srOQA5MsERYayoZjT8LfoxvgwcgO2pBhlKD4Q9gQ5cL1LKjJQkfXRU3101x5YPchjwcV1EyWV1fqh9yjxXe504vWnmv5OA7CS10ptd7y-0SAOf6R_e33BURRU7CI2wBPcHM5fBzSd7AYM1giFvaWo2C1stdbGxVJvV0GvVZEjY8GGOA_KkJGN4P"

intel_pcs_server="https://api.trustedservices.intel.com/sgx/certification/v2/"

v_cpusvn="0202ffffff8002000000000000000000"
v_pcesvn="0A00"
v_pceid="0000"
v_qeid="0f16dfa4033e66e642af8fe358c18751"
v_ca="processor"
v_fmspc="00906ed50000"

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
