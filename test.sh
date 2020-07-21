#!/bin/sh

op="$1"
env="$2"

if [[ "x$2" = "x" ]]; then
	env="scs"
fi

subscription_key=9e0153b3f0c948d9ade866635f039e1e

v_encppid="8b5ca7e798d89ca2483928c27cb457d3a7e92b53061c4be9e2691d8d228e447b1ef805f63a11a0b1301e1bfda0fffdc995a5e295657d7b49fc7265cf4b6714991d9104dfd01cfcc1b8571a01903f634ba13f3787b63f95712306baf5371374e4dd67dec12650171e88b5b23fbe87d8077e6343d9f4743955c7b4e43740a9c0a609bda0b42701f2248f91b0bbb2ae4a295d39c545b15983500d5cd49df279bb713b839bf5d83dddeb6ea641543597ce09bf099e70dfeed39ddb2d8c9c9419bbeb9b33f958dcc3ff018383f88013012545977122a0d3244fdc48b8e7573996299642837b40a184a8e4774972af9e234f18d5fc5d596bf64a99f4c1b1b7893d0599728894a94e595fd1105ba66647f78638c34d063085da841cf0cbb5948daf3dc291e805322eaeca4d7da9c8e274ffb3b2484115b4da1bfc57c80722427b0598d75d656c384e97cc41dde363ee5693a86e8e5f6099f017917db32b109990558eb08346021d588e3e1f4ca19df48bcccd9db167c6a71f510393b8d4eaace961d55b"

Refresh_Bearer_token="eyJhbGciOiJSUzM4NCIsImtpZCI6ImUyODlkM2E5YzE1ZmM0MWVjMDkzZjAyNWI2MWU2ZDBkY2E0MTEyZDEiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkNNUyIsIm5hbWUiOiJDZXJ0QXBwcm92ZXIiLCJjb250ZXh0IjoiQ049U0NTIFRMUyBDZXJ0aWZpY2F0ZTtTQU49MTAuMjE5LjEzOC43OTtDRVJUVFlQRT1UTFMifSx7InNlcnZpY2UiOiJTQ1MiLCJuYW1lIjoiQ2FjaGVNYW5hZ2VyIn1dLCJleHAiOjE1OTU0MzQ5OTcsImlhdCI6MTU5NTI2MjE2NywiaXNzIjoiQUFTIEpXVCBJc3N1ZXIiLCJzdWIiOiJzY3N1c2VyQHNjcyJ9.wwBfnCEsH_WRlXMIPcVQmm-3jZoM89Kh_Vdwu0r0Qb16cJcnPCTFyNZj48_EaAsyh4zcCTGuXV7zfXWIUPzpIS6W-F_O1QrZFe5qSxKutEae_yUgxlp4R-GQlzbIhWGLPnwAOmd_2GN3T3s5WLHRJ_9mfDBYsMP6FZ20iee4n42EoolLZEw-CenuB5_YKTh7xgMLAtNIqIn39c4u9AWJ-JG90HjgDgayupWg2A0zexQSD5Qs192p82xPYgxN_MzR2jvq5CHY7N_JRXXJ4pgkbBruo9WiwjVzq9Gbc-k6FbFGO0542EpeaMJ24G2zIw3JLxtoldSlL-5o6-KVgSMtNWopfhkhpl1e9Bh10nLsGUT8qLgkMUzCMK-MvsT30PeHvdQPz7dJyYNz__F4-aQa3IjN70EYro8GRsbqARcpjMDgYjMR4WSX-AHP6ItPBPD5HWIESHLXXMrY81eTyNByM7ZP-sxerRUcciO0matWOKawFDRvyG293w0g2JgIYDGk"

Push_and_tcbstatus_Bearer_Token="eyJhbGciOiJSUzM4NCIsImtpZCI6ImUyODlkM2E5YzE1ZmM0MWVjMDkzZjAyNWI2MWU2ZDBkY2E0MTEyZDEiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkNNUyIsIm5hbWUiOiJDZXJ0QXBwcm92ZXIiLCJjb250ZXh0IjoiQ049U0hWUyBUTFMgQ2VydGlmaWNhdGU7U0FOPTEwLjIxOS4xMzguNzk7Q0VSVFRZUEU9VExTIn0seyJzZXJ2aWNlIjoiU0dYX0FHRU5UIiwibmFtZSI6Ikhvc3REYXRhUmVhZGVyIn0seyJzZXJ2aWNlIjoiU0NTIiwibmFtZSI6Ikhvc3REYXRhVXBkYXRlciJ9LHsic2VydmljZSI6IlNDUyIsIm5hbWUiOiJIb3N0RGF0YVJlYWRlciJ9LHsic2VydmljZSI6IlNIVlMiLCJuYW1lIjoiSG9zdExpc3RNYW5hZ2VyIn1dLCJleHAiOjE1OTU0MzUwMzUsImlhdCI6MTU5NTI2MjIwNSwiaXNzIjoiQUFTIEpXVCBJc3N1ZXIiLCJzdWIiOiJzaHZzdXNlckBzaHZzIn0.oRfF4bLpAE4BdJ1t-u2d5bT4lPKM8sjpWeZnleBV35dQdraPqDN-v_D4-CzgIy7cnx7mmeFBH0CyU_UBDej0N037vVrd9UvZt3mbIEqsmVj_LmJPzRY-WRVXKtw5ccNeww3CXd6vH8JItqu9C2GugTCRIkab4r3mUFphlO1K_octB4oZLO1eR1xdpj3fTvuM76dwzEhs8oWms4XKBis317HJ_rtqPlmeZg0HWs6_E9mTM_yPOaPeNAx5ZUGVdNqE4F6WzuNsvW1i46uCgjF-eJfSras9g5nFO4x7vbnuAobvUTiXyWK-Qc-nASGeVP9uVssWUY-5VEBKCijoWv2X9j1GByTk4NEA9fR2rRg0sPyn_N22B_krOdNMdPmzFJbh0kIQnvN5dam0Vs0GwHOFrHV4et4Ozy4fI7DI8VSyXiMWtuQAr-N0znq5sOyX3j4g3veUbzGXpvwHdqeBeipnZBl7Nm-5kfwjWbqI88XZlFvtVgwDj72UFITl8pDAUOWP"


intel_pcs_server="https://sbx.api.trustedservices.intel.com/sgx/certification/v3"

v_cpusvn="02020001010000000000000000000000"
v_pcesvn="0A00"
v_pceid="0000"
v_qeid="0b1ae1e1b05cf3c7425cc3b7ef018299"
v_ca="processor"
v_fmspc="20606a000000"

hostname="127.0.0.1"
port=9000

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
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/push" -H "Content-Type: application/json" -H "Authorization: Bearer ${Push_and_tcbstatus_Bearer_Token}" --data @$PF_CREATE_JSON_FILE -k
fi

if [[ "$op" = "refresh" ]]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/refresh" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" -k
fi

if [[ "$op" = "tcbstatus" ]]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/tcbstatus?qeid=$v_qeid" -H "Content-Type: application/json" -H "Authorization: Bearer ${Push_and_tcbstatus_Bearer_Token}" -k
fi
