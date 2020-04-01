#!/bin/sh

op="$1"
env="$2"

if [[ "x$2" = "x" ]]; then
	env="scs"
fi

subscription_key=ec73a0f55ca348cb9f02371f2b9ca614

v_encppid="b9632b61a767df16e7417db63c56770ce782babc231e83dd54ec2e9287232c958a3a0f00054980e4d6a709c7f202248f79af1d6247e71fefbd3a2f9fd444eff80d54ae73d1277d9d86805091fe23fc81dc4aa8be604147dbaadb7aaaf6cf5b8d6c7e56207cdf0b4c6f5d7ae6c3ec97d0fcfc0cb0dc4cb4eca6598beed7191a53dee367df1df53cfa12fbb481b6fc9ec7779bf6013016878ba0ecbe1c8e39274a1e2319056da6b3028201f5d2e37179140261514e27370e6047ff758d8e8e1bc45cf9eaaeaf67b9244ff4655675764b8e6e0d236f67f3b0f1dcd35286566330b91e02030abcba7a0d32a96d5c111b645fc6b1af152f4799228d1e1081938d25e38d39cabf65a0a41337752ab65924d3d08476368c7acb0a26d841ce5c03b3eccc06d1897ca06e152b6025d35208847c033dca757065f77ddb19843f66d959f38d99f66e2929d0f01aaa26b590298d22a58f870f7316d92ac9d42a489fd10e0fc0f928450389372498a7fee9d3a1b2d10c6ea15c180c6b58f352e59c72588fef24"

Bearer_token="eyJhbGciOiJSUzM4NCIsImtpZCI6IjFhOTQ3OTc4NjVkNDk0ODJmMDM1OGE0OGYzY2Q3MDMxOGVjOWM1OGEiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkNNUyIsIm5hbWUiOiJDZXJ0QXBwcm92ZXIiLCJjb250ZXh0IjoiQ049U0NTIFRMUyBDZXJ0aWZpY2F0ZTtTQU49MTAuMTA1LjE2Ny4xODQsMTI3LjAuMC4xLGxvY2FsaG9zdDtDRVJUVFlQRT1UTFMifV0sImV4cCI6MTU4NTMzMzAzNywiaWF0IjoxNTg1MTYwMjA3LCJpc3MiOiJBQVMgSldUIElzc3VlciIsInN1YiI6InNjc3VzZXJAc2NzIn0.EkJ09pNgoa1zjNX-uYAv9rT-rdA5sWNZRFjmZlPE985WKULUefES9OwBVwDenRvnE1q92KK0AJWdGNxDmBjd3uCQd6mNlF26TKtN_vHdWDOWfTjiY5H5Dm0dYdPwo1IXSUkXNZm-xd8QNANOvWYVDcDcDZdQ_Pm0j6tIwTXSeLEvBBbJXqDQJN9MTfc8MTDpM-4PD1figyCQoLdIDVgqac0nVhQgK-XfGLT_Sc3RdJjdNDyC-e05XFZwYh9SZm2UlHEDZ9oF8bVDVSHPWVWZKP-4Ljz3-ssJov0-vY9V_nd4f22mGdNymv031LLHBTia8NjKZGCtnTFbfJxHwF8obwGKGvsLUF2pFK067Zhz2xerYMToOl7sD6hjpK0ri3BNTDg_E3BHOEjPvURQnZ82FxLyahvBkeRR3vMgh1WMyuKs0bYVfx0V7qJTXXsAyMc2DaLUTqEUx_7DSsu-vQSWPovDd-gj8PQOTTYwxeuVxN_5zKN83wPumStQ4GiIoqH2"

intel_pcs_server="https://api.trustedservices.intel.com/sgx/certification/v2/"

v_cpusvn="0202ffffff8002000000000000000000"
v_pcesvn="0A00"
v_pceid="0000"
v_qeid="0f16dfa4033e66e642af8fe358c18751"
v_ca="processor"
v_fmspc="00906ed50000"

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
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/push" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$PF_CREATE_JSON_FILE -k
fi

if [[ "$op" = "refresh" ]]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/refresh" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" -k
fi

if [[ "$op" = "tcbstatus" ]]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/tcbstatus?qeid=$v_qeid" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" -k
fi
