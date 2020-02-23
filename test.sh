#!/bin/sh

op="$1"
env="$2"

if [[ "x$2" = "x" ]]; then
	env="scs"
fi

subscription_key=ec73a0f55ca348cb9f02371f2b9ca614

v_encppid="c6d80271c121b1ff45c7a917aa65c23d096544c1c26c93d068fdd1f53b7b083f91f84b10d5efb30d146d934143966fc1194a7025854afe65edf3ea177d2ba538d6350eb7aa06f5eb34bcb23b8efb546bc97bb90356454d9ecbe143c3742e8cd43e9d66850578f2ee4fcfe2473a99eb300a960044ee5142c41fe90b1d7804c3a218a272b509975eba9b66556b33b406c2b5771e1a8f7223f96bcd922252c1e96385082bdc52d3f91a06e8d27eecf087966c5396d38510dd0b6fc941261d3f3bbe6cb9dd6025f6e80cab274bf5275c570e390d33cf64db7fbbbdd402665165ab5c29a7d5ddee84a688fa62eedd70871fc15f226419aecff733bc7fd72a5a039b2ae518a03611e7461700e5228607d3b1012bc265c5df23cf2434e37e79f8eabadb5fcbe9b9b7b741848c1022a02fa8e968d3c4f5db72a993326345d5f473669b2a97abe5b7b630f39f05592a8cb4a3333e71c09731b521e315fbfd22632981f7c3d6bedb0cbdc55307c9f75a0b0150731028ceb1951daa550b0bccc82b45b5f1ef"

Bearer_token="eyJhbGciOiJSUzM4NCIsImtpZCI6ImY1NjU2MjAxZjc4YmJjOGRhYTQyNmYzZjljYjgwNjYyN2MwNDY2YzkiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkNNUyIsIm5hbWUiOiJDZXJ0QXBwcm92ZXIiLCJjb250ZXh0IjoiQ049U0NTIFRMUyBDZXJ0aWZpY2F0ZTtTQU49MTAuMTA1LjE2Ny4xODQsMTI3LjAuMC4xLGxvY2FsaG9zdDtDRVJUVFlQRT1UTFMifV0sImV4cCI6MTczOTg1MzU0NCwiaWF0IjoxNTgyMTczNTQ0LCJpc3MiOiJBQVMgSldUIElzc3VlciIsInN1YiI6InNjc3VzZXJAc2NzIn0.tr8Y4wJQoKKXvXEioie2tNqODaFcR_i1jZlrboiD5K5oVlwLB6Ow4th0MSD26Bg_Ca09LoG3V9gdyKf2bVWk4NVNYhWPSaa8Mn_XCKadu83XHoziCb5uszX0FxtmXIWAWUtY7v2qlJG7DDyszA2ZR1lzAXwYg47K78hzcx9QzKgYheVmDI5rX7InS3pMg7Y_zhR3yvuUHal6o6ts7fqdjfl-ULbT0GdeWiT9GKO2UC-u8Cee6XKfB_XxiQ5UPa2DODf5m52qpd7G1KCvLanUonFcSoMA8t5F7TC-eDlZCrb_Ppv9iXR2GB55_iBSVZCMaRJntRt6GyeWQmX56djxspyeiGB8QOapJvWuvItbExScTOugFgjfwpNRLFoo9sujLJjN-H8lo8Wj7zMdBRCp9iPmh3J3006ABETZ38lOEpxHPsx6rNffAfYgIp9l9OTKIyNujPxgvPKsE_6-6Lt2yonDzfdwpI9JVDakxL40uPZrobtpg6xiJIiaAyM6luyk"

intel_pcs_server="https://api.trustedservices.intel.com/sgx/certification/v2/"

v_cpusvn="0202ffffff8002000000000000000000"
v_pcesvn="0900"
v_pceid="0000"
v_qeid="0f16dfa4033e66e642af8fe358c18751"
v_ca="processor"
v_fmspc="00906ed50000"

hostname="127.0.0.1"
port=9443

if [ "$op" = "pckcert" ] && [ "$env" = "scs" ]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/pckcert?encrypted_ppid=$v_encppid&cpusvn=$v_cpusvn&pcesvn=$v_pcesvn&pceid=$v_pceid&qeid=$v_qeid"  -H "Authorization: Bearer ${Bearer_token}" -k
elif [ "$op" = "pckcert" ] && [ "$env" = "intel" ]; then
	curl -v -H "Ocp-Apim-Subscription-Key: $subscription_key" "${intel_pcs_server}/pckcert?encrypted_ppid=$v_encppid&pceid=$v_pceid&pcesvn=$v_pcesvn&cpusvn=$v_cpusvn"
elif [ "$op" = "pckcerts" ] && [ "$env" = "intel" ]; then
	curl -v -H "Ocp-Apim-Subscription-Key: $subscription_key" "${intel_pcs_server}/pckcerts?encrypted_ppid=$v_encppid&pceid=$v_pceid"
fi

if [ "$op" = "pckcrl" ] && [ "$env" = "scs" ]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/pckcrl?ca=$v_ca"  -H "Authorization: Bearer ${Bearer_token}" -k
elif [ "$op" = "pckcrl" ] && [ "$env" = "intel" ]; then
	curl -v "${intel_pcs_server}/pckcrl?ca=$v_ca"
fi

if [ "$op" = "qe" ] && [ "$env" = "scs" ]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/qe/identity" -H "Authorization: Bearer ${Bearer_token}" -k
elif [ "$op" = "qe" ] && [ "$env" = "intel" ]; then
	curl -v "${intel_pcs_server}/qe/identity"
fi

if [ "$op" = "tcb" ] && [ "$env" = "scs" ]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/tcb?fmspc=$v_fmspc" -H "Authorization: Bearer ${Bearer_token}" -k
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
	curl -X POST --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/push" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$PF_CREATE_JSON_FILE -k
fi

if [[ "$op" = "refresh" ]]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/refresh" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" -k
fi

if [[ "$op" = "tcbstatus" ]]; then
	curl --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/tcbstatus?pceid=$v_pceid" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" -k
fi
