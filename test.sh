#!/bin/sh

op="$1"
env="$2"

if [[ "x$2" = "x" ]]; then
	env="scs"
fi

echo "Operation:$op, Environment:$env"

subscription_key=ec73a0f55ca348cb9f02371f2b9ca614

v_encppid="c6d80271c121b1ff45c7a917aa65c23d096544c1c26c93d068fdd1f53b7b083f91f84b10d5efb30d146d934143966fc1194a7025854afe65edf3ea177d2ba538d6350eb7aa06f5eb34bcb23b8efb546bc97bb90356454d9ecbe143c3742e8cd43e9d66850578f2ee4fcfe2473a99eb300a960044ee5142c41fe90b1d7804c3a218a272b509975eba9b66556b33b406c2b5771e1a8f7223f96bcd922252c1e96385082bdc52d3f91a06e8d27eecf087966c5396d38510dd0b6fc941261d3f3bbe6cb9dd6025f6e80cab274bf5275c570e390d33cf64db7fbbbdd402665165ab5c29a7d5ddee84a688fa62eedd70871fc15f226419aecff733bc7fd72a5a039b2ae518a03611e7461700e5228607d3b1012bc265c5df23cf2434e37e79f8eabadb5fcbe9b9b7b741848c1022a02fa8e968d3c4f5db72a993326345d5f473669b2a97abe5b7b630f39f05592a8cb4a3333e71c09731b521e315fbfd22632981f7c3d6bedb0cbdc55307c9f75a0b0150731028ceb1951daa550b0bccc82b45b5f1ef"

Bearer_token="eyJhbGciOiJSUzM4NCIsImtpZCI6Ijc1NmVlMWU5ZjdiM2M3MzRlM2I4MzgxZTBhNjgwZWM2NmFlOWIyYmQiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkNNUyIsIm5hbWUiOiJDZXJ0QXBwcm92ZXIiLCJjb250ZXh0IjoiQ049U0dYQUdFTlQgVExTIENlcnRpZmljYXRlO1NBTj0xMC4xLjY4LjIyMztDRVJUVFlQRT1UTFMifV0sImV4cCI6MTcyNTcwNzAyNywiaWF0IjoxNTY4MDI3MDI3LCJpc3MiOiJBQVMgSldUIElzc3VlciIsInN1YiI6InVzZXIxQHNneGFnZW50In0.Eqr_BQmmWOFiQzU8Y57iwvzi4t_lwJoiG9KXek5FlrM_Vw3fB-MhVw3xhjD8ZfXJF7qQL2CWT4plL9-T2L5kVH01iERIGnzVYXQEWm0QfXKWMCezRqPp3pXXaIZMfdSGJImVURJMs39eTBEkdzGRIl7CYEjUmml4gZT6nz_iM1DpW_nTHz2UgopEFrLzKQpFcoZgGjp99Yuv8r38XebEIu7SYQmaiUnzPki7Q1NvBwaNh_we75jElhxIN7LJKzNicH1KnAkTKTqGUl8a67x8ygHqp-VwRCoxiya8r49LT3rmEkIBWDi6eRyJbJRN05NyF1OiksH0hTadMWEXMyZ2Z8yUmF8H-jJQFvXoSCtmxEDVqtGNOcKfGIHkrF-Mw-za3EQOYBHghKq6lg0nTBhaGLdPNrHlNWFQuA4KaNyIgiANmUI33EcWsRzJUggJMrfdRJj19nD224GFGEKb3tyVjJmlUxr0hVtWvRO-Hkpv7a0QGVKn5E5ckGtBecRz4uqE"
v_cpusvn="0202ffffff8002000000000000000000"
v_pcesvn="0900"
v_pceid="0000"
v_qeid="0f16dfa4033e66e642af8fe358c18751"
v_ca="processor"
v_fmspc="00906ed50000"

hostname="127.0.0.1"
port=9443

if [ "$op" = "pckcert" ] && [ "$env" = "scs" ]; then
	curl -X GET -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/pckcert?encrypted_ppid=$v_encppid&cpusvn=$v_cpusvn&pcesvn=$v_pcesvn&pceid=$v_pceid&qeid=$v_qeid" -s --insecure

elif [ "$op" = "pckcert" ] && [ "$env" = "intel" ]; then
	curl -X GET -vvv -H "Ocp-Apim-Subscription-Key: $subscription_key" "https://api.trustedservices.intel.com/sgx/certification/v2/pckcerts?encrypted_ppid=$v_encppid&pceid=$v_pceid"
fi

if [ "$op" = "pckcrl" ] && [ "$env" = "scs" ]; then
	curl -X GET -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/pckcrl?ca=$v_ca" -s --insecure
elif [ "$op" = "pckcrl" ] && [ "$env" = "intel" ]; then
	curl -X GET -vvv "https://api.trustedservices.intel.com/sgx/certification/v2/pckcrl?ca=$v_ca"
fi

if [ "$op" = "qe" ] && [ "$env" = "scs" ]; then
	curl -X GET -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/qe/identity" -s --insecure

elif [ "$op" = "qe" ] && [ "$env" = "intel" ]; then
	curl -X GET -vvv "https://api.trustedservices.intel.com/sgx/certification/v2/qe/identity"
elif [ "$op" = "qe" ] && [ "$env" = "nodejs" ]; then
	curl -X GET -vvv --tlsv1.2 "https://$hostname:8081/sgx/certification/v1/qe/identity" -s --insecure
fi

if [ "$op" = "fmspc" ] && [ "$env" = "scs" ]; then
	curl -X GET -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/tcb?fmspc=$v_fmspc" -s --insecure

elif [ "$op" = "fmspc" ] && [ "$env" = "intel" ]; then
	curl -X GET -vvv "https://api.trustedservices.intel.com/sgx/certification/v2/tcb?fmspc=$v_fmspc"
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

#	curl -X POST -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/push" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$PF_CREATE_JSON_FILE -s --insecure
fi

if [[ "$op" = "refresh" ]]; then
	curl -X GET -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/refresh?type=certs" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}"  -s --insecure

	curl -X GET -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/refresh" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}"  -s --insecure
fi
