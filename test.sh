#!/bin/sh
unset http_proxy
unset https_proxy

op="$1"
env="$2"

if [[ "x$2" = "x" ]]; then
	env="scs"
fi

echo "Operation:$op, Environment:$env"

subscription_key=9e0153b3f0c948d9ade866635f039e1e
#subscription_key=66fac45aa4a94c71b075e64179eae0e8

v_encppid="974F57D49D60914F44C0A7B897035FA0114A4C3659316FF56354B122896AD4CEBE559031095010553998054A578578CC979A84C62337DD17AB96BAAA00DCD252B806EDC8CA405341214522C498A996CF73106E2A91A45F4E5710360DD32240F3D869479A408166E470A033DBA4B6241E8E7497F33F44BF885BFB87975D6AB769C4EDE1FBAC5840EE612CC54674CC5CF9DCE0CD5302340555D0EC1670D73C0500B38201143AD379FB8776202856681623C2D3F062E781D04FB0A513B48AC9A416CAB5448795205302F5A020A2DACBA7351A56F6DE92745D9AD49D11C62BA4579C377BCCB6F717D9A6CC20DB2E3765C1CF5E87111EB492ED1CE70DC4E2D22BA396BB8648CF315022A2A066323269D2E79B17CCB13BCEFDEA7A3E428DCC98FD14006D9DE187FC245A6D9EECE97C2D14BE8750EA25732854A84541B5B868164A0AAEE776BC98699CDD69169994A0B303F950491EA7B0F620FC0F1492553697D30701030CA9C9F70295845F8876A0B90E72889927BA29AA5BC32B3D340D4B7F6A0156"

Bearer_token="eyJhbGciOiJSUzM4NCIsImtpZCI6Ijc1NmVlMWU5ZjdiM2M3MzRlM2I4MzgxZTBhNjgwZWM2NmFlOWIyYmQiLCJ0eXAiOiJKV1QifQ.eyJyb2xlcyI6W3sic2VydmljZSI6IkNNUyIsIm5hbWUiOiJDZXJ0QXBwcm92ZXIiLCJjb250ZXh0IjoiQ049U0dYQUdFTlQgVExTIENlcnRpZmljYXRlO1NBTj0xMC4xLjY4LjIyMztDRVJUVFlQRT1UTFMifV0sImV4cCI6MTcyNTcwNzAyNywiaWF0IjoxNTY4MDI3MDI3LCJpc3MiOiJBQVMgSldUIElzc3VlciIsInN1YiI6InVzZXIxQHNneGFnZW50In0.Eqr_BQmmWOFiQzU8Y57iwvzi4t_lwJoiG9KXek5FlrM_Vw3fB-MhVw3xhjD8ZfXJF7qQL2CWT4plL9-T2L5kVH01iERIGnzVYXQEWm0QfXKWMCezRqPp3pXXaIZMfdSGJImVURJMs39eTBEkdzGRIl7CYEjUmml4gZT6nz_iM1DpW_nTHz2UgopEFrLzKQpFcoZgGjp99Yuv8r38XebEIu7SYQmaiUnzPki7Q1NvBwaNh_we75jElhxIN7LJKzNicH1KnAkTKTqGUl8a67x8ygHqp-VwRCoxiya8r49LT3rmEkIBWDi6eRyJbJRN05NyF1OiksH0hTadMWEXMyZ2Z8yUmF8H-jJQFvXoSCtmxEDVqtGNOcKfGIHkrF-Mw-za3EQOYBHghKq6lg0nTBhaGLdPNrHlNWFQuA4KaNyIgiANmUI33EcWsRzJUggJMrfdRJj19nD224GFGEKb3tyVjJmlUxr0hVtWvRO-Hkpv7a0QGVKn5E5ckGtBecRz4uqE"
v_cpusvn="02030205FF8000000000000000000000"
v_pcesvn="0700"
v_pceid="0000"
v_qeid="D475493A08E576404388A928DA23EA15"
v_ca="processor"
v_fmspc="10906ec10000"

hostname="127.0.0.1"
port=9443

#v_ca="platform"

if [ "$op" = "pckcert" ] && [ "$env" = "scs" ]; then
	curl -X GET -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/pckcert?encrypted_ppid=$v_encppid&cpusvn=$v_cpusvn&pcesvn=$v_pcesvn&pceid=$v_pceid&qeid=$v_qeid" -s --insecure

elif [ "$op" = "pckcert" ] && [ "$env" = "intel" ]; then

	export http_proxy=http://proxy-us.intel.com:911/
	export https_proxy=http://proxy-us.intel.com:911/
	curl -X GET -vvv -H "Ocp-Apim-Subscription-Key: $subscription_key"  "https://sbx.api.trustedservices.intel.com/sgx/certification/v1/pckcert?encrypted_ppid=$v_encppid&cpusvn=$v_cpusvn&pcesvn=$v_pcesvn&pceid=$v_pceid" 

	unset http_proxy
	unset https_proxy
fi


if [ "$op" = "pckcrl" ] && [ "$env" = "scs" ]; then
	curl -X GET -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/pckcrl?ca=$v_ca" -s --insecure
elif [ "$op" = "pckcrl" ] && [ "$env" = "intel" ]; then
	export http_proxy=http://proxy-us.intel.com:911/
	export https_proxy=http://proxy-us.intel.com:911/
	curl -X GET -vvv "https://sbx.api.trustedservices.intel.com/sgx/certification/v1/pckcrl?ca=$v_ca" 
	unset http_proxy
	unset https_proxy
fi


if [ "$op" = "qe" ] && [ "$env" = "scs" ]; then
	curl -X GET -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/qe/identity" -s --insecure

elif [ "$op" = "qe" ] && [ "$env" = "intel" ]; then
	export http_proxy=http://proxy-us.intel.com:911/
	export https_proxy=http://proxy-us.intel.com:911/
	curl -X GET -vvv "https://sbx.api.trustedservices.intel.com/sgx/certification/v1/qe/identity" 
	unset http_proxy
	unset https_proxy
elif [ "$op" = "qe" ] && [ "$env" = "nodejs" ]; then
	curl -X GET -vvv --tlsv1.2 "https://$hostname:8081/sgx/certification/v1/qe/identity" -s --insecure
fi


if [ "$op" = "fmspc" ] && [ "$env" = "scs" ]; then
	curl -X GET -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/certification/v1/tcb?fmspc=$v_fmspc" -s --insecure

elif [ "$op" = "fmspc" ] && [ "$env" = "intel" ]; then
	export http_proxy=http://proxy-us.intel.com:911/
	export https_proxy=http://proxy-us.intel.com:911/
	curl -X GET -vvv "https://sbx.api.trustedservices.intel.com/sgx/certification/v1/tcb?fmspc=$v_fmspc" 
	unset http_proxy
	unset https_proxy
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

	curl -X POST -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/push" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$PF_CREATE_JSON_FILE -s --insecure

fi





if [[ "$op" = "refresh" ]]; then
	curl -X GET -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/refresh?type=certs" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}"  -s --insecure

	curl -X GET -vvv --tlsv1.2 "https://$hostname:$port/scs/sgx/platforminfo/refresh" -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}"  -s --insecure
fi
