#!/bin/bash

echo "Setting up SGX Caching Related roles and user in AAS Database"

source ~/scs.env 2> /dev/null

#Get the value of AAS IP address and port. Default vlue is also provided.
aas_hostname=${AAS_API_URL:-"https://<aas.server.com>:8444/aas/v1"}
CURL_OPTS="-s -k"
CONTENT_TYPE="Content-Type: application/json"
ACCEPT="Accept: application/jwt"
CN="SCS TLS Certificate"

red=`tput setaf 1`
green=`tput setaf 2`
reset=`tput sgr0`

mkdir -p /tmp/setup/scs
tmpdir=$(mktemp -d -p /tmp/setup/scs)

cat >$tmpdir/aasAdmin.json <<EOF
{
	"username": "admin@aas",
	"password": "aasAdminPass"
}
EOF

#Get the AAS Admin JWT Token
curl_output=`curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "$ACCEPT" --data @$tmpdir/aasAdmin.json -w "%{http_code}" $aas_hostname/token`
Bearer_token=`echo $curl_output | rev | cut -c 4- | rev`

dnf install -qy jq

# This routined checks if sgx caching service user exists and reurns user id
# it creates a new user if one does not exist
create_scs_user()
{
cat > $tmpdir/user.json << EOF
{
	"username":"$SCS_ADMIN_USERNAME",
	"password":"$SCS_ADMIN_PASSWORD"
}
EOF

	#check if user already exists
	curl $CURL_OPTS -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/user_response.json -w "%{http_code}" $aas_hostname/users?name=$SCS_ADMIN_USERNAME > $tmpdir/user-response.status

	len=$(jq '. | length' < $tmpdir/user_response.json)
	if [ $len -ne 0 ]; then
		user_id=$(jq -r '.[0] .user_id' < $tmpdir/user_response.json)
	else
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/user.json -o $tmpdir/user_response.json -w "%{http_code}" $aas_hostname/users > $tmpdir/user_response.status

		local status=$(cat $tmpdir/user_response.status)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/user_response.json ]; then
			user_id=$(jq -r '.user_id' < $tmpdir/user_response.json)
			if [ -n "$user_id" ]; then
				echo "${green} Created scs user, id: $user_id ${reset}"
			fi
		fi
	fi
}

# This routined checks if scs CertApprover/CacheManager roles exist and reurns those role ids
# it creates above roles if not present in AAS db
create_roles()
{
cat > $tmpdir/certroles.json << EOF
{
	"service": "CMS",
	"name": "CertApprover",
	"context": "CN=$CN;SAN=$SAN_LIST;CERTTYPE=TLS"
}
EOF

cat > $tmpdir/hostregroles.json << EOF
{
	"service": "SCS",
	"name": "CacheManager",
	"context": ""
}
EOF

	#check if CertApprover role already exists
	curl $CURL_OPTS -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/role_response.json -w "%{http_code}" $aas_hostname/roles?name=CertApprover > $tmpdir/role_response.status

	cms_role_id=$(jq --arg SAN $SAN_LIST -r '.[] | select ( .context | ( contains("SCS") and contains($SAN)))' < $tmpdir/role_response.json | jq -r '.role_id')
	if [ -z $cms_role_id ]; then
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/certroles.json -o $tmpdir/role_response.json -w "%{http_code}" $aas_hostname/roles > $tmpdir/role_response-status.json

		local status=$(cat $tmpdir/role_response-status.json)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/role_response.json ]; then
			cms_role_id=$(jq -r '.role_id' < $tmpdir/role_response.json)
		fi
	fi

	#check if CacheManager role already exists
	curl $CURL_OPTS -H "Authorization: Bearer ${Bearer_token}" -o $tmpdir/role_resp.json -w "%{http_code}" $aas_hostname/roles?name=CacheManager > $tmpdir/role_resp.status

	len=$(jq '. | length' < $tmpdir/role_resp.json)
	if [ $len -ne 0 ]; then
		scs_role_id=$(jq -r '.[0] .role_id' < $tmpdir/role_resp.json)
	else
		curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/hostregroles.json -o $tmpdir/role_resp.json -w "%{http_code}" $aas_hostname/roles > $tmpdir/role_resp-status.json

		local status=$(cat $tmpdir/role_resp-status.json)
		if [ $status -ne 201 ]; then
			return 1
		fi

		if [ -s $tmpdir/role_resp.json ]; then
			scs_role_id=$(jq -r '.role_id' < $tmpdir/role_resp.json)
		fi
	fi
	ROLE_ID_TO_MAP=`echo \"$cms_role_id\",\"$scs_role_id\"`
}

#Maps scs user to CertApprover/CacheManager Roles
mapUser_to_role()
{
cat >$tmpdir/mapRoles.json <<EOF
{
	"role_ids": [$ROLE_ID_TO_MAP]
}
EOF

	curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/mapRoles.json -o $tmpdir/mapRoles_response.json -w "%{http_code}" $aas_hostname/users/$user_id/roles > $tmpdir/mapRoles_response-status.json

	local status=$(cat $tmpdir/mapRoles_response-status.json)
	if [ $status -ne 201 ]; then
		return 1
	fi
}

SCS_SETUP_API="create_scs_user create_roles mapUser_to_role"
status=
for api in $SCS_SETUP_API
do
	eval $api
    	status=$?
	if [ $status -ne 0 ]; then
		break;
	fi
done

if [ $status -ne 0 ]; then
	echo "${red} SGX Caching Service user/roles creation failed.: $api ${reset}"
	exit 1
else
	echo "${green} SGX Caching Service user/roles creation succeded ${reset}"
fi

#Get Token for SGX Cachine Service user and configure it in scs config.
curl $CURL_OPTS -X POST -H "$CONTENT_TYPE" -H "$ACCEPT" --data @$tmpdir/user.json -o $tmpdir/scs_token-resp.json -w "%{http_code}" $aas_hostname/token > $tmpdir/get_scs_token-response.status

status=$(cat $tmpdir/get_scs_token-response.status)
if [ $status -ne 200 ]; then
	echo "${red} Couldn't get bearer token for scs user ${reset}"
else
	export BEARER_TOKEN=`cat $tmpdir/scs_token-resp.json`
	echo "************************************************************************************************************************************************"
	echo $BEARER_TOKEN
	echo "************************************************************************************************************************************************"
	echo "${green} copy the above token and paste it against BEARER_TOKEN in scs.env ${reset}"
fi

# cleanup
rm -rf $tmpdir
