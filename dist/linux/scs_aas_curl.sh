#!/bin/bash
#Steps:
#Get token from AAS

echo "Setting up SCS Related roles and user in AAS Database"

#Get the value of AAS IP address and port. Default vlue is also provided.
aas_hostname=${AAS_URL:-"https://10.80.245.104:8444"}
CURL_OPTS="-s -k"
IPADDR="10.80.245.104,127.0.0.1,localhost"
CN="SCS TLS Certificate"

mkdir -p /tmp/setup/scs
tmpdir=$(mktemp -d -p /tmp/setup/scs)

cat >$tmpdir/aasAdmin.json <<EOF
{
"username": "admin",
"password": "password"
}
EOF

#Get the JWT Token
curl_output=`curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Accept: application/jwt" --data @$tmpdir/aasAdmin.json -w "%{http_code}" $aas_hostname/aas/token`

Bearer_token=`echo $curl_output | rev | cut -c 4- | rev`
response_status=`echo "${curl_output: -3}"`

if rpm -q jq; then
	echo "JQ package installed"
else
	echo "JQ package not installed, please install jq package and try"
	exit 2
fi

#Create scsUser also get user id
create_scs_user() {
cat > $tmpdir/user.json << EOF
{
	"username":"scsuser@scs",
	"password":"scspassword"
}
EOF

curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/user.json -o $tmpdir/user_response.json -w "%{http_code}" $aas_hostname/aas/users > $tmpdir/createscsuser-response.status

local actual_status=$(cat $tmpdir/createscsuser-response.status)
if [ $actual_status -ne 201 ]; then
	local response_mesage=$(cat $tmpdir/user_response.json)
	if [ "$response_mesage" = "same user exists" ]; then
		return 2 
	fi
	return 1
fi

if [ -s $tmpdir/user_response.json ]; then
	user_id=$(jq -r '.user_id' < $tmpdir/user_response.json)
	if [ -n "$user_id" ]; then
		echo "Created user id: $user_id"
		SCS_USER_ID=$user_id;
	fi
fi
}

#Add SCS roles
#cms role(scs will create these roles where CN=SCS), getroles(api in aas that is to be map with), keyTransfer, keyCrud
create_user_roles() {

cat > $tmpdir/roles.json << EOF
{
	"service": "$1",
	"name": "$2",
	"context": "$3"
}
EOF

curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/roles.json -o $tmpdir/role_response.json -w "%{http_code}" $aas_hostname/aas/roles > $tmpdir/role_response-status.json

local actual_status=$(cat $tmpdir/role_response-status.json)
if [ $actual_status -ne 201 ]; then
	local response_mesage=$(cat $tmpdir/role_response.json)
	if [ "$response_mesage"="same role exists" ]; then
		return 2 
	fi
	return 1
fi

if [ -s $tmpdir/role_response.json ]; then
	role_id=$(jq -r '.role_id' < $tmpdir/role_response.json)
fi
echo "$role_id"
}

create_roles() {

	local cms_role_id=$( create_user_roles "CMS" "CertApprover" "CN=$CN;SAN=$IPADDR;CERTTYPE=TLS" ) #get roleid
	local scs_role_id=$( create_user_roles "SCS" "CacheManager" "" )
	ROLE_ID_TO_MAP=`echo \"$cms_role_id\",\"$scs_role_id\"`
	echo $ROLE_ID_TO_MAP
}

#Map scsUser to Roles
mapUser_to_role() {
cat >$tmpdir/mapRoles.json <<EOF
{
	"role_ids": [$ROLE_ID_TO_MAP]
}
EOF

curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Authorization: Bearer ${Bearer_token}" --data @$tmpdir/mapRoles.json -o $tmpdir/mapRoles_response.json -w "%{http_code}" $aas_hostname/aas/users/$user_id/roles > $tmpdir/mapRoles_response-status.json

local actual_status=$(cat $tmpdir/mapRoles_response-status.json)
if [ $actual_status -ne 201 ]; then
	return 1 
fi
}

SCS_SETUP_API="create_scs_user create_roles mapUser_to_role"

status=
for api in $SCS_SETUP_API
do
	echo $api
	eval $api
    	status=$?
    if [ $status -ne 0 ]; then
        echo "SCS-AAS User/Roles creation failed.: $api"
        break;
    fi
done

if [ $status -eq 0 ]; then
    echo "SCS Setup for AAS-CMS complete: No errors"
fi
if [ $status -eq 2 ]; then
    echo "SCS Setup for AAS-CMS already exists in AAS Database: No action will be done"
fi

#Get Token for SCS USER and configure it in scs config
curl $CURL_OPTS -X POST -H "Content-Type: application/json" -H "Accept: application/jwt" --data @$tmpdir/user.json -o $tmpdir/scs_token-response.json -w "%{http_code}" $aas_hostname/aas/token > $tmpdir/getscsusertoken-response.status

status=$(cat $tmpdir/getscsusertoken-response.status)
if [ $status -ne 200 ]; then
	echo "Couldn't get bearer token"
else
	export BEARER_TOKEN=`cat $tmpdir/scs_token-response.json`
	echo $BEARER_TOKEN
fi
