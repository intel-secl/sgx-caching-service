module intel/isecl/scs

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/jinzhu/gorm v1.9.12
	github.com/lib/pq v1.3.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.4.2
	github.com/stretchr/testify v1.5.1
	golang.org/x/crypto master
	golang.org/x/time master
	gopkg.in/yaml.v2 v2.2.8
	intel/isecl/lib/clients v1.0.0
	intel/isecl/lib/common v1.0.0-Beta
)

replace intel/isecl/lib/common => gitlab.devtools.intel.com/sst/isecl/lib/common.git v2.1/develop
replace intel/isecl/lib/clients => gitlab.devtools.intel.com/sst/isecl/lib/clients.git v2.1/develop
