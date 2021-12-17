module intel/isecl/scs/v5

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/google/uuid v1.2.0
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/jinzhu/gorm v1.9.16
	github.com/lib/pq v1.3.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.6.1
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
	intel/isecl/lib/common/v5 v5.0.0
)

replace intel/isecl/lib/common/v5 => gitlab.devtools.intel.com/sst/isecl/lib/common.git/v5 v5.0/develop
