module intel/isecl/scs/v3

require (
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/google/uuid v1.1.1
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/jinzhu/gorm v1.9.12
	github.com/lib/pq v1.3.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.5.0
	github.com/stretchr/testify v1.5.1
	gopkg.in/yaml.v2 v2.2.8
	intel/isecl/lib/common/v3 v3.3.1
)

replace intel/isecl/lib/common/v3 => github.com/intel-secl/common/v3 v3.3.1
