module intel/isecl/scs

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
	golang.org/x/crypto master
	golang.org/x/time master
	gopkg.in/yaml.v2 v2.2.8
	intel/isecl/lib/common/v3 v3.0.0
)

replace intel/isecl/lib/common/v3 => github.com/intel-secl/common/v3 v3.0.0
