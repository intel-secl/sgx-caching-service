module intel/isecl/scs/v5

require (
	github.com/google/uuid v1.2.0
	github.com/gorilla/handlers v1.4.2
	github.com/gorilla/mux v1.7.4
	github.com/jinzhu/gorm v1.9.16
	github.com/lib/pq v1.3.0
	github.com/pkg/errors v0.9.1
	github.com/sirupsen/logrus v1.7.0
	github.com/stretchr/testify v1.6.1
	gopkg.in/yaml.v3 v3.0.1
	intel/isecl/lib/common/v5 v5.0.0
)

replace intel/isecl/lib/common/v5 => github.com/intel-innersource/libraries.security.isecl.common/v5 v5.0/develop
