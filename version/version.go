/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package version

import (
	"fmt"
	"intel/isecl/scs/v4/constants"
)

var Version = ""
var GitHash = ""
var BuildDate = ""

func GetVersion() string {
	verStr := fmt.Sprintf("Service Name: %s\n", constants.ExplicitServiceName)
	verStr += fmt.Sprintf("Version: %s-%s\n", Version, GitHash)
	verStr += fmt.Sprintf("Build Date: %s\n", BuildDate)
	return verStr
}
