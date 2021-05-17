/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package types

import (
	"time"
)

type LastRefresh struct {
	CompletedAt time.Time `json:"completed-at"`
	Status      string    `json:"status"`
}
