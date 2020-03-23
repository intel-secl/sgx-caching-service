/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	"intel/isecl/scs/repository"
	"intel/isecl/lib/common/setup"
	"io"
	commLog "intel/isecl/lib/common/log"
	"github.com/pkg/errors"
)

type Admin struct {
	Flags           []string
	DatabaseFactory func() (repository.SCSDatabase, error)
	ConsoleWriter   io.Writer
}

var log = commLog.GetDefaultLogger()
var slog = commLog.GetSecurityLogger()

func (a Admin) Run(c setup.Context) error {
	fmt.Fprintln(a.ConsoleWriter, "Running admin setup...")
	envUser, _ := c.GetenvString("SCS_ADMIN_USERNAME", "Username for admin authentication")
	envPass, _ := c.GetenvSecret("SCS_ADMIN_PASSWORD", "Password for admin authentication")
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	_ = fs.String("user", envUser, "Username for admin authentication")
	_ = fs.String("pass", envPass, "Password for admin authentication")
	err := fs.Parse(a.Flags)
	if err != nil {
		return errors.Wrap(err, "setup admin: failed to parse cmd flags")
	}
	db, err := a.DatabaseFactory()
	if err != nil {
		log.WithError(err).Error("failed to open database")
		return errors.Wrap(err, "setup admin: failed to open database")
	}
	defer db.Close()
	return nil
}

func (a Admin) Validate(c setup.Context) error {
	return nil
}
