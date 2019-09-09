/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package tasks

import (
	"flag"
	"fmt"
	"intel/isecl/sgx-caching-service/repository"
	"intel/isecl/lib/common/setup"
	"io"

	log "github.com/sirupsen/logrus"
)

type Admin struct {
	Flags           []string
	DatabaseFactory func() (repository.SCSDatabase, error)
	ConsoleWriter   io.Writer
}

func (a Admin) Run(c setup.Context) error {
	fmt.Fprintln(a.ConsoleWriter, "Running admin setup...")
	fs := flag.NewFlagSet("admin", flag.ContinueOnError)
	err := fs.Parse(a.Flags)
	if err != nil {
		return err
	}
	db, err := a.DatabaseFactory()
	if err != nil {
		log.WithError(err).Error("failed to open database")
		return err
	}
	defer db.Close()
	return nil
}

func (a Admin) Validate(c setup.Context) error {
	return nil
}
