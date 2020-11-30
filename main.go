/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"fmt"
	"intel/isecl/scs/v3/constants"
	_ "intel/isecl/scs/v3/swagger/docs"
	"os"
	"os/user"
	"strconv"
)

func openLogFiles() (logFile *os.File, httpLogFile *os.File, secLogFile *os.File, err error) {
	logFile, err = os.OpenFile(constants.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = os.Chmod(constants.LogFile, 0664); err != nil {
		return nil, nil, nil, err
	}

	httpLogFile, err = os.OpenFile(constants.HTTPLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = os.Chmod(constants.HTTPLogFile, 0664); err != nil {
		return nil, nil, nil, err
	}

	secLogFile, err = os.OpenFile(constants.SecLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, nil, err
	}
	if err = os.Chmod(constants.SecLogFile, 0664); err != nil {
		return nil, nil, nil, err
	}

	scsUser, err := user.Lookup(constants.SCSUserName)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Could not find user '%s'", constants.SCSUserName)
	}

	uid, err := strconv.Atoi(scsUser.Uid)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Could not parse scs user uid '%s'", scsUser.Uid)
	}

	gid, err := strconv.Atoi(scsUser.Gid)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Could not parse scs user gid '%s'", scsUser.Gid)
	}

	err = os.Chown(constants.HTTPLogFile, uid, gid)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Could not change file ownership for file: '%s'", constants.HTTPLogFile)
	}

	err = os.Chown(constants.SecLogFile, uid, gid)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Could not change file ownership for file: '%s'", constants.SecLogFile)
	}

	err = os.Chown(constants.LogFile, uid, gid)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("Could not change file ownership for file: '%s'", constants.LogFile)
	}

	return
}

func main() {
	l, h, s, err := openLogFiles()
	var app *App
	if err != nil {
		app = &App{
			LogWriter: os.Stdout,
		}
	} else {
		defer l.Close()
		defer h.Close()
		defer s.Close()
		app = &App{
			LogWriter:     l,
			HTTPLogWriter: h,
			SecLogWriter:  s,
		}
	}
	err = app.Run(os.Args)
	if err != nil {
		fmt.Println("Application returned with error:", err.Error())
		os.Exit(1)
	}
}
