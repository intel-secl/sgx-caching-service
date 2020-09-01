/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"intel/isecl/scs/constants"
	_ "intel/isecl/scs/swagger/docs"
	"os"
	"os/user"
	"strconv"
)

func openLogFiles() (logFile *os.File, httpLogFile *os.File, secLogFile *os.File, err error) {
	logFile, err = os.OpenFile(constants.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	if err != nil {
		return nil, nil, nil, err
	}
	os.Chmod(constants.LogFile, 0664)

	httpLogFile, err = os.OpenFile(constants.HTTPLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, nil, err
	}
	os.Chmod(constants.HTTPLogFile, 0664)

	secLogFile, err = os.OpenFile(constants.SecLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return nil, nil, nil, err
	}
	os.Chmod(constants.SecLogFile, 0664)

	scsUser, err := user.Lookup(constants.SCSUserName)
	if err != nil {
		log.Errorf("Could not find user '%s'", constants.SCSUserName)
		return nil, nil, nil, err
	}

	uid, err := strconv.Atoi(scsUser.Uid)
	if err != nil {
		log.Errorf("Could not parse scs user uid '%s'", scsUser.Uid)
		return nil, nil, nil, err
	}

	gid, err := strconv.Atoi(scsUser.Gid)
	if err != nil {
		log.Errorf("Could not parse scs user gid '%s'", scsUser.Gid)
		return nil, nil, nil, err
	}

	err = os.Chown(constants.HTTPLogFile, uid, gid)
	if err != nil {
		log.Errorf("Could not change file ownership for file: '%s'", constants.HTTPLogFile)
		return nil, nil, nil, err
	}

	err = os.Chown(constants.SecLogFile, uid, gid)
	if err != nil {
		log.Errorf("Could not change file ownership for file: '%s'", constants.SecLogFile)
	}

	err = os.Chown(constants.LogFile, uid, gid)
	if err != nil {
		log.Errorf("Could not change file ownership for file: '%s'", constants.LogFile)
		return nil, nil, nil, err
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
		log.Error("Application returned with error: ", err)
		os.Exit(1)
	}
}
