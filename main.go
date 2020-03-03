/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package main

import (
	"intel/isecl/sgx-caching-service/constants"
	"os"
	"os/user"
	"strconv"
)

func openLogFiles() (logFile *os.File, httpLogFile *os.File, secLogFile *os.File) {
	logFile, _ = os.OpenFile(constants.LogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0664)
	os.Chmod(constants.LogFile, 0664)

        httpLogFile, _ = os.OpenFile(constants.HTTPLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
        os.Chmod(constants.HTTPLogFile, 0664)

        secLogFile, _ = os.OpenFile(constants.SecLogFile, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0644)
        os.Chmod(constants.SecLogFile, 0664)

        scsUser, err := user.Lookup(constants.SCSUserName)
        if err != nil {
                log.Errorf("Could not find user '%s'", constants.SCSUserName)
        }

        uid, err := strconv.Atoi(scsUser.Uid)
        if err != nil {
                log.Errorf("Could not parse scs user uid '%s'", scsUser.Uid)
        }

        gid, err := strconv.Atoi(scsUser.Gid)
        if err != nil {
                log.Errorf("Could not parse scs user gid '%s'", scsUser.Gid)
        }

        err = os.Chown(constants.HTTPLogFile, uid, gid)
        if err != nil {
                log.Errorf("Could not change file ownership for file: '%s'", constants.HTTPLogFile)
        }

        err = os.Chown(constants.SecLogFile, uid, gid)
        if err != nil {
                log.Errorf("Could not change file ownership for file: '%s'", constants.SecLogFile)
        }

        err = os.Chown(constants.LogFile, uid, gid)
        if err != nil {
                log.Errorf("Could not change file ownership for file: '%s'", constants.LogFile)
        }

        return
}

func main() {
	log.Trace("main:main() Entering")
	defer log.Trace("main:main() Leaving")
        l, h, s := openLogFiles()
        defer l.Close()
        defer h.Close()
        defer s.Close()
        app := &App{
                LogWriter: l,
                HTTPLogWriter: h,
                SecLogWriter: s,
        }
        err := app.Run(os.Args)
        if err != nil {
		log.WithError(err).Error("main:main() SCS application error")
		log.Tracef("%+v",err)
                os.Exit(1)
        }
}
