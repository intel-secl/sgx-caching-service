/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

 import (
	 "intel/isecl/lib/common/setup"
	 "intel/isecl/sgx-caching-service/constants"
	 "intel/isecl/lib/common/crypt"
	 "intel/isecl/sgx-caching-service/config"
	 "github.com/pkg/errors"
	 "crypto/tls"
	 "io"
	 "os"
	 "io/ioutil"
	 "net/http"
 )
 
 type Root_Ca struct {
	 Flags            []string
	 ConsoleWriter    io.Writer
	 Config           *config.Configuration
 }

 func (ca Root_Ca) Run(c setup.Context) error {
	log.Trace("tasks/rootca:Run() Entering")
	defer log.Trace("tasks/rootca:Run() Leaving")

        url := ca.Config.CMSBaseUrl + "ca-certificates"
        req, _ := http.NewRequest("GET", url, nil)
        req.Header.Add("accept", "application/x-pem-file")
        httpClient := &http.Client{
                                Transport: &http.Transport{
                                        TLSClientConfig: &tls.Config{
                                                InsecureSkipVerify: true,
                                                },
                                        },
                                }

        res, err := httpClient.Do(req)
        if err != nil {
		return errors.Wrapf(err, "tasks/rootca:Run() Could not get response from http client")
        }
        defer res.Body.Close()
        body, _ := ioutil.ReadAll(res.Body)
        err = crypt.SavePemCertWithShortSha1FileName(body, constants.RootCADirPath)
        if err != nil {
		return errors.Wrapf(err, "tasks/rootca:Run() Could not store Certificate")
        }

        return nil
 }
 
 func (ca Root_Ca) Validate(c setup.Context) error {
	log.Trace("tasks/rootca:Validate() Entering")
	defer log.Trace("tasks/rootca:Validate() Leaving")

	 _, err := os.Stat(constants.RootCADirPath)	 
	 if os.IsNotExist(err) {
		 return errors.Wrapf(err, "tasks/rootca:validate() RootCACertFile is not configured")
	 }
	 return nil
 }
