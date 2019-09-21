/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
 package tasks

 import (
	 "errors"
	 "fmt"
	 "intel/isecl/lib/common/setup"
	 "intel/isecl/sgx-caching-service/constants"
	 "intel/isecl/lib/common/crypt"
	 "intel/isecl/sgx-caching-service/config"
	 "crypto/tls"
	 "io"
	 "os"
	 "io/ioutil"
	 "net/http"
	 log "github.com/sirupsen/logrus"
 )
 
 type Root_Ca struct {
	 Flags            []string
	 ConsoleWriter    io.Writer
	 Config           *config.Configuration
 }

 func (ca Root_Ca) Run(c setup.Context) error {
        log.WithField("CMS", ca.Config.CMSBaseUrl).Debug("URL dump")
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
        	log.WithError(err).Debug("Could not retrieve Root CA Certificate from CMS")
                return fmt.Errorf("Could not retrieve Root CA certificate from CMS")
        }
        defer res.Body.Close()
        body, _ := ioutil.ReadAll(res.Body)
        err = crypt.SavePemCertWithShortSha1FileName(body, constants.RootCADirPath)
        if err != nil {
                fmt.Println("Could not store Certificate")
                return fmt.Errorf("Certificate setup: %v", err)
        }

        log.WithField("Retrieve Root CA cert", "compledted").Debug("successfully")
        return nil
 }
 
 func (ca Root_Ca) Validate(c setup.Context) error {
	 _, err := os.Stat(constants.RootCADirPath)	 
	 if os.IsNotExist(err) {
		 return errors.New("RootCACertFile is not configured")
	 }
	 return nil
 }
 
