/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */

package tasks

import (
	"fmt"
	"intel/isecl/lib/clients"
	"intel/isecl/lib/common/crypt"
	commLog "intel/isecl/lib/common/log"
	"intel/isecl/lib/common/setup"
	"intel/isecl/sgx-caching-service/config"
	consts "intel/isecl/sgx-caching-service/constants"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/pkg/errors"
)

var secLog = commLog.GetSecurityLogger()

type JWT struct {
	Flags         []string
	Config        *config.Configuration
	ConsoleWriter io.Writer
}

func (jwt JWT) Run(c setup.Context) error {
	fmt.Fprintln(jwt.ConsoleWriter, "Running jwt setup...")

	var err error
	if jwt.Validate(c) == nil {
		fmt.Println("setup download-aas-jwt-cert: setup task already complete. Skipping...")
		log.Trace("tasks/jwt:Run() AAS configuration config already setup, skipping ...")
		return nil
	}

	var aasURL string
	if aasURL, err = c.GetenvString("AAS_API_URL", "AAS Server URL"); err != nil {
		return errors.Wrap(err, "tasks/jwt:Run AAS endpoint not set in environment")
	}

	//Fetch JWT Certificate from AAS
	err = fnGetJwtCerts(aasURL)
	if err != nil {
		log.Tracef("tasks/jwt:Run() %+v", err)
		return errors.Wrap(err, "tasks/jwt:Run() Failed to fetch JWT Auth Certs")
	}

	log.Info("tasks/jwt:Run() JWT setup task successful")
	return nil
}

func fnGetJwtCerts(aasURL string) error {
	url := aasURL + "noauth/jwt-certificates"
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("accept", "application/x-pem-file")
	secLog.Debugf("tasks/jwt:fnGetJwtCerts() Connecting to AAS Endpoint %s", url)

	hc, err := clients.HTTPClientWithCADir(consts.TrustedCAsStoreDir)
	if err != nil {
		return errors.Wrap(err, "tasks/jwt:fnGetJwtCerts() Error setting up HTTP client")
	}

	res, err := hc.Do(req)
	if err != nil {
		return errors.Wrap(err, "tasks/jwt:fnGetJwtCerts() Could not retrieve jwt certificate")
	}
	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "tasks/jwt:fnGetJwtCerts() Error while reading response body")
	}

	err = crypt.SavePemCertWithShortSha1FileName(body, consts.TrustedJWTSigningCertsDir)
	if err != nil {
		return errors.Wrap(err, "tasks/jwt:fnGetJwtCerts() Error while saving certificate")
	}
	return nil
}

func (jwt JWT) Validate(c setup.Context) error {
	_, err := os.Stat(consts.TrustedJWTSigningCertsDir)
	if os.IsNotExist(err) {
		return errors.Wrap(err, "tasks/jwt:Validate() JWT certificate directory does not exist")
	}

	isJWTCertExist := isPathContainPemFile(consts.TrustedJWTSigningCertsDir)

	if !isJWTCertExist {
		return errors.New("tasks/jwt:Validate() AAS JWT certs not found")
	}
	return nil
}

func isPathContainPemFile(name string) bool {
	f, err := os.Open(name)
	if err != nil {
		log.WithError(err).Errorf("tasks/jwt:isPathContainPemFile() Erron while opening file: %s", name)
		return false
	}
	defer f.Close()

	// read in ONLY one file
	fname, err := f.Readdir(1)

	// if EOF detected path is empty
	if err != io.EOF && len(fname) > 0 && strings.HasSuffix(fname[0].Name(), ".pem") {
		log.Debug("tasks/jwt:isPathContainPemFile() fname is ", fname[0].Name())
		_, errs := crypt.GetCertFromPemFile(name + "/" + fname[0].Name())
		if errs == nil {
			log.Debug("tasks/jwt:isPathContainPemFile() full path valid PEM ", name+"/"+fname[0].Name())
			return true
		}
	}
	return false
}
