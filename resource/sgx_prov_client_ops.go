/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/pkg/errors"
	"intel/isecl/scs/config"
	"net/http"
	"time"
)

func GetProvClientObj() (*http.Client, *config.Configuration, error) {
	conf := config.Global()
	if conf == nil {
		return nil, nil, errors.New("Configuration details not found")
	}

	timeout := time.Duration(500 * time.Second)
	client := &http.Client{
		Timeout: timeout,
	}

	return client, conf, nil
}

func GetPCKCertFromProvServer(EncryptedPPID string, PceId string) (*http.Response, error) {
	log.Trace("resource/sgx_prov_client_ops: GetPCKCertFromProvServer() Entering")
	defer log.Trace("resource/sgx_prov_client_ops: GetPCKCertFromProvServer() Leaving")
	client, conf, err := GetProvClientObj()
	if err != nil {
		return nil, errors.Wrap(err, "GetPCKCertFromProvServer: Cannot get provclient Object")
	}
	url := fmt.Sprintf("%s/pckcerts", conf.ProvServerInfo.ProvServerUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "GetPCKCertFromProvServer: Getpckcerts http request Failed")
	}

	req.Header.Add("Ocp-Apim-Subscription-Key", conf.ProvServerInfo.ApiSubscriptionkey)
	q := req.URL.Query()
	q.Add("encrypted_ppid", EncryptedPPID)
	q.Add("pceid", PceId)

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "GetPCKCertFromProvServer: Getpckcerts call to PCS Server Failed")
	}
	return resp, nil
}

func GetPCKCertsWithManifestFromProvServer(manifest string, pceId string) (*http.Response, error) {
	log.Trace("resource/sgx_prov_client_ops: GetPCKCertsWithManifestFromProvServer() Entering")
	defer log.Trace("resource/sgx_prov_client_ops: GetPCKCertsWithManifestFromProvServer() Leaving")
	client, conf, err := GetProvClientObj()
	if err != nil {
		return nil, errors.Wrap(err, "getPCKCertsWithManifestFromProvServer: Cannot get provclient Object")
	}
	url := fmt.Sprintf("%s/pckcerts", conf.ProvServerInfo.ProvServerUrl)

	requestStr := map[string]string{
		"platformManifest": manifest,
		"pceid":            pceId}

	reqBytes, err := json.Marshal(requestStr)
	if err != nil {
		return nil, errors.Wrap(err, "getPCKCertsWithManifestFromProvServer: Marshal error:"+err.Error())
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, errors.Wrap(err, "getPCKCertsWithManifestFromProvServer: Getpckcerts http request Failed")
	}

	req.Header.Add("Ocp-Apim-Subscription-Key", conf.ProvServerInfo.ApiSubscriptionkey)
	req.Header.Add("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		log.Error("error came: ", err)
		return nil, errors.Wrap(err, "getPCKCertsWithManifestFromProvServer: Getpckcerts call to PCS Server Failed")
	}
	return resp, nil
}

func GetPCKCRLFromProvServer(ca string) (*http.Response, error) {
	log.Trace("resource/sgx_prov_client_ops: GetPCKCRLFromProvServer() Entering")
	defer log.Trace("resource/sgx_prov_client_ops: GetPCKCRLFromProvServer() Leaving")
	client, conf, err := GetProvClientObj()
	if err != nil {
		return nil, errors.Wrap(err, "GetPCKCRLFromProvServer(): Cannot get provclient Object")
	}
	url := fmt.Sprintf("%s/pckcrl", conf.ProvServerInfo.ProvServerUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "GetPCKCRLFromProvServer(): GetpckCrl http request Failed")
	}

	q := req.URL.Query()
	q.Add("ca", ca)

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "GetPCKCRLFromProvServer(): GetPckCrl call to PCS Server Failed")
	}
	return resp, nil
}

func GetFmspcTcbInfoFromProvServer(fmspc string) (*http.Response, error) {
	log.Trace("resource/sgx_prov_client_ops: GetFmspcTcbInfoFromProvServer() Entering")
	defer log.Trace("resource/sgx_prov_client_ops: GetFmspcTcbInfoFromProvServer() Leaving")
	client, conf, err := GetProvClientObj()
	if err != nil {
		return nil, errors.Wrap(err, "GetFmspcTcbInfoFromProvServer(): Cannot get provclient Object")
	}
	url := fmt.Sprintf("%s/tcb", conf.ProvServerInfo.ProvServerUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "GetFmspcTcbInfoFromProvServer(): GetTcb http request Failed")
	}

	q := req.URL.Query()
	q.Add("fmspc", fmspc)

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "GetFmspcTcbInfoFromProvServer(): GetTcb call to PCS Server Failed")
	}
	return resp, nil
}

func GetQEInfoFromProvServer() (*http.Response, error) {
	log.Trace("resource/sgx_prov_client_ops: GetQEInfoFromProvServer() Entering")
	defer log.Trace("resource/sgx_prov_client_ops: GetQEInfoFromProvServer() Leaving")
	client, conf, err := GetProvClientObj()
	if err != nil {
		return nil, errors.Wrap(err, "GetQEInfoFromProvServer(): Cannot get provclient Object")
	}
	url := fmt.Sprintf("%s/qe/identity", conf.ProvServerInfo.ProvServerUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "GetQEInfoFromProvServer(): GetQeIdentity http request Failed")
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.Wrap(err, "GetQEInfoFromProvServer(): GetQeIdentity call to PCS Server Failed")
	}
	return resp, nil
}
