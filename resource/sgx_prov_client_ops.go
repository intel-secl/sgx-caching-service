/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"bytes"
	"encoding/json"
	"fmt"
	"intel/isecl/scs/v5/config"
	"intel/isecl/scs/v5/domain"
	"net/http"
	"time"

	"github.com/pkg/errors"
)

func getRespFromProvServer(req *http.Request, client domain.HttpClient, conf *config.Configuration) (*http.Response, error) {
	var err error
	var resp *http.Response

	if conf == nil {
		return nil, errors.New("getRespFromProvServer(): Configuration not provided")
	}

	if client == nil {
		return nil, errors.New("getRespFromProvServer(): Empty client provided")
	}

	var retries int = conf.RetryCount
	var timeBwCalls int = conf.WaitTime

	for retries >= 0 {
		resp, err := client.Do(req)

		if err == nil {
			return resp, err
		}

		if resp != nil && resp.StatusCode < http.StatusInternalServerError {
			return resp, err
		}
		retries -= 1
		if retries <= 0 {
			log.Error("getRespFromProvServer:ERROR ", err)
			return resp, errors.Wrap(err, "getRespFromProvServer: Getting reponse from PCS server Failed")
		}

		select {
		case <-time.After(time.Duration(timeBwCalls) * time.Second):
		}
	}
	return resp, err
}

func getPckCertFromProvServer(encryptedPPID, pceID string, conf *config.Configuration, client *domain.HttpClient) (*http.Response, error) {
	log.Trace("resource/sgx_prov_client_ops: getPckCertFromProvServer() Entering")
	defer log.Trace("resource/sgx_prov_client_ops: getPckCertFromProvServer() Leaving")

	if conf == nil {
		return nil, errors.New("getPckCertFromProvServer(): Configuration not provided")
	}

	if client == nil {
		return nil, errors.New("getPckCertFromProvServer(): Empty client provided")
	}

	url := fmt.Sprintf("%s/pckcerts", conf.ProvServerInfo.ProvServerURL)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "getPckCertFromProvServer: Getpckcerts http request Failed")
	}

	req.Header.Add("Ocp-Apim-Subscription-Key", conf.ProvServerInfo.APISubscriptionkey)
	q := req.URL.Query()
	q.Add("encrypted_ppid", encryptedPPID)
	q.Add("pceid", pceID)

	req.URL.RawQuery = q.Encode()

	resp, err := getRespFromProvServer(req, *client, conf)

	if err != nil {
		return nil, errors.Wrap(err, "getPckCertFromProvServer: Getpckcerts call to PCS Server Failed")
	}
	return resp, nil
}

func getPckCertsWithManifestFromProvServer(manifest, pceID string, conf *config.Configuration, client *domain.HttpClient) (*http.Response, error) {
	log.Trace("resource/sgx_prov_client_ops: getPckCertsWithManifestFromProvServer() Entering")
	defer log.Trace("resource/sgx_prov_client_ops: getPckCertsWithManifestFromProvServer() Leaving")

	if conf == nil {
		return nil, errors.New("getPckCertsWithManifestFromProvServer(): Configuration not provided")
	}

	if client == nil {
		return nil, errors.New("getPckCertsWithManifestFromProvServer(): Empty client provided")
	}

	url := fmt.Sprintf("%s/pckcerts", conf.ProvServerInfo.ProvServerURL)

	requestStr := map[string]string{
		"platformManifest": manifest,
		"pceid":            pceID}

	reqBytes, err := json.Marshal(requestStr)
	if err != nil {
		return nil, errors.Wrap(err, "getPckCertsWithManifestFromProvServer: Marshal error:"+err.Error())
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewBuffer(reqBytes))
	if err != nil {
		return nil, errors.Wrap(err, "getPckCertsWithManifestFromProvServer: Getpckcerts http request Failed")
	}

	req.Header.Add("Ocp-Apim-Subscription-Key", conf.ProvServerInfo.APISubscriptionkey)
	req.Header.Add("Content-Type", "application/json")

	resp, err := getRespFromProvServer(req, *client, conf)
	if err != nil {
		log.Error("error came: ", err)
		return nil, errors.Wrap(err, "getPckCertsWithManifestFromProvServer: Getpckcerts call to PCS Server Failed")
	}
	return resp, nil
}

func getPckCrlFromProvServer(ca, encoding string, conf *config.Configuration, client *domain.HttpClient) (*http.Response, error) {
	log.Trace("resource/sgx_prov_client_ops: getPckCrlFromProvServer() Entering")
	defer log.Trace("resource/sgx_prov_client_ops: getPckCrlFromProvServer() Leaving")

	if conf == nil {
		return nil, errors.New("getPckCrlFromProvServer(): Configuration not provided")
	}

	if client == nil {
		return nil, errors.New("getPckCrlFromProvServer(): Empty client provided")
	}

	url := fmt.Sprintf("%s/pckcrl", conf.ProvServerInfo.ProvServerURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "getPckCrlFromProvServer(): GetpckCrl http request Failed")
	}

	q := req.URL.Query()
	q.Add("ca", ca)
	q.Add("encoding", encoding)

	req.URL.RawQuery = q.Encode()

	resp, err := getRespFromProvServer(req, *client, conf)

	if err != nil {
		return nil, errors.Wrap(err, "getPckCrlFromProvServer(): GetPckCrl call to PCS Server Failed")
	}
	return resp, nil
}

func getFmspcTcbInfoFromProvServer(fmspc string, conf *config.Configuration, client *domain.HttpClient) (*http.Response, error) {
	log.Trace("resource/sgx_prov_client_ops: getFmspcTcbInfoFromProvServer() Entering")
	defer log.Trace("resource/sgx_prov_client_ops: getFmspcTcbInfoFromProvServer() Leaving")

	if conf == nil {
		return nil, errors.New("getFmspcTcbInfoFromProvServer(): Configuration not provided")
	}

	if client == nil {
		return nil, errors.New("getFmspcTcbInfoFromProvServer(): Empty client provided")
	}

	url := fmt.Sprintf("%s/tcb", conf.ProvServerInfo.ProvServerURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "getFmspcTcbInfoFromProvServer(): GetTcb http request Failed")
	}

	q := req.URL.Query()
	q.Add("fmspc", fmspc)

	req.URL.RawQuery = q.Encode()

	resp, err := getRespFromProvServer(req, *client, conf)

	if err != nil {
		return nil, errors.Wrap(err, "getFmspcTcbInfoFromProvServer(): GetTcb call to PCS Server Failed")
	}
	return resp, nil
}

func getQeInfoFromProvServer(conf *config.Configuration, client *domain.HttpClient) (*http.Response, error) {
	log.Trace("resource/sgx_prov_client_ops: getQeInfoFromProvServer() Entering")
	defer log.Trace("resource/sgx_prov_client_ops: getQeInfoFromProvServer() Leaving")

	if conf == nil {
		return nil, errors.New("getQeInfoFromProvServer(): Configuration not provided")
	}

	if client == nil {
		return nil, errors.New("getQeInfoFromProvServer(): Empty client provided")
	}

	url := fmt.Sprintf("%s/qe/identity", conf.ProvServerInfo.ProvServerURL)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, errors.Wrap(err, "getQeInfoFromProvServer(): getQeIdentity http request Failed")
	}

	resp, err := getRespFromProvServer(req, *client, conf)

	if err != nil {
		return nil, errors.Wrap(err, "getQeInfoFromProvServer(): getQeIdentity call to PCS Server Failed")
	}
	return resp, nil
}
