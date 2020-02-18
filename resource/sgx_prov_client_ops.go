package resource

import (
	"fmt"
	"time"
	"net/http"
	"net/url"
	"github.com/pkg/errors"
	"intel/isecl/sgx-caching-service/config"
)

func GetProvClientObj()(*http.Client, *config.Configuration, error){
	log.Trace("resource/sgx_prov_client_ops: GetProvClientObj() Entering")
	defer log.Trace("resource/sgx_prov_client_ops: GetProvClientObj() Leaving")

	conf:= config.Global()
	if conf == nil {
		return nil, nil, errors.New("Configuration pointer is null")
	}

	timeout := time.Duration(5 * time.Second)
	client  := &http.Client{
		Timeout: timeout,
	}

	if len(conf.ProxyUrl) > 0 {
		proxyUrl, err := url.Parse(conf.ProxyUrl)
		if err != nil {
			return nil, nil, errors.Wrap(err, "GetProvClientObj: Failed to Parse Proxy Url")
		}
		client.Transport = &http.Transport{ Proxy: http.ProxyURL(proxyUrl)}
		log.WithField("Proxy URL", conf.ProxyUrl).Debug("Intel Prov Client OPS")
	}
	return client, conf, nil
}

func GetPCKCertFromProvServer(EncryptedPPID string, CpuSvn string, PceSvn string, PceId string) (*http.Response, error) {
	log.Trace("resource/sgx_prov_client_ops: GetPCKCertFromProvServer() Entering")
	defer log.Trace("resource/sgx_prov_client_ops: GetPCKCertFromProvServer() Leaving")

	client, conf, err := GetProvClientObj()
	if err != nil {
		return nil, errors.Wrap(err, "GetPCKCertFromProvServer: Cannot get provclient Object")
	}
	url := fmt.Sprintf("%s/pckcerts", conf.ProvServerInfo.ProvServerUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
	    return nil, errors.Wrap(err, "GetPCKCertFromProvServer: GET http request Failed")
	}

	req.Header.Add("Ocp-Apim-Subscription-Key", conf.ProvServerInfo.ApiSubscriptionkey)
	q := req.URL.Query()
	q.Add("encrypted_ppid", EncryptedPPID)
	q.Add("pceid", PceId)

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
	    return nil, errors.Wrap(err, "GetPCKCertFromProvServer: GET pckcerts call to PCS failed")
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
	    return nil, errors.Wrap(err, "GetPCKCRLFromProvServer(): GET http request Failed")
	}

	q := req.URL.Query()
	q.Add("ca", ca)

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
	    return nil, errors.Wrap(err, "GetPCKCRLFromProvServer(): Cannot get client req")
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
	    return nil, errors.Wrap(err, "GetFmspcTcbInfoFromProvServer(): GET http request Failed")
	}

	q := req.URL.Query()
	q.Add("fmspc", fmspc)

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do(req)
	if err != nil {
	    return nil, errors.Wrap(err, "GetFmspcTcbInfoFromProvServer(): Cannot get client req")
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
	    return nil, errors.Wrap(err, "GetQEInfoFromProvServer(): GET http request Failed")
	}

	resp, err := client.Do(req)
	if err != nil {
	    return nil, errors.Wrap(err, "GetQEInfoFromProvServer(): Can not get Client Request")
	}
	return resp, nil
}
