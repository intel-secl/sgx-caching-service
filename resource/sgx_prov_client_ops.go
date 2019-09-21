package resource

import (
	"fmt"
	"errors"
	"time"
	"net/http"
	"net/url"
	"intel/isecl/sgx-caching-service/config"
	log "github.com/sirupsen/logrus"
	//"intel/isecl/sgx-caching-service/types"
)


func GetProvClientObj()(*http.Client, *config.Configuration, error){
	
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
	    		return nil, nil, err
		}
		client.Transport = &http.Transport{ Proxy: http.ProxyURL(proxyUrl)}
		log.WithField("Proxy URL", conf.ProxyUrl).Debug("Intel Prov Client OPS")
	}
	return client, conf, nil
}

func GetPCKCertFromProvServer(EncryptedPPID string, CpuSvn string, PceSvn string, PceId string) (*http.Response, error) {

	client, conf, err := GetProvClientObj()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/pckcert", conf.ProvServerInfo.ProvServerUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
	    return nil, err
	}

	req.Header.Add("Ocp-Apim-Subscription-Key", conf.ProvServerInfo.ApiSubscriptionkey)
	q := req.URL.Query()
	q.Add("encrypted_ppid", EncryptedPPID)
	q.Add("cpusvn", CpuSvn)
	q.Add("pcesvn", PceSvn)
	q.Add("pceid", PceId)

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do( req )
	if err != nil {
	    return nil, err
	}
	return resp, nil
}

func GetPCKCRLFromProvServer(ca string) (*http.Response, error) {

	client, conf, err := GetProvClientObj()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/pckcrl", conf.ProvServerInfo.ProvServerUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
	    return nil, err
	}

	q := req.URL.Query()
	q.Add("ca", ca)

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do( req )
	if err != nil {
	    return nil, err
	}
	return resp, nil
}



func GetFmspcTcbInfoFromProvServer(fmspc string) (*http.Response, error) {

	client, conf, err := GetProvClientObj()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/tcb", conf.ProvServerInfo.ProvServerUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
	    return nil, err
	}

	q := req.URL.Query()
	q.Add("fmspc", fmspc)

	req.URL.RawQuery = q.Encode()

	resp, err := client.Do( req )
	if err != nil {
	    return nil, err
	}
	return resp, nil
}


func GetQEInfoFromProvServer() (*http.Response, error) {

	client, conf, err := GetProvClientObj()
	if err != nil {
		return nil, err
	}
	url := fmt.Sprintf("%s/qe/identity", conf.ProvServerInfo.ProvServerUrl)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
	    return nil, err
	}

	resp, err := client.Do( req )
	if err != nil {
	    return nil, err
	}
	return resp, nil
}
