/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"strings"
	"fmt"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"time"
	"encoding/pem"
	"encoding/hex"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"

	"intel/isecl/sgx-caching-service/constants"
	"intel/isecl/sgx-caching-service/repository"
	"intel/isecl/sgx-caching-service/types"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
)

type Response struct{
	Status 		string
	Message 	string
}

type PlatformInfo struct {
	EncryptedPPID 	string `json:"enc_ppid"`
	CpuSvn          string `json:"cpu_svn"`
	PceSvn          string `json:"pce_svn"`
	PceId 		string `json:"pce_id"`
	QeId 		string `json:"qe_id"`
	Ca 		string `json:"ca"`
	CreatedTime 	time.Time
}

type PlatformTcbInfo struct {
	CpuSvn 		string `json:"cpu_svn"`
	PceSvn 		string `json:"pce_svn"`
	PceId 		string `json:"pce_id"`
	QeId 		string `json:"qe_id"`
	Tcbm 		string
	CreatedTime 	time.Time
}

type PckCertChainInfo struct {
	Id 		uint
	CreatedTime 	time.Time
	PckCertChain 	string
}

type PckCRLInfo struct {
	PckCRL 		string
	PckCRLCertChain string
	Ca 		string
	CreatedTime 	time.Time
}

type PckCertInfo struct {
	PceId 		string `json:"pce_id"`
	QeId 		string `json:"qe_id"`
	PckCert         []string
	Tcbm      	[]string
	Fmspc      	string     
	CreatedTime 	time.Time
	PckCertChainId 	int
}

type FmspcTcbInfo struct {
	Fmspc      	string     
	TcbInfo         string
	TcbInfoIssuerChain  string
	CreatedTime 	time.Time
}

type QEInfo struct {
	Id		uint
	QEInfo         	string
	QEIssuerChain  	string
	CreatedTime 	time.Time
}

type tcbinfo struct {
	tcbcomp01 uint `json:"sgxtcbcomp01svn"`
	tcbcomp02 uint `json:"sgxtcbcomp02svn"`
	tcbcomp03 uint `json:"sgxtcbcomp03svn"`
	tcbcomp04 uint `json:"sgxtcbcomp04svn"`
	tcbcomp05 uint `json:"sgxtcbcomp05svn"`
	tcbcomp06 uint `json:"sgxtcbcomp06svn"`
	tcbcomp07 uint `json:"sgxtcbcomp07svn"`
	tcbcomp08 uint `json:"sgxtcbcomp08svn"`
	tcbcomp09 uint `json:"sgxtcbcomp09svn"`
	tcbcomp10 uint `json:"sgxtcbcomp10svn"`
	tcbcomp11 uint `json:"sgxtcbcomp11svn"`
	tcbcomp12 uint `json:"sgxtcbcomp12svn"`
	tcbcomp13 uint `json:"sgxtcbcomp13svn"`
	tcbcomp14 uint `json:"sgxtcbcomp14svn"`
	tcbcomp15 uint `json:"sgxtcbcomp15svn"`
	tcbcomp16 uint `json:"sgxtcbcomp16svn"`
}

type PckCertsInfo struct {
	Tcb tcbinfo `json:"tcb"`
	Tcbm string `json:"tcbm"`
	Cert string `json:"cert"`
}

type SgxData struct {
	Type constants.CacheType
	PlatformInfo 
	PlatformTcbInfo 
	PckCertChainInfo 
	PckCertInfo 
	PckCRLInfo
	FmspcTcbInfo
	QEInfo
	Platform *types.Platform
	PlatformTcb *types.PlatformTcb
	PckCert *types.PckCert
	PckCertChain *types.PckCertChain
	PckCrl *types.PckCrl
	FmspcTcb *types.FmspcTcbInfo
	QEIdentity *types.QEIdentity
}

func PlatformInfoOps(r *mux.Router, db repository.SCSDatabase) {
	log.Trace("resource/platform_ops.go: PlatformInfoOps() Entering")
	defer log.Trace("resource/platform_ops.go: PlatformInfoOps() Leaving")

	r.Handle("/push", handlers.ContentTypeHandler(PushPlatformInfoCB(db), "application/json")).Methods("POST")
	r.Handle("/refresh", handlers.ContentTypeHandler(RefreshPlatformInfoCB(db), "application/json")).Methods("GET")
}

func GetFmspcVal(CertBuf *pem.Block) (string, error) {
	log.Trace("resource/platform_ops.go: GetFmspcVal() Entering")
	defer log.Trace("resource/platform_ops.go: GetFmspcVal() Leaving")

        var fmspcHex string
        cert, err := x509.ParseCertificate(CertBuf.Bytes)
        if err != nil {
            return fmspcHex, err
        }

        SgxExtensionsOid := asn1.ObjectIdentifier{1,2,840,113741,1,13,1}
        FmspcSgxExtensionsOid := asn1.ObjectIdentifier{1,2,840,113741,1,13,1,4}
        var ext pkix.Extension

        for i:=0; i< len(cert.Extensions); i++ {
                ext=cert.Extensions[i]
                if SgxExtensionsOid.Equal(ext.Id) == true {
                        var asn1Extensions []asn1.RawValue
                        _, err := asn1.Unmarshal(ext.Value, &asn1Extensions)
                        if err != nil {
                                log.Warn("Could not parse extension")
                                return fmspcHex, err
                        }

                        var fmspcExt pkix.Extension
                        for j:=0; j<len(asn1Extensions); j++ {
                                _, err = asn1.Unmarshal(asn1Extensions[j].FullBytes, &fmspcExt)
                                if err != nil {
                                        log.Warn("Could not parse sub extension")
                                }
                                if FmspcSgxExtensionsOid.Equal(fmspcExt.Id) == true {
                                        fmspcHex=hex.EncodeToString(fmspcExt.Value)
                                        log.WithField("FMSPC hex value", fmspcHex).Debug("Fmspc Value extracted from PCK cert")
                                        return fmspcHex, nil
                                }
                        }
                }
        }
        return fmspcHex, errors.New("Fmspc value not found in PCK Certificate")
}

func FetchPCKCertInfo(in *SgxData) error {
	log.Trace("resource/platform_ops.go: PlatformInfoOps() Entering")
	defer log.Trace("resource/platform_ops.go: PlatformInfoOps() Leaving")

	resp, err := GetPCKCertFromProvServer(in.PlatformInfo.EncryptedPPID,
							in.PlatformInfo.CpuSvn,
							in.PlatformInfo.PceSvn,
							in.PlatformInfo.PceId)

        if err != nil {
		log.WithError(err).Error("Intel PCS Server getPCKCerts curl failed")
		return err;
	}

	if resp.StatusCode != 200 {
		dump, _ := httputil.DumpResponse(resp, true)
		log.WithField("Status Code", resp.StatusCode).Error(string(dump))
		return errors.New("Could not Fetch PCKCertificates from Intel PCS Server")
	}

	headers := resp.Header
	in.PckCertChainInfo.PckCertChain = ConverAsciiCodeToChar(headers["Sgx-Pck-Certificate-Issuer-Chain"][0])
	if resp.ContentLength == 0 {
		return errors.New("No content found in getPCkCerts Http Response")
	}

	defer resp.Body.Close()
        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
		log.WithError(err).Error("Could not Read GetPckCerts Http Response")
            	return err
        }

	var pckCerts []PckCertsInfo
	err = json.Unmarshal(body, &pckCerts)
        if err != nil {
                log.WithError(err).Error("Could not decode the pckCerts json response")
                return err
        }

	in.PckCertInfo.PckCert = make([]string, constants.MaxNumberofPCKCerts)
	in.PckCertInfo.Tcbm = make([]string, constants.MaxNumberofPCKCerts)
	for i:=0; i < len(pckCerts); i++ {
		in.PckCertInfo.PckCert[i] = ConverAsciiCodeToChar(pckCerts[i].Cert)
		in.PckCertInfo.Tcbm[i] = pckCerts[i].Tcbm
	}

	in.PckCertInfo.QeId = in.PlatformInfo.QeId
	in.PckCertInfo.PceId = in.PlatformInfo.PceId
	CertBuf, _ := pem.Decode([]byte(in.PckCertInfo.PckCert[0]))
	
	if CertBuf == nil {
		return errors.New("Failed to parse PEM block ")
	}

	in.PckCertInfo.Fmspc, err = GetFmspcVal(CertBuf)
	if err != nil {
		return err
	}

	return nil
}

func ConverAsciiCodeToChar(s string) string {
	s = strings.Replace(s, "%20", " ", -1)
	s = strings.Replace(s, "%0A", "\n", -1)
	s = strings.Replace(s, "%2F", "/", -1)
	s = strings.Replace(s, "%2B", "+", -1)
	s = strings.Replace(s, "%3D", "=", -1)
	s = strings.Replace(s, "%20", " ", -1)
	return s
}

func FetchPCKCRLInfo(in *SgxData) error {
	log.Trace("resource/platform_ops.go: FetchPCKCRLInfo() Entering")
	defer log.Trace("resource/platform_ops.go: FetchPCKCRLInfo() Leaving")

	in.PckCRLInfo.Ca = in.PlatformInfo.Ca
	resp, err := GetPCKCRLFromProvServer(in.PckCRLInfo.Ca)
        if err != nil {
		log.WithError(err).Error("Intel PCS Server getPCKCrl curl failed")
		return err;
	}

	if resp.StatusCode != 200 {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("invalid response received from intel SGX provisioning server")
	}

	headers := resp.Header
	in.PckCRLInfo.PckCRLCertChain = ConverAsciiCodeToChar(headers["Sgx-Pck-Crl-Issuer-Chain"][0])
	log.WithField("PckCrlCertChain", in.PckCRLInfo.PckCRLCertChain).Debug("Values")

	if resp.ContentLength == 0 {
		return errors.New("No content found in getPCkCrl Http Response")
	}

	defer resp.Body.Close()
        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
		log.WithError(err).Error("Could not Read GetPckCrl Http Response")
            	return err
        }
	in.PckCRLInfo.PckCRL = ConverAsciiCodeToChar(string(body))
	CrlBuf, _ := pem.Decode(body)
	if CrlBuf == nil {
		return errors.New("Failed to parse Crl PEM block")
	}
	log.WithField("PckCrl", in.PckCRLInfo.PckCRL).Debug("Values")
	return nil
}

func FetchFmspcTcbInfo(in *SgxData) error {
	log.Trace("resource/platform_ops.go: FetchFmspcTcbInfo() Entering")
	defer log.Trace("resource/platform_ops.go: FetchFmspcTcbInfo() Leaving")

	resp, err := GetFmspcTcbInfoFromProvServer(in.FmspcTcbInfo.Fmspc)
        if err != nil {
		log.WithError(err).Error("Intel PCS Server getTCBInfo curl failed")
		return err;
	}

	if resp.StatusCode != 200 {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("Invalid response from Intel SGX Provisioning Server")
	}

	headers := resp.Header
	in.FmspcTcbInfo.TcbInfoIssuerChain = ConverAsciiCodeToChar(headers["Sgx-Tcb-Info-Issuer-Chain"][0])
	log.WithField("TcbInfoIssuerChain", in.FmspcTcbInfo.TcbInfoIssuerChain).Debug("Values")

	if resp.ContentLength == 0 {
		return errors.New("No content found in getTCBInfo Http Response")
	}

	defer resp.Body.Close()
        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
		log.WithError(err).Error("Could not Read GetTCBInfo Http Response")
            	return err
        }
	in.FmspcTcbInfo.TcbInfo	= string(body)
	return nil
}

func FetchQEIdentityInfo(in *SgxData) error {
	log.Trace("resource/platform_ops.go: FetchQEIdentityInfo() Entering")
	defer log.Trace("resource/platform_ops.go: FetchQEIdentityInfo() Leaving")

	resp, err := GetQEInfoFromProvServer()
        if err != nil {
		log.WithError(err).Error("Intel PCS Server getQEIdentity curl failed")
		return err
	}

	if resp.StatusCode != 200 {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("Invalid response from Intel SGX Provisioning Server")
	}

	headers := resp.Header
	in.QEInfo.QEIssuerChain = ConverAsciiCodeToChar(headers["Sgx-Enclave-Identity-Issuer-Chain"][0])
	log.WithField("QEIssuerChain", in.QEInfo.QEIssuerChain).Debug("Values")

	if resp.ContentLength == 0 {
		return errors.New("No content found in getQEIdentity Http Response")
	}

	defer resp.Body.Close()
        body, err := ioutil.ReadAll(resp.Body)
        if err != nil {
		log.WithError(err).Error("Could not Read GetQEIdentity Http Response")
            	return err
        }
	in.QEInfo.QEInfo = string(body)
	log.WithField("QEInfo", string(body)).Debug("Values")
	return nil
}

func CachePckCertInfo(db repository.SCSDatabase, data *SgxData) error {
	log.Trace("resource/platform_ops.go: CachePckCertInfo() Entering")
	defer log.Trace("resource/platform_ops.go: CachePckCertInfo() Leaving")

	var err error
	data.PckCert = &types.PckCert {
					PceId: strings.ToLower(data.PckCertInfo.PceId),
					QeId: strings.ToLower(data.PckCertInfo.QeId),
					Tcbm: data.PckCertInfo.Tcbm,
					Fmspc: strings.ToLower(data.PckCertInfo.Fmspc),
					PckCert: data.PckCertInfo.PckCert,
					CertChainId: data.PckCertChain.Id,}

	if data.Type == constants.CacheRefresh {
		data.PckCert.UpdatedTime = time.Now()
		data.PckCert.CreatedTime = data.PlatformInfo.CreatedTime
		err = db.PckCertRepository().Update(*data.PckCert)
		if err != nil {
			log.WithError(err).Error("PckCert record could not be updated in db")
			return err
		}
	}else{
		data.PckCert.CreatedTime = time.Now()
		data.PckCert.UpdatedTime = time.Now()
		data.PckCert, err = db.PckCertRepository().Create(*data.PckCert)
		if err != nil {
			log.WithError(err).Error("PckCert record could not be created in db")
			return err
		}
	}
	return nil
}

func CacheQEIdentityInfo(db repository.SCSDatabase, data *SgxData) error {
	data.QEIdentity = &types.QEIdentity{	
					QeIdentity: data.QEInfo.QEInfo,
					QeIdentityIssuerChain: data.QEInfo.QEIssuerChain,
					CreatedTime: time.Now(), 
					UpdatedTime: time.Now()}
	log.Trace("resource/platform_ops.go: CacheQEIdentityInfo() Entering")
	defer log.Trace("resource/platform_ops.go: CacheQEIdentityInfo() Leaving")
	var err error
        if  data.Type == constants.CacheRefresh {
		data.QEIdentity.UpdatedTime = time.Now()
		data.QEIdentity.CreatedTime = data.QEInfo.CreatedTime
		data.QEIdentity.Id = data.QEInfo.Id
		err = db.QEIdentityRepository().Update(*data.QEIdentity)
		if err != nil {
			log.WithError(err).Error("QE Identity record could not be updated in db")
			return err
		}
	}else{
		data.QEIdentity.UpdatedTime = time.Now()
		data.QEIdentity.CreatedTime = time.Now()
		data.QEIdentity, err = db.QEIdentityRepository().Create(*data.QEIdentity)
		if err != nil {
			log.WithError(err).Error("QE Identity record could not created in db")
			return err
		}
	}
	log.WithField("QE Identity Id", data.QEIdentity.Id).Debug("Db value")
	return nil
}

func CachePckCertChainInfo(db repository.SCSDatabase, data *SgxData) error {
	log.Trace("resource/platform_ops.go: CachePckCertChainInfo() Entering")
	defer log.Trace("resource/platform_ops.go: CachePckCertChainInfo() Leaving")

	var err error
	data.PckCertChain = &types.PckCertChain{	
					CertChain: data.PckCertChainInfo.PckCertChain,}

	if data.Type == constants.CacheRefresh {
		data.PckCertChain.Id = data.PckCertChainInfo.Id
		data.PckCertChain.CreatedTime = data.PckCertChainInfo.CreatedTime
		data.PckCertChain.UpdatedTime = time.Now()
		err = db.PckCertChainRepository().Update(*data.PckCertChain)
		if err != nil {
			log.WithError(err).Error("PckCertChain record could not be updated in db")
			return err
		}
	}else{
		data.PckCertChain.UpdatedTime = time.Now()
		data.PckCertChain.CreatedTime = time.Now()
		data.PckCertChain, err = db.PckCertChainRepository().Create(*data.PckCertChain)
		if err != nil {
			log.WithError(err).Error("PckCertChain record could not be created in db")
			return err
		}
	}
	log.WithField("PCK Cert Chain ID", data.PckCertChain.Id).Debug("Db value")
	return nil
}

func CacheFmspcTcbInfo(db repository.SCSDatabase, data *SgxData) error {
	log.Trace("resource/platform_ops.go: CacheFmspcTcbInfo() Entering")
	defer log.Trace("resource/platform_ops.go: CacheFmspcTcbInfo() Leaving")

	data.FmspcTcb = &types.FmspcTcbInfo{	
					Fmspc: strings.ToLower(data.FmspcTcbInfo.Fmspc),
					TcbInfo: data.FmspcTcbInfo.TcbInfo,
					TcbInfoIssuerChain: data.FmspcTcbInfo.TcbInfoIssuerChain,}
	var err error

	if data.Type == constants.CacheRefresh {
		data.FmspcTcb.CreatedTime = data.FmspcTcbInfo.CreatedTime
		data.FmspcTcb.UpdatedTime = time.Now()
		err = db.FmspcTcbInfoRepository().Update(*data.FmspcTcb)
		if err != nil {
			log.WithError(err).Error("FmspcTcb record could not be Updated in db")
			return err
		}
	}else {
		data.FmspcTcb.CreatedTime = time.Now()
		data.FmspcTcb.UpdatedTime = time.Now()
		data.FmspcTcb, err = db.FmspcTcbInfoRepository().Create(*data.FmspcTcb)
		if err != nil {
			log.WithError(err).Error("FmspcTcb record could not be created in db")
			return err
		}
	}
	log.WithField("Fmspc", data.FmspcTcb.Fmspc).Debug("Cached inside Db")
	return nil
}

func CachePlatformInfo(db repository.SCSDatabase, data *SgxData) error {
	log.Trace("resource/platform_ops.go: CachePlatformInfo() Entering")
	defer log.Trace("resource/platform_ops.go: CachePlatformInfo() Leaving")

	if data.Platform == nil {
		data.Platform = &types.Platform{
						Encppid: strings.ToLower(data.PlatformInfo.EncryptedPPID),
						CpuSvn: strings.ToLower(data.PlatformInfo.CpuSvn),
						PceSvn:strings.ToLower(data.PlatformInfo.PceSvn),
						PceId: strings.ToLower(data.PlatformInfo.PceId),
						QeId: strings.ToLower(data.PlatformInfo.QeId),
						Fmspc: strings.ToLower(data.PckCertInfo.Fmspc),
		}
	}

	var err error
        if  data.Type == constants.CacheRefresh {
		data.Platform.CreatedTime = data.PlatformInfo.CreatedTime
		data.Platform.UpdatedTime = time.Now()
		err = db.PlatformRepository().Update(*data.Platform)
		if err != nil {
			log.WithError(err).Error("Platform values record could not be updated in db")
			return err
		}
        }else {
		data.Platform.UpdatedTime = time.Now()
		data.Platform.CreatedTime = time.Now()
		data.Platform, err = db.PlatformRepository().Create(*data.Platform)
		if err != nil {
			log.WithError(err).Error("Platform values record could not be created in db")
			return err
		}
	}
	return nil
}

func CachePlatformTcbInfo(db repository.SCSDatabase, data *SgxData) error {
	log.Trace("resource/platform_ops.go: CachePlatformTcbInfo() Entering")
	defer log.Trace("resource/platform_ops.go: CachePlatformTcbInfo() Leaving")

	if data.PlatformTcb == nil {
		data.PlatformTcb = &types.PlatformTcb{
						Tcbm: strings.ToLower(data.PckCertInfo.Tcbm[0]),
						CpuSvn: strings.ToLower(data.PlatformInfo.CpuSvn),
						PceSvn:strings.ToLower(data.PlatformInfo.PceSvn),
						PceId: strings.ToLower(data.PlatformInfo.PceId),
						QeId: strings.ToLower(data.PlatformInfo.QeId),
		}
	}

	var err error
        if  data.Type == constants.CacheRefresh {
		data.PlatformTcb.CreatedTime = data.PlatformInfo.CreatedTime
		data.PlatformTcb.UpdatedTime = time.Now()
		err = db.PlatformTcbRepository().Update(*data.PlatformTcb)
		if err != nil {
				log.WithError(err).Error("PlatformTcb values record could not be updated in db")
				return err
		}
        }else {
		data.PlatformTcb.UpdatedTime = time.Now()
		data.PlatformTcb.CreatedTime = time.Now()
		data.PlatformTcb, err = db.PlatformTcbRepository().Create(*data.PlatformTcb)
		if err != nil {
				log.WithError(err).Error("PlatformTcb values record could not be created in db")
				return err
		}
	}
	return nil
}

func CachePckCRLInfo(db repository.SCSDatabase, data *SgxData) error {
	log.Trace("resource/platform_ops.go: CachePckCRLInfo() Entering")
	defer log.Trace("resource/platform_ops.go: CachePckCRLInfo() Leaving")

	data.PckCrl = &types.PckCrl{	
				Ca: data.PckCRLInfo.Ca,
				PckCrl: data.PckCRLInfo.PckCRL,
				PckCrlCertChain: data.PckCRLInfo.PckCRLCertChain}
	var err error
        if  data.Type == constants.CacheRefresh {
		data.PckCrl.CreatedTime = data.PckCRLInfo.CreatedTime
		data.PckCrl.UpdatedTime = time.Now()
		err = db.PckCrlRepository().Update(*data.PckCrl)
		if err != nil {
			log.WithError(err).Error("PckCrl record could not be updated in db")
			return err
		}
        }else {
		data.PckCrl.CreatedTime = time.Now()
		data.PckCrl.UpdatedTime = time.Now()
		data.PckCrl, err = db.PckCrlRepository().Create(*data.PckCrl)
		if err != nil {
			slog.WithError(err).Error("PckCrl record could not be created in db")
			return err
		}
	}
	return nil
}

func PushPlatformInfoCB(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		var data SgxData
		if (r.ContentLength == 0) {
                        return &resourceError{Message: "The request body was not provided", StatusCode: http.StatusBadRequest}
                }

                dec := json.NewDecoder(r.Body)
                dec.DisallowUnknownFields()
                err := dec.Decode(&data.PlatformInfo)
                if err != nil {
                        return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
                }

		if      !ValidateInputString(constants.EncPPID_Key, data.PlatformInfo.EncryptedPPID) ||
                        !ValidateInputString(constants.CpuSvn_Key, data.PlatformInfo.CpuSvn) ||
                        !ValidateInputString(constants.PceSvn_Key, data.PlatformInfo.PceSvn) ||
                        !ValidateInputString(constants.PceId_Key, data.PlatformInfo.PceId)  ||
                        !ValidateInputString(constants.QeId_Key, data.PlatformInfo.QeId) {
                        return &resourceError{Message: "Invalid query Param Data", StatusCode: http.StatusBadRequest}
                }

		data.Platform = &types.Platform{	
						Encppid: strings.ToLower(data.PlatformInfo.EncryptedPPID), 
						CpuSvn: strings.ToLower(data.PlatformInfo.CpuSvn), 
						PceSvn: strings.ToLower(data.PlatformInfo.PceSvn), 
						PceId: strings.ToLower(data.PlatformInfo.PceId), 
						QeId: strings.ToLower(data.PlatformInfo.QeId), 
		}
		existingPlaformData, err := db.PlatformRepository().Retrieve(*data.Platform)
                if  existingPlaformData != nil {
			w.Header().Set("Content-Type", "application/json")
                	w.WriteHeader(http.StatusOK) // HTTP 200
			res := Response{ Status:"Success", Message: "Platform Info Already exists"}
                	js, err := json.Marshal(res)
                	if err != nil {
                        	return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
                	}
                	w.Write(js)
			return nil
                }

		data.Type = constants.CacheInsert
		err = FetchPCKCertInfo(&data)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		err = CachePlatformInfo(db, &data) 
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		err = CachePckCertChainInfo(db, &data) 
                if err != nil {
                        return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		err = CachePckCertInfo(db, &data) 
                if err != nil {
                        return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		pckCrl := types.PckCrl{Ca: constants.Ca_Processor}
		existingPckCrl, err := db.PckCrlRepository().Retrieve(pckCrl)
		if existingPckCrl == nil {

			data.PlatformInfo.Ca = constants.Ca_Processor
			err = FetchPCKCRLInfo(&data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}

			err = CachePckCRLInfo(db, &data) 
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		TcbInfo := types.FmspcTcbInfo{ Fmspc: strings.ToLower(data.PckCertInfo.Fmspc) }
                existingFmspc, err := db.FmspcTcbInfoRepository().Retrieve(TcbInfo)
		if existingFmspc == nil {
			data.FmspcTcbInfo.Fmspc = data.PckCertInfo.Fmspc
			err = FetchFmspcTcbInfo(&data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}

			err = CacheFmspcTcbInfo(db, &data) 
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		existingQEData, err := db.QEIdentityRepository().RetrieveAll()
                if  existingPlaformData != nil {
                        return &resourceError{Message: "Platform Info Already exist", StatusCode: http.StatusBadRequest}
                }

		if len(existingQEData) == 0 {
			err = FetchQEIdentityInfo(&data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}

			err = CacheQEIdentityInfo(db, &data) 
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}else {
			log.WithField("Tcb Data count", len(existingQEData)).Debug("QE Data already present")
		}

                w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated) // HTTP 201

		res := Response{ Status:"Created", Message: "Platform Data pushed Successfully"}	
		js, err := json.Marshal(res)
		if err != nil {
                        return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
	        }
		w.Write(js)
                return nil
	}
}

func RefreshPckCerts(db repository.SCSDatabase) error {
	log.Trace("resource/platform_ops.go: RefreshPckCerts() Entering")
	defer log.Trace("resource/platform_ops.go: RefreshPckCerts() Leaving")

	existingPlaformData, err := db.PlatformRepository().RetrieveAllPlatformInfo()
        if  len(existingPlaformData) == 0 {
                return errors.New("No PCK Certificate is cached in SCS, cannot perform refresh operation")
        }

	log.Debug("Existing Platform info count:", len(existingPlaformData))
	var data SgxData
	data.Type = constants.CacheRefresh
	for n := 0; n < len(existingPlaformData); n++ {
		tmp := existingPlaformData[n]
		data.PlatformInfo.EncryptedPPID = tmp.Encppid
	 	data.PlatformInfo.CpuSvn = tmp.CpuSvn 
	 	data.PlatformInfo.PceSvn = tmp.PceSvn
		data.PlatformInfo.PceId = tmp.PceId
		data.PlatformInfo.QeId = tmp.QeId 
		data.PlatformInfo.CreatedTime = tmp.CreatedTime

		log.Debug("Existing Platform Data:", existingPlaformData[n])

		err = FetchPCKCertInfo(&data)
                if err != nil {
                        return errors.New(fmt.Sprintf("Error in Refresh Pck Cert Info: %s", string(err.Error())))
                }

		err = CachePlatformTcbInfo(db, &data)
		if err != nil {
                        return errors.New(fmt.Sprintf("Error in Cache Platform Tcb Cert Info: %s", err.Error()))
		}

		existingPckCertData := &types.PckCert { 
						PceId: tmp.PceId,
						QeId: tmp.QeId }
		existingPckCertData, err = db.PckCertRepository().Retrieve(*existingPckCertData)
		if existingPckCertData == nil {
			return errors.New("Error in fetching existing pck cert data")
		}

		log.Debug("Printing existing Pck Cert:", existingPckCertData)
		data.PckCertChainInfo.Id = existingPckCertData.CertChainId
		data.PckCertChainInfo.CreatedTime = existingPckCertData.CreatedTime
		
		err = CachePckCertChainInfo(db, &data) 
                if err != nil {
                        return errors.New(fmt.Sprintf("Error in Cache Pck Cert Chain Info: %s", err.Error()))
		}
		data.PckCertInfo.CreatedTime = existingPckCertData.CreatedTime
		err = CachePckCertInfo(db, &data) 
                if err != nil {
                        return errors.New(fmt.Sprintf("Error in Cache Pck Cert Info: %s", err.Error()))
		}
    	}	
	log.Debug("All PckCerts refeteched from PCS as part of refresh")
	return nil
}

func RefreshAllPckCrl(db repository.SCSDatabase) error {
	log.Trace("resource/platform_ops.go: RefreshAllPckCrl() Entering")
	defer log.Trace("resource/platform_ops.go: RefreshAllPckCrl() Leaving")

	existingPckCrlData, err := db.PckCrlRepository().RetrieveAllPckCrls()
        if  len(existingPckCrlData) == 0 {
                return errors.New("Cached PCK Crl count is 0, cannot perform refresh operation")
        }

	log.Debug("Existing PckCrl count:", len(existingPckCrlData))
	var data SgxData
	data.Type = constants.CacheRefresh
	for n := 0; n < len(existingPckCrlData); n++ {

		data.PlatformInfo.Ca=existingPckCrlData[n].Ca
		err = FetchPCKCRLInfo(&data)
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Fetch Pck CRL info: %s", err.Error()))
		}
	
		data.PckCRLInfo.CreatedTime = existingPckCrlData[n].CreatedTime	
		err = CachePckCRLInfo(db, &data) 
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Cache Pck CRL info: %s", err.Error()))
		}
	}
	log.Debug("All PckCrls refeteched from PCS as part of refresh")
	return nil
}

func RefreshAllTcbInfo(db repository.SCSDatabase) error {
	log.Trace("resource/platform_ops.go: RefreshAllTcbInfo() Entering")
	defer log.Trace("resource/platform_ops.go: RefreshAllTcbInfo() Leaving")

	existingTcbInfoData, err := db.FmspcTcbInfoRepository().RetrieveAllFmspcTcbInfos()
        if  len(existingTcbInfoData) == 0 {
                return errors.New("Cached Tcb Info count is 0, cannot perform refresh operation")
        }

	log.Debug("Existing Fmspc count:", len(existingTcbInfoData))
	var data SgxData
	data.Type = constants.CacheRefresh
	for n := 0; n < len(existingTcbInfoData); n++ {
		data.FmspcTcbInfo.Fmspc = existingTcbInfoData[n].Fmspc
		err = FetchFmspcTcbInfo(&data)
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Fetch Tcb info: %s", err.Error()))
		}
	
		data.FmspcTcbInfo.CreatedTime = existingTcbInfoData[n].CreatedTime	
		err = CacheFmspcTcbInfo(db, &data) 
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Cache Fmspc Tcb info: %s", err.Error()))
		}
	}
	log.Debug("All TCBInfos refeteched from PCS as part of refresh")
	return nil
}

func RefreshAllQE(db repository.SCSDatabase) error {
	log.Trace("resource/platform_ops.go: RefreshAllQE() Entering")
	defer log.Trace("resource/platform_ops.go: RefreshAllQE() Leaving")

	existingQEData, err := db.QEIdentityRepository().RetrieveAll()
        if  len(existingQEData) == 0 {
                return errors.New("Cached QEIdentity count is 0, cannot perform refresh operation")
        }

	log.Debug("Existing QEIdentity count:", len(existingQEData))
	var data SgxData
	data.Type = constants.CacheRefresh
	for n := 0; n < len(existingQEData); n++ {
		err = FetchQEIdentityInfo(&data)
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Fetch QEIdentity info: %s", err.Error()))
		}
		data.QEInfo.CreatedTime = existingQEData[n].CreatedTime
		data.QEInfo.Id 		= existingQEData[n].Id
		err = CacheQEIdentityInfo(db, &data) 
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Cache QEIdentity info: %s", err.Error()))
		}
	}
	log.Debug("All QEIdentity refeteched from PCS as part of refresh")
	return nil
}

func RefreshTcbInfos(db repository.SCSDatabase) error {
	log.Trace("resource/platform_ops.go: RefreshTcbInfos() Entering")
	defer log.Trace("resource/platform_ops.go: RefreshTcbInfos() Leaving")

	err := RefreshAllPckCrl(db)
	if err != nil{
		return nil
	}

	err = RefreshAllTcbInfo(db)
	if err != nil{
		return nil
	}

	err = RefreshAllQE(db)
	if err != nil{
		return nil
	}
	return nil
}

func RefreshPlatformInfoTimerCB(db repository.SCSDatabase, rtype string) error {
	log.Trace("resource/platform_ops.go: RefreshPlatformInfoTimerCB() Entering")
	defer log.Trace("resource/platform_ops.go: RefreshPlatformInfoTimerCB() Leaving")

	var err error
	if strings.Compare(rtype ,constants.Type_Refresh_Cert) == 0 {
		err = RefreshPckCerts(db)
		if err != nil{
			log.WithError(err).Error("Could not complete refresh of Pck Certificates")
			return err
		}
	} else if strings.Compare(rtype, constants.Type_Refresh_Tcb) == 0  {
		err = RefreshTcbInfos(db)
		if err != nil{
			log.WithError(err).Error("Could not complete refresh of TcbInfo")
			return err
		}
	}
	log.Debug("Timer CB: RefreshPlatformInfoTimerCB, completed")
	return nil
}

func RefreshPlatformInfoCB(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if  r.URL.Query() != nil && len(r.URL.Query()) > len( constants.Type_Key) {
                	Type,_ := r.URL.Query()["type"]
			if !ValidateInputString(constants.Type_Key, Type[0]) {
				return &resourceError{Message: "Invalid query Param type", StatusCode: http.StatusBadRequest}
			}

			err := RefreshPckCerts(db)
			if err != nil{
				return &resourceError{Message: "Could not Refresh Pck Certificates",
					StatusCode: http.StatusInternalServerError}
			}
			return nil
		}

		err := RefreshTcbInfos(db)
		if err != nil{
			return &resourceError{Message: "Could not Refresh Pck Certificates",
				StatusCode: http.StatusInternalServerError}
		}

 		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK) // HTTP 200

		res := Response{ Status:"Success", Message: "All Platform Data refreshed Successfully"}
		js, err := json.Marshal(res)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		w.Write(js)

		return nil
	}
}
