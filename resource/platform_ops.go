/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	//"fmt"
	"encoding/json"
	"errors"
	//"intel/isecl/lib/common/context"
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
	log "github.com/sirupsen/logrus"
)

type Response struct{
	Status string
	Message string
}
	

type PlatformInfo struct {
	EncryptedPPID string `json:"enc_ppid"`
	CpuSvn string `json:"cpu_svn"`
	PceSvn string `json:"pce_svn"`
	PceId string `json:"pce_id"`
	QeId string `json:"qe_id"`
	Ca string `json:"ca"`
}
type PckCertChainInfo struct {
	PckCertChain []byte
}
type PckCRLInfo struct {
	PckCRL []byte
	PckCRLCertChain []byte
	Ca string
}
type PckCertInfo struct {
	PckCert         []byte
	Tcbm      	string     
	Fmspc      	string     
}

type FmspcTcbInfo struct {
	Fmspc      	string     
	TcbInfo         []byte
	TcbInfoIssuerChain  []byte
}

type QEInfo struct {
	QEInfo         []byte
	QEIssuerChain  []byte
}

type SgxData struct {
	PlatformInfo 
	PckCertChainInfo 
	PckCertInfo 
	PckCRLInfo
	FmspcTcbInfo
	QEInfo
	PlatformTcb *types.PlatformTcb
	PckCert *types.PckCert
	PckCertChain *types.PckCertChain
	PckCrl *types.PckCrl
	FmspcTcb *types.FmspcTcbInfo
	QEIdentity *types.QEIdentity
}


func PlatformInfoOps(r *mux.Router, db repository.SCSDatabase) {
	r.Handle("/push", handlers.ContentTypeHandler( PushPlatformInfoCB(db), "application/json")).Methods("POST") 
	r.Handle("/refresh", handlers.ContentTypeHandler( RefreshPlatformInfoCB(db), "application/json")).Methods("GET") 
}

func GetFmspcVal( CertBuf *pem.Block )(string, error){

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
                //fmt.Println("Ext val:", ext.Value)
                //fmt.Println("Ext Id:", ext.Value)
                if SgxExtensionsOid.Equal(ext.Id) == true {

                        var asn1Extensions []asn1.RawValue
                        _, err := asn1.Unmarshal(ext.Value, &asn1Extensions)
                        if err != nil {
                                log.Warn("Asn1 Extension Unmarshal failed")
                                return fmspcHex, err
                        }

                        var fmspcExt pkix.Extension
                        for j:=0; j<len(asn1Extensions); j++ {

                                _, err = asn1.Unmarshal(asn1Extensions[j].FullBytes, &fmspcExt)
                                if err != nil {
                                        log.Warn("Warning: Asn1 Extension Unmarshal failed - 2 for index\n")
                                        //return fmspcHex, err
                                }
                                if FmspcSgxExtensionsOid.Equal(fmspcExt.Id) == true {
                                        //fmt.Printf("FMSPC Extension array:%d, idx:%d, size:%d\n", fmspcExt, j, len(fmspcExt.Value))
                                        fmspcHex=hex.EncodeToString(fmspcExt.Value)
                                        log.WithField("FMSPC hex value", fmspcHex).Debug("Fmspc Value from cert")
                                        return fmspcHex, nil
                                }
                        }
                }

        }
        return fmspcHex, errors.New("Fmspc Value not found in Extension")
}




func FetchPCKCertInfo( in *SgxData ) (error){

	resp, err := GetPCKCertFromProvServer(in.PlatformInfo.EncryptedPPID, 
							in.PlatformInfo.CpuSvn, 
							in.PlatformInfo.PceSvn, 
							in.PlatformInfo.PceId)
        if err != nil {
		log.WithError(err).Error("Provisioning server curl failed for PCKCert fetch operation")
		return err;
	}


	if resp.StatusCode != 200 {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("Invalid response from Intel SGX Provisioning Server for PCKCert")
	}

	headers := resp.Header
	in.PckCertChainInfo.PckCertChain = []byte(headers["Sgx-Pck-Certificate-Issuer-Chain"][0])
	in.PckCertInfo.Tcbm = headers["Sgx-Tcbm"][0] 
	DateVal := headers["Date"][0]


	log.WithField("Sgx-Pck-Certificate-Issuer-Chain", in.PckCertChainInfo.PckCertChain).Debug("Cert Chain")
	log.WithField("Sgx-Tcbm", in.PckCertInfo.Tcbm).Debug("Tcbm")
	log.WithField("Date", DateVal).Debug("Date")

	if resp.ContentLength == 0 {
		return errors.New("Invalid content length received")
	}

	defer resp.Body.Close()
        body, err := ioutil.ReadAll( resp.Body )
        if err != nil {
		log.WithError(err).Error("Response Body read error")
            	return err
        }

	in.PckCertInfo.PckCert	= []byte(body)
	CertBuf, _ := pem.Decode([]byte(body))
	if CertBuf == nil {
		return errors.New("Failed to parse PEM block ")
	}
	//in.PckCertInfo.PckCert = CertBuf.Bytes

	in.PckCertInfo.Fmspc, err = GetFmspcVal(CertBuf)
	if err != nil {
		return err
	}

	return nil
}

func FetchPCKCRLInfo( in *SgxData ) (error){

	in.PckCRLInfo.Ca = in.PlatformInfo.Ca
	resp, err := GetPCKCRLFromProvServer(in.PckCRLInfo.Ca)
        if err != nil {
		log.WithError(err).Error("Provisioning server curl failed for PCKCrl fetch operation")
		return err;
	}

	if resp.StatusCode != 200 {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("Invalid response from Intel SGX Provisioning Server")
	}

	headers := resp.Header
	log.WithField("Headers", headers).Debug("Header Values")
	in.PckCRLInfo.PckCRLCertChain = []byte(headers["Sgx-Pck-Crl-Issuer-Chain"][0])
	log.WithField("PckCrlCertChain", in.PckCRLInfo.PckCRLCertChain).Debug("Values")

	if resp.ContentLength == 0 {
		return errors.New("Invalid content length received")
	}

	defer resp.Body.Close()
        body, err := ioutil.ReadAll( resp.Body )
        if err != nil {
		log.WithError(err).Error("Response Body read error")
            	return err
        }
	in.PckCRLInfo.PckCRL	= []byte(body)
	CrlBuf, _ := pem.Decode([]byte(body))
	if CrlBuf == nil {
		return errors.New("Failed to parse Crl PEM block ")
	}
	log.WithField("PckCrl", string(CrlBuf.Bytes)).Debug("Values")
	return nil
}


func FetchFmspcTcbInfo( in *SgxData ) (error){

	in.FmspcTcbInfo.Fmspc = in.PckCertInfo.Fmspc
	resp, err := GetFmspcTcbInfoFromProvServer(in.FmspcTcbInfo.Fmspc)
        if err != nil {
		log.WithError(err).Error("Provisioning server curl failed for FmspcTcbInfo fetch operation")
		return err;
	}

	if resp.StatusCode != 200 {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("Invalid response from Intel SGX Provisioning Server")
	}

	headers := resp.Header
	log.WithField("Headers", headers).Debug("Header Values")
	in.FmspcTcbInfo.TcbInfoIssuerChain = []byte(headers["Sgx-Tcb-Info-Issuer-Chain"][0])
	log.WithField("TcbInfoIssuerChain", in.FmspcTcbInfo.TcbInfoIssuerChain).Debug("Values")

	if resp.ContentLength == 0 {
		return errors.New("Invalid content length received")
	}

	defer resp.Body.Close()
        body, err := ioutil.ReadAll( resp.Body )
        if err != nil {
		log.WithError(err).Error("Response Body read error")
            	return err
        }
	in.FmspcTcbInfo.TcbInfo	= []byte(body)
	//log.WithField("TcbInfo", string(CrlBuf.Bytes)).Debug("Values")
	return nil
}

func FetchQEIdentityInfo( in *SgxData ) (error){

	resp, err := GetQEInfoFromProvServer()
        if err != nil {
		log.WithError(err).Error("Provisioning server curl failed for FmspcTcbInfo fetch operation")
		return err
	}

	if resp.StatusCode != 200 {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("Invalid response from Intel SGX Provisioning Server")
	}

	headers := resp.Header
	log.WithField("Headers", headers).Debug("Header Values")
	in.QEInfo.QEIssuerChain = []byte(headers["Sgx-Qe-Identity-Issuer-Chain"][0])
	log.WithField("QEIssuerChain", in.QEInfo.QEIssuerChain).Debug("Values")

	if resp.ContentLength == 0 {
		return errors.New("Invalid content length received")
	}

	defer resp.Body.Close()
        body, err := ioutil.ReadAll( resp.Body )
        if err != nil {
		log.WithError(err).Error("Response Body read error")
            	return err
        }
	in.QEInfo.QEInfo	= []byte(body)
	log.WithField("QEInfo", string(body)).Debug("Values")
	return nil
}

func CachePckCertInfo( db repository.SCSDatabase, data *SgxData )( error ){
	data.PckCert = &types.PckCert {
					PceId: data.PlatformInfo.PceId, 
					QeId: data.PlatformInfo.QeId, 
					Tcbm: data.PckCertInfo.Tcbm,
					Fmspc: data.PckCertInfo.Fmspc, 
					PckCert: data.PckCertInfo.PckCert,
					CertChainId: data.PckCertChain.Id,
					CreatedTime: time.Now(), 
					UpdatedTime: time.Now()}
	var err error
	data.PckCert, err = db.PckCertRepository().Create(*data.PckCert)
	if err != nil {
		log.WithError(err).Error("PckCert Info Insertion failed")
		return err
	}
	return nil
}


func CacheQEIdentityInfo( db repository.SCSDatabase, data *SgxData )( error ){
	data.QEIdentity = &types.QEIdentity{	
					QeIdentity: data.QEInfo.QEInfo,
					QeIdentityIssuerChain: data.QEInfo.QEIssuerChain,
					CreatedTime: time.Now(), 
					UpdatedTime: time.Now()}
	var err error
	data.QEIdentity, err = db.QEIdentityRepository().Create(*data.QEIdentity)
	if err != nil {
		log.WithError(err).Error("QE Identity Info Insertion failed")
		return err
	}
	log.WithField("QE Identity Id", data.QEIdentity.Id).Debug("Db value")
	return nil
}

func CachePckCertChainInfo( db repository.SCSDatabase, data *SgxData )( error ){
	data.PckCertChain = &types.PckCertChain{	
					CertChain: data.PckCertChainInfo.PckCertChain,
					CreatedTime: time.Now(), 
					UpdatedTime: time.Now()}
	var err error
	data.PckCertChain, err = db.PckCertChainRepository().Create(*data.PckCertChain)
	if err != nil {
		log.WithError(err).Error("PckCertChain Info Insertion failed")
		return err
	}
	log.WithField("PCK Cert Chain ID", data.PckCertChain.Id).Debug("Db value")
	return nil
}


func CacheFmspcTcbInfo( db repository.SCSDatabase, data *SgxData )( error ){
	data.FmspcTcb = &types.FmspcTcbInfo{	
					Fmspc: data.FmspcTcbInfo.Fmspc,
					TcbInfo: data.FmspcTcbInfo.TcbInfo,
					TcbInfoIssuerChain: data.FmspcTcbInfo.TcbInfoIssuerChain,
					CreatedTime: time.Now(), 
					UpdatedTime: time.Now()}
	var err error
	data.FmspcTcb, err = db.FmspcTcbInfoRepository().Create(*data.FmspcTcb)
	if err != nil {
		log.WithError(err).Error("PckCertChain Info Insertion failed")
		return err
	}
	log.WithField("Fmspc", data.FmspcTcb.Fmspc).Debug("Cached inside Db")
	return nil
}

func CachePlatformTcbInfo( db repository.SCSDatabase, data *SgxData )( error ){
	data.PlatformTcb.CreatedTime = time.Now()
	data.PlatformTcb.UpdatedTime = time.Now()

	var err error
	data.PlatformTcb, err = db.PlatformTcbRepository().Create(*data.PlatformTcb)
	if err != nil {
			log.WithError(err).Error("Platform Info Insertion failed")
			return err
	}
	return nil
}

func CachePckCRLInfo( db repository.SCSDatabase, data *SgxData )( error ){
	data.PckCrl = &types.PckCrl{	
					Ca: data.PckCRLInfo.Ca,
					PckCrl: data.PckCRLInfo.PckCRL,
					PckCrlCertChain: data.PckCRLInfo.PckCRLCertChain,
					CreatedTime: time.Now(), 
					UpdatedTime: time.Now()}
	var err error
	data.PckCrl, err = db.PckCrlRepository().Create(*data.PckCrl)
	if err != nil {
		log.WithError(err).Error("PckCrl Info Insertion failed")
		return err
	}
	log.WithField("PCK CRL", data.PckCrl).Debug("insertion completed")
	return nil
}
//Agent call
func PushPlatformInfoCB(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		//As of now platform is not supported and currently fetching only processor 
		//CaArray := [2]string { constants.Ca_Processor, constants.Ca_Platform }
		CaArray := [1]string { constants.Ca_Processor}

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



		data.PlatformTcb = &types.PlatformTcb{	
						Encppid: data.PlatformInfo.EncryptedPPID, 
						CpuSvn: data.PlatformInfo.CpuSvn, 
						PceSvn:data.PlatformInfo.PceSvn, 
						PceId: data.PlatformInfo.PceId, 
						QeId: data.PlatformInfo.QeId, 
		}
		existingPlaformData, err := db.PlatformTcbRepository().Retrieve(*data.PlatformTcb)
                if  existingPlaformData != nil {
                        return &resourceError{Message: "Platform Info Already exist", StatusCode: http.StatusBadRequest}
                }

		err = FetchPCKCertInfo(&data)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		err = CachePlatformTcbInfo(db, &data) 
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


		for i:=0; i<len(CaArray); i++ {	
			data.PlatformInfo.Ca=CaArray[i]
			err = FetchPCKCRLInfo(&data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			
			err = CachePckCRLInfo(db, &data) 
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}


		err = FetchFmspcTcbInfo(&data)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		err = CacheFmspcTcbInfo(db, &data) 
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
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



//Admin Call
func RefreshPlatformInfoCB(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Debug("Calling PushPlatformInfoCB")
		return nil
	}
}

