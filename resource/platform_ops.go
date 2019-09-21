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
	log "github.com/sirupsen/logrus"
)

type Response struct{
	Status 		string
	Message 	string
}

type PlatformInfo struct {
	EncryptedPPID 	string `json:"enc_ppid"`
	CpuSvn 		string `json:"cpu_svn"`
	PceSvn 		string `json:"pce_svn"`
	PceId 		string `json:"pce_id"`
	QeId 		string `json:"qe_id"`
	Ca 		string `json:"ca"`
	CreatedTime 	time.Time
}
type PckCertChainInfo struct {
	Id 		uint
	CreatedTime 	time.Time
	PckCertChain 	[]byte
}
type PckCRLInfo struct {
	PckCRL 		[]byte
	PckCRLCertChain []byte
	Ca 		string
	CreatedTime 	time.Time
}
type PckCertInfo struct {
	PckCert         []byte
	Tcbm      	string     
	Fmspc      	string     
	CreatedTime 	time.Time
	PckCertChainId 	int
}

type FmspcTcbInfo struct {
	Fmspc      	string     
	TcbInfo         []byte
	TcbInfoIssuerChain  []byte
	CreatedTime 	time.Time
}

type QEInfo struct {
	Id		uint
	QEInfo         	[]byte
	QEIssuerChain  	[]byte
	CreatedTime 	time.Time
}

type SgxData struct {
	Type constants.CacheType
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
		dump, _ := httputil.DumpResponse(resp, true)
		log.WithField("Status Code", resp.StatusCode).Error(string(dump))
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

	var err error
	data.PckCert = &types.PckCert {
					PceId: data.PlatformInfo.PceId, 
					QeId: data.PlatformInfo.QeId, 
					Tcbm: data.PckCertInfo.Tcbm,
					Fmspc: data.PckCertInfo.Fmspc, 
					PckCert: data.PckCertInfo.PckCert,
					CertChainId: data.PckCertChain.Id,}

	if data.Type == constants.CacheRefresh {
		data.PckCert.UpdatedTime = time.Now()
		data.PckCert.CreatedTime = data.PlatformInfo.CreatedTime
		err = db.PckCertRepository().Update(*data.PckCert)
		if err != nil {
			log.WithError(err).Error("PckCert Info Updation failed")
			return err
		}
	}else{
		data.PckCert.CreatedTime = time.Now()
		data.PckCert.UpdatedTime = time.Now()
		data.PckCert, err = db.PckCertRepository().Create(*data.PckCert)
		if err != nil {
			log.WithError(err).Error("PckCert Info Insertion failed")
			return err
		}
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
        if  data.Type == constants.CacheRefresh {
		data.QEIdentity.UpdatedTime = time.Now()
		data.QEIdentity.CreatedTime = data.QEInfo.CreatedTime
		data.QEIdentity.Id = data.QEInfo.Id
		err = db.QEIdentityRepository().Update(*data.QEIdentity)
		if err != nil {
			log.WithError(err).Error("QE Identity Info Updateion failed")
			return err
		}
	}else{
		data.QEIdentity.UpdatedTime = time.Now()
		data.QEIdentity.CreatedTime = time.Now()
		data.QEIdentity, err = db.QEIdentityRepository().Create(*data.QEIdentity)
		if err != nil {
			log.WithError(err).Error("QE Identity Info Insertion failed")
			return err
		}
	}
	log.WithField("QE Identity Id", data.QEIdentity.Id).Debug("Db value")
	return nil
}

func CachePckCertChainInfo( db repository.SCSDatabase, data *SgxData )( error ){

	var err error
	data.PckCertChain = &types.PckCertChain{	
					CertChain: data.PckCertChainInfo.PckCertChain,}

	if data.Type == constants.CacheRefresh {
		data.PckCertChain.Id = data.PckCertChainInfo.Id
		data.PckCertChain.CreatedTime = data.PckCertChainInfo.CreatedTime
		data.PckCertChain.UpdatedTime = time.Now()
		err = db.PckCertChainRepository().Update(*data.PckCertChain)
		if err != nil {
			log.WithError(err).Error("PckCertChain Info Updation failed")
			return err
		}
	}else{
		data.PckCertChain.UpdatedTime = time.Now()
		data.PckCertChain.CreatedTime = time.Now()
		data.PckCertChain, err = db.PckCertChainRepository().Create(*data.PckCertChain)
		if err != nil {
			log.WithError(err).Error("PckCertChain Info Insertion failed")
			return err
		}
	}
	log.WithField("PCK Cert Chain ID", data.PckCertChain.Id).Debug("Db value")
	return nil
}


func CacheFmspcTcbInfo( db repository.SCSDatabase, data *SgxData)( error ){
	data.FmspcTcb = &types.FmspcTcbInfo{	
					Fmspc: data.FmspcTcbInfo.Fmspc,
					TcbInfo: data.FmspcTcbInfo.TcbInfo,
					TcbInfoIssuerChain: data.FmspcTcbInfo.TcbInfoIssuerChain,}
	var err error

	if data.Type == constants.CacheInsert {
		data.FmspcTcb.CreatedTime = time.Now()
		data.FmspcTcb.UpdatedTime = time.Now()
		data.FmspcTcb, err = db.FmspcTcbInfoRepository().Create(*data.FmspcTcb)
		if err != nil {
			log.WithError(err).Error("PckCertChain Info Insertion failed")
			return err
		}
	}else {
		data.FmspcTcb.CreatedTime = data.FmspcTcbInfo.CreatedTime
		data.FmspcTcb.UpdatedTime = time.Now()
		err = db.FmspcTcbInfoRepository().Update(*data.FmspcTcb)
		if err != nil {
			log.WithError(err).Error("PckCertChain Info Insertion failed")
			return err
		}
	}
	log.WithField("Fmspc", data.FmspcTcb.Fmspc).Debug("Cached inside Db")
	return nil
}

func CachePlatformTcbInfo( db repository.SCSDatabase, data *SgxData )( error ){

	if data.PlatformTcb == nil {
		data.PlatformTcb = &types.PlatformTcb{
						Encppid: data.PlatformInfo.EncryptedPPID, 
						CpuSvn: data.PlatformInfo.CpuSvn, 
						PceSvn:data.PlatformInfo.PceSvn, 
						PceId: data.PlatformInfo.PceId, 
						QeId: data.PlatformInfo.QeId, 
		}
	}

	var err error
        if  data.Type == constants.CacheRefresh {
		data.PlatformTcb.CreatedTime = data.PlatformInfo.CreatedTime
		data.PlatformTcb.UpdatedTime = time.Now()
		err = db.PlatformTcbRepository().Update(*data.PlatformTcb)
		if err != nil {
				log.WithError(err).Error("Platform Info Updation failed")
				return err
		}
        }else {
		data.PlatformTcb.UpdatedTime = time.Now()
		data.PlatformTcb.CreatedTime = time.Now()
		data.PlatformTcb, err = db.PlatformTcbRepository().Create(*data.PlatformTcb)
		if err != nil {
				log.WithError(err).Error("Platform Info Insertion failed")
				return err
		}
	}
	return nil
}

func CachePckCRLInfo( db repository.SCSDatabase, data *SgxData )( error ){
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
				log.WithError(err).Error("Platform Info Updation failed")
				return err
		}
        }else {
		data.PckCrl.CreatedTime = time.Now()
		data.PckCrl.UpdatedTime = time.Now()
		data.PckCrl, err = db.PckCrlRepository().Create(*data.PckCrl)
		if err != nil {
			log.WithError(err).Error("PckCrl Info Insertion failed")
			return err
		}
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

		data.Type = constants.CacheInsert
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


		data.FmspcTcbInfo.Fmspc = data.PckCertInfo.Fmspc
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


func RefreshPckCerts(db repository.SCSDatabase) error {

	existingPlaformData, err := db.PlatformTcbRepository().RetrieveAllPlatformInfo()
        if  len(existingPlaformData) == 0 {
                return errors.New("Cached PCK Cert count is 0, cannot perform refresh operation")
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
	log.Debug("RefreshPckCerts completed successfully")
	return nil
}

func RefreshAllPckCrl(db repository.SCSDatabase) error{
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
	log.Debug("RefreshAllPckCrl completed successfully")
	return nil
}
func RefreshAllTcbInfo(db repository.SCSDatabase) error{

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
	log.Debug("RefreshAllTcbInfo completed successfully")
	return nil
}
func RefreshAllQE(db repository.SCSDatabase) error{

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
	log.Debug("RefreshAllQE completed successfully")
	return nil
}

func RefreshTcbInfos(db repository.SCSDatabase) error {
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

	log.Debug("Timer CB: RefreshPlatformInfoTimerCB, started")
	var err error
	if strings.Compare(rtype ,constants.Type_Refresh_Cert) == 0 {
		err = RefreshPckCerts(db)
		if err != nil{
			log.WithError(err).Error("Error in Refresh Pck Certificates")
			return err
		}
	} else if strings.Compare(rtype, constants.Type_Refresh_Tcb) == 0  {
		err = RefreshTcbInfos(db)
		if err != nil{
			log.WithError(err).Error("Error in Refresh Tcb Infos")
			return err
		}
	}
	log.Debug("Timer CB: RefreshPlatformInfoTimerCB, completed")
	return nil

}
//Admin Call
func RefreshPlatformInfoCB(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.Debug("Calling RefreshPlatformInfoCB", r.URL.Query())
		if  r.URL.Query() != nil && len(r.URL.Query()) > len( constants.Type_Key) {
                	Type,_ := r.URL.Query()["type"]
                        if !ValidateInputString(constants.Type_Key, Type[0]) {
                        	return &resourceError{Message: "Invalid query Param Data type", StatusCode: http.StatusBadRequest}
			}

			err := RefreshPckCerts(db)
			if err != nil{
                        	return &resourceError{Message: "Error in Refresh Pck Certificates", 
							StatusCode: http.StatusInternalServerError}
			}
			return nil
		}

		err := RefreshTcbInfos(db)
		if err != nil{
                       	return &resourceError{Message: "Error in Refresh Pck Certificates", 
						StatusCode: http.StatusInternalServerError}
		}

 		w.Header().Set("Content-Type", "application/json")
                w.WriteHeader(http.StatusOK) // HTTP 200

                res := Response{ Status:"Success", Message: "Platform Data refreshed Successfully"}
                js, err := json.Marshal(res)
                if err != nil {
                        return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
                }
                w.Write(js)

		return nil
	}
}

