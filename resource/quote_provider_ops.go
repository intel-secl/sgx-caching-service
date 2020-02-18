/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"strings"
	"net/http"
	"encoding/pem"

	"intel/isecl/sgx-caching-service/constants"
	"intel/isecl/sgx-caching-service/repository"
	"intel/isecl/sgx-caching-service/types"
	"github.com/gorilla/mux"
)

func QuoteProviderOps(r *mux.Router, db repository.SCSDatabase) {
	r.Handle("/pckcert", GetPCKCertificateCB(db)).Methods("GET")
	r.Handle("/pckcrl", GetPCKCRLCB(db)).Methods("GET")
	r.Handle("/tcb", GetTCBInfoCB(db)).Methods("GET")
	r.Handle("/qe/identity", GetQEIdentityInfoCB(db)).Methods("GET")
}

// Invoked by DCAP Quote Provider Library to fetch PCK certificate
// as part of ECDSA Quote Generation
func GetPCKCertificateCB(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.WithField("GetPCKCertificateCB", ":").Debug("Invoked")


		if ( len(r.URL.Query()) == 0) {
			return &resourceError{Message: "GetPCKCertificateCB: The Request Query Data not provided", 
									StatusCode: http.StatusBadRequest}
		} 

		EncryptedPPID,_	:= r.URL.Query()["encrypted_ppid"]
		CpuSvn, _  	:= r.URL.Query()["cpusvn"]
		PceSvn,_  	:= r.URL.Query()["pcesvn"]
		PceId,_  	:= r.URL.Query()["pceid"]
		QeId,_  	:= r.URL.Query()["qeid"]

                if  	!ValidateInputString(constants.EncPPID_Key, EncryptedPPID[0]) || 
			!ValidateInputString(constants.CpuSvn_Key, CpuSvn[0]) || 
			!ValidateInputString(constants.PceSvn_Key, PceSvn[0]) || 
			!ValidateInputString(constants.PceId_Key, PceId[0])   || 
			!ValidateInputString(constants.QeId_Key, QeId[0])  {
                        return &resourceError{Message: "GetPCKCertificateCB: Invalid query Param Data", 
									StatusCode: http.StatusBadRequest}
                }

		log.WithField("Encrypted PPID", EncryptedPPID).Debug("QueryParams")

		pinfo := types.Platform{	
						CpuSvn: strings.ToLower(CpuSvn[0]), 
						PceSvn:strings.ToLower(PceSvn[0]), 
						PceId: strings.ToLower(PceId[0]), 
						QeId: strings.ToLower(QeId[0]),}
		existingPinfo, err := db.PlatformRepository().Retrieve(pinfo)
		model, err := GetCacheModel()
		if err != nil {
			return &resourceError{ Message: "GetPCKCertificateCB: Get Lazy Cache Model error: "+err.Error(), 
									StatusCode: http.StatusInternalServerError}
		}
		if model == constants.RegisterCachingModel&& existingPinfo == nil {
                        return &resourceError{Message: "GetPCKCertificateCB: Platform Data not cached", 
									StatusCode: http.StatusNotFound}
                } else if model == constants.LazyCachingModel && existingPinfo == nil {
                        existingPinfo, err = GetLazyCachePlatformInfo(db, strings.ToLower(EncryptedPPID[0]), 
										strings.ToLower(CpuSvn[0]), 
										strings.ToLower(PceSvn[0]), 
										strings.ToLower(PceId[0]), 
										strings.ToLower(QeId[0]))
                        if err != nil {
                                return &resourceError{ Message: "GetPCKCertificateCB: Lazy Cache error: "+err.Error(), 
							StatusCode: http.StatusInternalServerError}
                        }
                }

		pck_cert := types.PckCert{ 
					QeId: strings.ToLower(QeId[0]), 
					PceId:PceId[0],}
		existingPckCert, err := db.PckCertRepository().Retrieve(pck_cert)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		log.WithField("QeID", QeId[0]).Debug("QueryParams")
		log.WithField("PceID", PceId[0]).Debug("QueryParams")
                if existingPckCert == nil {
			if err != nil {
				log.WithError(err).Error("Pck Cert Retrival failed")
			}
                        return &resourceError{Message: "GetPCKCertificateCB: Pck Cert Data not cached", 
										StatusCode: http.StatusBadRequest}
                }

		existingPckCertChain, err := db.PckCertChainRepository().Retrieve(types.PckCertChain{
						Id: existingPckCert.CertChainId})
                if existingPckCertChain == nil {
                        return &resourceError{Message: "GetPCKCertificateCB: Pck Cert Chain Data not cached", 
										StatusCode: http.StatusNotFound}
                }
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header()["sgx-pck-certificate-issuer-chain"] = []string{string(existingPckCertChain.CertChain)}
		w.Header()["sgx-tcbm"]= []string{existingPckCert.Tcbm[0]}

 		w.WriteHeader(http.StatusOK) // HTTP 200
		log.Warn(existingPckCert.PckCert)
		CertBuf, _ := pem.Decode([]byte(existingPckCert.PckCert[0]))
        	if CertBuf == nil {
                        return &resourceError{Message: "GetPCKCertificateCB: Invalid Pck Cert cache", 
									StatusCode: http.StatusInternalServerError}
        	}

	        w.Write([]byte(existingPckCert.PckCert[0]))
		log.WithField("Pck Cert request responded with status", http.StatusOK).Debug("Response")
		return nil
	}
}

//QutoProvider call
func GetPCKCRLCB(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.WithField("GetPCKCRLCB", ":").Debug("Invoked")

		if ( len(r.URL.Query()) == 0) {
                        return &resourceError{Message: "GetPCKCRLCB: The Request Query Data not provided", 
										StatusCode: http.StatusBadRequest}
                }

		Ca,_	:= r.URL.Query()["ca"]

                if  	!ValidateInputString(constants.Ca_Key, Ca[0]) {
                        return &resourceError{Message: "GetPCKCRLCB: Invalid query Param Data", StatusCode: http.StatusBadRequest}
                }

		pckCrl := types.PckCrl{Ca: Ca[0]}
		model, err := GetCacheModel()
		if err != nil {
			return &resourceError{ Message: "GetPCKCRLCB: Lazy Cache Model error: "+err.Error(), 
							StatusCode: http.StatusInternalServerError}
		}
		existingPckCrl, err := db.PckCrlRepository().Retrieve(pckCrl)

                if model == constants.RegisterCachingModel && existingPckCrl == nil {
                        return &resourceError{Message: "GetPCKCRLCB: Pck Crl Data not cached", 
								StatusCode: http.StatusNotFound}
                } else if model == constants.LazyCachingModel && existingPckCrl == nil{
                        existingPckCrl, err = GetLazyCachePckCrl(db, Ca[0])
                        if err != nil {
                                return &resourceError{ Message: "GetPCKCRLCB: Lazy Cache error: "+err.Error(), 
							StatusCode: http.StatusInternalServerError}
                        }
                }

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header()["sgx-pck-crl-issuer-chain"]= []string{string(existingPckCrl.PckCrlCertChain)}

 		w.WriteHeader(http.StatusOK) // HTTP 200
        	CrlBuf, _ := pem.Decode([]byte(existingPckCrl.PckCrl))
        	if CrlBuf == nil {
                        return &resourceError{Message: "GetPCKCRLCB: Invalid Pck Crl cache", 
							StatusCode: http.StatusInternalServerError}
        	}
                err = pem.Encode(w, CrlBuf)
                if err != nil {
                        return &resourceError{Message: "GetPCKCRLCB: Error in writing response to client", 
								StatusCode: http.StatusInternalServerError}
                }
		return nil
	}
}

//QutoProvider call
func GetQEIdentityInfoCB(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.WithField("GetQEIdentityInfoCB", ":").Debug("Invoked")
		existingQeInfo, err := db.QEIdentityRepository().RetrieveAll()
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		model, err := GetCacheModel()
		if err != nil {
			return &resourceError{ Message: "GetQEIdentityInfoCB: Lazy Cache Model error: "+err.Error(), 
							StatusCode: http.StatusInternalServerError}
		}
		if model == constants.RegisterCachingModel && (existingQeInfo == nil || len(existingQeInfo) == 0) {
                        return &resourceError{Message: "GetQEIdentityInfoCB: QE Identity Info Data not cached", 
										StatusCode: http.StatusNotFound}
                } else if model == constants.LazyCachingModel && (existingQeInfo == nil || len(existingQeInfo) == 0) {
			existingQeInfo, err = GetLazyCacheQEIdentityInfo(db)
                        if err != nil {
				return &resourceError{ Message: "GetQEIdentityInfoCB: Lazy Cache error: "+err.Error(), 
							StatusCode: http.StatusInternalServerError}
                        }
                }

		if len(existingQeInfo) != 1{
                        return &resourceError{Message: "GetQEIdentityInfoCB:Tcb Info caching multiple duplicate entries", 
										StatusCode: http.StatusInternalServerError}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header()["sgx-qe-identity-issuer-chain"]= []string{ string(existingQeInfo[0].QeIdentityIssuerChain)}
 		w.WriteHeader(http.StatusOK) // HTTP 200
		w.Write(existingQeInfo[0].QeIdentity)
		return nil
	}
}

//QutoProvider call
func GetTCBInfoCB(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		log.WithField("GetTCBInfoCB", ":").Debug("Invoked")

		if ( len(r.URL.Query()) == 0) {
                        return &resourceError{Message: "GetTCBInfoCB:The Request Query Data not provided", 
									StatusCode: http.StatusBadRequest}
                }

		Fmspc, _ := r.URL.Query()["fmspc"]

                if  	!ValidateInputString(constants.Fmspc_Key, Fmspc[0]) {
                        return &resourceError{Message: "Invalid query Param Data", StatusCode: http.StatusBadRequest}
                }
		log.WithField("Fmspc", Fmspc[0]).Debug("Value")


		TcbInfo := types.FmspcTcbInfo{ Fmspc: strings.ToLower(Fmspc[0])}
		existingFmspc, err := db.FmspcTcbInfoRepository().Retrieve(TcbInfo)
		model, err := GetCacheModel()
		if err != nil {
			return &resourceError{ Message: "GetTCBInfoCB: Lazy Cache Model error: "+err.Error(), 
							StatusCode: http.StatusInternalServerError}
		}
                if model == constants.RegisterCachingModel && existingFmspc == nil {
                        return &resourceError{Message: "GetTCBInfoCB: Tcb Info Data not cached", 
									StatusCode: http.StatusNotFound}
                } else if model == constants.LazyCachingModel && existingFmspc == nil{
                        existingFmspc, err = GetLazyCacheFmspcTcbInfo(db, strings.ToLower(Fmspc[0]))
                        if err != nil {
                                return &resourceError{ Message: "GetTCBInfoCB: Lazy Cache error: "+err.Error(), 
							StatusCode: http.StatusInternalServerError}
                        }
                }
		w.Header().Set("Content-Type", "application/json")
		w.Header()["sgx-tcb-info-issuer-chain"]= []string{ string(existingFmspc.TcbInfoIssuerChain)}
 		w.WriteHeader(http.StatusOK) // HTTP 200

		w.Write(existingFmspc.TcbInfo)
		return nil
	}
}
