/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	"intel/isecl/scs/constants"
	"intel/isecl/scs/repository"
	"intel/isecl/scs/types"
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
		if len(r.URL.Query()) == 0 {
			return &resourceError{Message: "GetPCKCertificateCB: Query Data not provided",
				StatusCode: http.StatusBadRequest}
		}

		EncryptedPPID, _ := r.URL.Query()["encrypted_ppid"]
		CpuSvn, _ := r.URL.Query()["cpusvn"]
		PceSvn, _ := r.URL.Query()["pcesvn"]
		PceId, _ := r.URL.Query()["pceid"]
		QeId, _ := r.URL.Query()["qeid"]

		if !ValidateInputString(constants.EncPPID_Key, EncryptedPPID[0]) ||
			!ValidateInputString(constants.CpuSvn_Key, CpuSvn[0]) ||
			!ValidateInputString(constants.PceSvn_Key, PceSvn[0]) ||
			!ValidateInputString(constants.PceId_Key, PceId[0]) ||
			!ValidateInputString(constants.QeId_Key, QeId[0]) {
			return &resourceError{Message: "GetPCKCertificateCB: Invalid query Param Data",
				StatusCode: http.StatusBadRequest}
		}

		var existingPckCert *types.PckCert
		log.WithField("Encrypted PPID", EncryptedPPID).Debug("QueryParams")

		pinfo := types.Platform{
			CpuSvn: strings.ToLower(CpuSvn[0]),
			PceSvn: strings.ToLower(PceSvn[0]),
			PceId:  strings.ToLower(PceId[0]),
			QeId:   strings.ToLower(QeId[0])}
		existingPinfo, err := db.PlatformRepository().Retrieve(pinfo)

		if existingPinfo != nil {
			pck_cert := types.PckCert{
				QeId:  strings.ToLower(QeId[0]),
				PceId: PceId[0]}
			existingPckCert, err = db.PckCertRepository().Retrieve(pck_cert)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		if existingPckCert == nil {
			///GetLazyCachePckCert API will get PCK Certs and will cache it as well.
			var manifest string
			if existingPinfo != nil {
				if existingPinfo.PlatformManifest != "" {
					manifest = existingPinfo.PlatformManifest
				} else {
					manifest = ""
				}
			}
			p, err := GetLazyCachePckCert(db, strings.ToLower(EncryptedPPID[0]),
				strings.ToLower(CpuSvn[0]),
				strings.ToLower(PceSvn[0]),
				strings.ToLower(PceId[0]),
				strings.ToLower(QeId[0]),
				manifest)
			if err != nil {
				log.WithError(err).Error("Pck Cert Retrieval failed")
				return &resourceError{Message: "GetPCKCertificateCB: GetLazyCachePckCert error: " + err.Error(),
					StatusCode: http.StatusInternalServerError}
			}
			existingPckCert = p
		}

		log.WithField("QeID", QeId[0]).Debug("QueryParams")
		log.WithField("PceID", PceId[0]).Debug("QueryParams")

		if existingPckCert == nil {
			return &resourceError{Message: "GetPCKCertificateCB: Pck Cert Data not in DB",
				StatusCode: http.StatusNotFound}
		}

		certIndex := existingPckCert.CertIndex
		existingPckCertChain, err := db.PckCertChainRepository().Retrieve(types.PckCertChain{
			ID: existingPckCert.PckCertChainId})
		if existingPckCertChain == nil {
			return &resourceError{Message: "GetPCKCertificateCB: Pck Cert Chain Data not cached",
				StatusCode: http.StatusNotFound}
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header()["sgx-pck-certificate-issuer-chain"] = []string{string(existingPckCertChain.PckCertChain)}
		w.Header()["sgx-tcbm"] = []string{existingPckCert.Tcbms[certIndex]}

		w.WriteHeader(http.StatusOK) // HTTP 200

		w.Write([]byte(existingPckCert.PckCerts[certIndex]))
		return nil
	}
}

func GetPCKCRLCB(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		if len(r.URL.Query()) == 0 {
			return &resourceError{Message: "GetPCKCRLCB: The Request Query Data not provided",
				StatusCode: http.StatusBadRequest}
		}

		Ca, _ := r.URL.Query()["ca"]

		if !ValidateInputString(constants.Ca_Key, Ca[0]) {
			return &resourceError{Message: "GetPCKCRLCB: Invalid query Param Data",
				StatusCode: http.StatusBadRequest}
		}

		pckCrl := types.PckCrl{Ca: Ca[0]}

		existingPckCrl, err := db.PckCrlRepository().Retrieve(pckCrl)

		if existingPckCrl == nil {
			existingPckCrl, err = GetLazyCachePckCrl(db, Ca[0])
			if err != nil {
				return &resourceError{Message: "GetPCKCRLCB: Lazy Cache error: " + err.Error(),
					StatusCode: http.StatusInternalServerError}
			}
		}

		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header()["SGX-PCK-CRL-Issuer-Chain"] = []string{string(existingPckCrl.PckCrlCertChain)}
		w.WriteHeader(http.StatusOK) // HTTP 200
		w.Write([]byte(existingPckCrl.PckCrl))
		return nil
	}
}

func GetQEIdentityInfoCB(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		existingQeInfo, err := db.QEIdentityRepository().RetrieveAll()
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		if existingQeInfo == nil || len(existingQeInfo) == 0 {
			existingQeInfo, err = GetLazyCacheQEIdentityInfo(db)
			if err != nil {
				return &resourceError{Message: "GetQEIdentityInfoCB: Lazy Cache error: " + err.Error(),
					StatusCode: http.StatusInternalServerError}
			}
		}

		if len(existingQeInfo) != 1 {
			return &resourceError{Message: "GetQEIdentityInfoCB:Tcb Info caching multiple duplicate entries",
				StatusCode: http.StatusInternalServerError}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header()["Sgx-Qe-Identity-Issuer-Chain"] = []string{string(existingQeInfo[0].QeIssuerChain)}
		w.WriteHeader(http.StatusOK) // HTTP 200
		w.Write([]byte(existingQeInfo[0].QeInfo))
		return nil
	}
}

func GetTCBInfoCB(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if len(r.URL.Query()) == 0 {
			return &resourceError{Message: "GetTCBInfoCB:The Request Query Data not provided",
				StatusCode: http.StatusBadRequest}
		}

		Fmspc, _ := r.URL.Query()["fmspc"]

		if !ValidateInputString(constants.Fmspc_Key, Fmspc[0]) {
			return &resourceError{Message: "Invalid query Param Data", StatusCode: http.StatusBadRequest}
		}
		log.WithField("Fmspc", Fmspc[0]).Debug("Value")

		TcbInfo := types.FmspcTcbInfo{Fmspc: strings.ToLower(Fmspc[0])}
		existingFmspc, err := db.FmspcTcbInfoRepository().Retrieve(TcbInfo)
		if existingFmspc == nil {
			existingFmspc, err = GetLazyCacheFmspcTcbInfo(db, strings.ToLower(Fmspc[0]))
			if err != nil {
				return &resourceError{Message: "GetTCBInfoCB: Lazy Cache error: " + err.Error(),
					StatusCode: http.StatusInternalServerError}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header()["SGX-TCB-Info-Issuer-Chain"] = []string{string(existingFmspc.TcbInfoIssuerChain)}
		w.WriteHeader(http.StatusOK) // HTTP 200
		w.Write([]byte(existingFmspc.TcbInfo))
		return nil
	}
}
