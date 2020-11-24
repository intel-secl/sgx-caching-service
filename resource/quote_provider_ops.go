/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gorilla/mux"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"intel/isecl/scs/constants"
	"intel/isecl/scs/repository"
	"intel/isecl/scs/types"
	"intel/isecl/scs/version"
)

func QuoteProviderOps(r *mux.Router, db repository.SCSDatabase) {
	r.Handle("/pckcert", getPckCertificate(db)).Methods("GET")
	r.Handle("/pckcrl", getPckCrl(db)).Methods("GET")
	r.Handle("/tcb", getTcbInfo(db)).Methods("GET")
	r.Handle("/qe/identity", getQeIdentityInfo(db)).Methods("GET")
	r.Handle("/version", getVersion()).Methods("GET")
}

func getVersion() http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		verStr := fmt.Sprintf("%s-%s", version.Version, version.GitHash)
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		w.Write([]byte(verStr))
	})
}

// Invoked by DCAP Quote Provider Library to fetch PCK certificate
// as part of ECDSA Quote Generation
func getPckCertificate(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if len(r.URL.Query()) < 5 {
			return &resourceError{Message: "query data not provided",
				StatusCode: http.StatusBadRequest}
		}

		encryptedppid := strings.ToLower(r.URL.Query().Get("encrypted_ppid"))
		cpusvn := strings.ToLower(r.URL.Query().Get("cpusvn"))
		pcesvn := strings.ToLower(r.URL.Query().Get("pcesvn"))
		pceid := strings.ToLower(r.URL.Query().Get("pceid"))
		qeid := strings.ToLower(r.URL.Query().Get("qeid"))

		if !validateInputString(constants.EncPPID_Key, encryptedppid) ||
			!validateInputString(constants.CpuSvn_Key, cpusvn) ||
			!validateInputString(constants.PceSvn_Key, pcesvn) ||
			!validateInputString(constants.PceId_Key, pceid) ||
			!validateInputString(constants.QeId_Key, qeid) {
			slog.Errorf("resource/quote_provider_ops: getPckCertificate() Input validation failed for query parameter")
			return &resourceError{Message: "invalid query param",
				StatusCode: http.StatusBadRequest}
		}
		var existingPckCert *types.PckCert

		pinfo := types.Platform{
			CpuSvn: cpusvn, PceSvn: pcesvn, PceId: pceid, QeId: qeid}

		existingPinfo, err := db.PlatformRepository().Retrieve(pinfo)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
		}

		if existingPinfo != nil {
			pck_cert := types.PckCert{
				QeId: qeid, PceId: pceid}
			existingPckCert, err = db.PckCertRepository().Retrieve(pck_cert)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}
		if existingPckCert == nil {
			var manifest string
			if existingPinfo != nil {
				if existingPinfo.PlatformManifest != "" {
					manifest = existingPinfo.PlatformManifest
				} else {
					manifest = ""
				}
			}
			///getLazyCachePckCert API will get PCK Certs and will cache it as well.
			p, err := getLazyCachePckCert(db, encryptedppid, cpusvn, pcesvn, pceid, qeid, manifest)
			if err != nil {
				log.WithError(err).Error("Pck Cert Retrieval failed")
				return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
			}
			existingPckCert = p
		}

		log.WithField("QeID", qeid).Debug("QueryParams")
		log.WithField("PceID", pceid).Debug("QueryParams")

		if existingPckCert == nil {
			return &resourceError{Message: "pck certs not found in db",
				StatusCode: http.StatusNotFound}
		}

		certIndex := existingPckCert.CertIndex
		existingPckCertChain, err := db.PckCertChainRepository().Retrieve(types.PckCertChain{
			ID: existingPckCert.PckCertChainId})
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
		}

		if existingPckCertChain == nil {
			return &resourceError{Message: "pck cert chain data not found in db",
				StatusCode: http.StatusNotFound}
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header()["sgx-pck-certificate-issuer-chain"] = []string{string(existingPckCertChain.PckCertChain)}
		w.Header()["sgx-tcbm"] = []string{existingPckCert.Tcbms[certIndex]}

		w.WriteHeader(http.StatusOK)
		w.Write([]byte(existingPckCert.PckCerts[certIndex]))
		slog.Infof("%s: PCK certificate retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

// api to get PCKCRL pem file form PCS server for a sgx platform
func getPckCrl(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		if len(r.URL.Query()) == 0 {
			return &resourceError{Message: "query data not provided",
				StatusCode: http.StatusBadRequest}
		}

		Ca := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("ca")))

		if !validateInputString(constants.Ca_Key, Ca) {
			slog.Errorf("resource/quote_provider_ops: getPckCrl() Input validation failed for query parameter")
			return &resourceError{Message: "invalid query param",
				StatusCode: http.StatusBadRequest}
		}

		pckCrl := types.PckCrl{Ca: Ca}

		existingPckCrl, err := db.PckCrlRepository().Retrieve(pckCrl)

		if existingPckCrl == nil {
			existingPckCrl, err = getLazyCachePckCrl(db, Ca)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
			}
		}

		w.Header()["SGX-PCK-CRL-Issuer-Chain"] = []string{string(existingPckCrl.PckCrlCertChain)}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(existingPckCrl.PckCrl))
		slog.Infof("%s: PCK CRL retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

// api to get quoting enclave identity information for a sgx platform
func getQeIdentityInfo(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		existingQeInfo, err := db.QEIdentityRepository().RetrieveAll()
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
		}
		if existingQeInfo == nil || len(existingQeInfo) == 0 {
			existingQeInfo, err = getLazyCacheQEIdentityInfo(db)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header()["Sgx-Qe-Identity-Issuer-Chain"] = []string{string(existingQeInfo[0].QeIssuerChain)}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(existingQeInfo[0].QeInfo))
		slog.Infof("%s: QE Identity info retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

// api to get trusted computing base information for a sgx platform using platfrom fmspc value
func getTcbInfo(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if len(r.URL.Query()) == 0 {
			return &resourceError{Message: "query data not provided",
				StatusCode: http.StatusBadRequest}
		}

		Fmspc := strings.ToLower(r.URL.Query().Get("fmspc"))

		if !validateInputString(constants.Fmspc_Key, Fmspc) {
			slog.Errorf("resource/quote_provider_ops: getTcbInfo() Input validation failed for query parameter")
			return &resourceError{Message: "invalid query param", StatusCode: http.StatusBadRequest}
		}
		log.WithField("Fmspc", Fmspc[0]).Debug("Value")

		TcbInfo := types.FmspcTcbInfo{Fmspc: Fmspc}
		existingFmspc, err := db.FmspcTcbInfoRepository().Retrieve(TcbInfo)
		if existingFmspc == nil {
			existingFmspc, err = getLazyCacheFmspcTcbInfo(db, Fmspc)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header()["SGX-TCB-Info-Issuer-Chain"] = []string{string(existingFmspc.TcbInfoIssuerChain)}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(existingFmspc.TcbInfo))
		slog.Infof("%s: TCB Info retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}
