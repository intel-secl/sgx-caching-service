/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"net/http"
	"strings"

	"encoding/json"
	commLogMsg "intel/isecl/lib/common/v5/log/message"
	"intel/isecl/scs/v5/constants"
	"intel/isecl/scs/v5/repository"
	"intel/isecl/scs/v5/types"
	"intel/isecl/scs/v5/version"

	"github.com/gorilla/mux"
)

type PCKCertInfo struct {
	Ppid string `json:"ppid"`
}

func QuoteProviderOps(r *mux.Router, db repository.SCSDatabase) {
	r.Handle("/pckcert", getPckCertificate(db)).Methods("GET")
	r.Handle("/pckcert", updatePckCertificate(db)).Methods("PUT")
	r.Handle("/pckcrl", getPckCrl(db)).Methods("GET")
	r.Handle("/tcb", getTcbInfo(db)).Methods("GET")
	r.Handle("/qe/identity", getQeIdentityInfo(db)).Methods("GET")
	r.Handle("/version", getVersion()).Methods("GET")
}

var pckCertificateRetrieveParams = map[string]bool{"encrypted_ppid": true, "cpusvn": true, "pcesvn": true, "pceid": true,
	"qeid": true}

var pckCrlRetrieveParams = map[string]bool{"ca": true, "encoding": true}

var tcbInfoRetrieveParams = map[string]bool{"fmspc": true}

func getVersion() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		verStr := version.GetVersion()
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		_, err := w.Write([]byte(verStr))
		if err != nil {
			log.WithError(err).Error("Could not write version to response")
		}
	}
}

// Invoked by vmware python client to update PCK certificate
func updatePckCertificate(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if r.ContentLength == 0 {
			slog.Error("resource/platform_ops: updatePckCertificate() The request body was not provided")
			return &resourceError{Message: "platform data not provided",
				StatusCode: http.StatusBadRequest}
		}

		var certData PCKCertInfo
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err := dec.Decode(&certData)
		if err != nil {
			slog.WithError(err).Errorf("resource/quote_provider_ops.go: updatePckCertificate() %s :  Failed to decode request body", commLogMsg.InvalidInputBadEncoding)
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}
		ppid := strings.ToLower(certData.Ppid)
		if !validateInputString(constants.PPID, ppid) {
			slog.Errorf("resource/quote_provider_ops: updatePckCertificate() Input validation failed for ppid given")
			return &resourceError{Message: "invalid input param",
				StatusCode: http.StatusBadRequest}
		}

		pInfo := &types.Platform{Ppid: ppid}
		existingPinfo, err := db.PlatformRepository().Retrieve(pInfo)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
		}
		// getLazyCachePckCert API will get PCK Certs and will cache it as well.
		_, _, _, err = getLazyCachePckCert(db, existingPinfo, constants.CacheRefresh)
		if err != nil {
			log.WithError(err).Error("Pck Cert Retrieval failed")
			return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
		}
		slog.Infof("%s: PCK certificate updated by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

// Invoked by DCAP Quote Provider Library to fetch PCK certificate
// as part of ECDSA Quote Generation
func getPckCertificate(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		if len(r.URL.Query()) < 5 {
			return &resourceError{Message: "query data not provided",
				StatusCode: http.StatusBadRequest}
		}

		if err := validateQueryParams(r.URL.Query(), pckCertificateRetrieveParams); err != nil {
			slog.Errorf("resource/platform_ops: getTcbStatus() %s", err.Error())
			return &resourceError{Message: "invalid query param", StatusCode: http.StatusBadRequest}
		}

		encryptedppid := strings.ToLower(r.URL.Query().Get("encrypted_ppid"))
		cpusvn := strings.ToLower(r.URL.Query().Get("cpusvn"))
		pcesvn := strings.ToLower(r.URL.Query().Get("pcesvn"))
		pceid := strings.ToLower(r.URL.Query().Get("pceid"))
		qeid := strings.ToLower(r.URL.Query().Get("qeid"))

		if !validateInputString(constants.EncPPIDKey, encryptedppid) ||
			!validateInputString(constants.CPUSvnKey, cpusvn) ||
			!validateInputString(constants.PceSvnKey, pcesvn) ||
			!validateInputString(constants.PceIDKey, pceid) ||
			!validateInputString(constants.QeIDKey, qeid) {
			slog.Errorf("resource/quote_provider_ops: getPckCertificate() Input validation failed for query parameter")
			return &resourceError{Message: "invalid query param",
				StatusCode: http.StatusBadRequest}
		}
		var existingPckCert *types.PckCert
		var existingPckCertChain *types.PckCertChain

		pInfo := &types.Platform{QeID: qeid, PceID: pceid}

		existingPinfo, err := db.PlatformRepository().Retrieve(pInfo)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
		}

		if existingPinfo != nil {
			pckCert := &types.PckCert{QeID: qeid, PceID: pceid}
			existingPckCert, err = db.PckCertRepository().Retrieve(pckCert)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			certChain := &types.PckCertChain{Ca: existingPinfo.Ca}
			existingPckCertChain, err = db.PckCertChainRepository().Retrieve(certChain)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}
		if existingPckCert == nil {
			pInfo.Encppid = encryptedppid
			if existingPinfo != nil {
				pInfo.Manifest = existingPinfo.Manifest
			}

			// getLazyCachePckCert API will get PCK Certs and will cache it as well.
			p, c, _, err := getLazyCachePckCert(db, pInfo, constants.CacheInsert)
			if err != nil {
				log.WithError(err).Error("Pck Cert Retrieval failed")
				return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
			}
			existingPckCert = p
			existingPckCertChain = c
		}

		certIndex := existingPckCert.CertIndex
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header()["sgx-pck-certificate-issuer-chain"] = []string{existingPckCertChain.PckCertChain}
		w.Header()["sgx-tcbm"] = []string{existingPckCert.Tcbms[certIndex]}

		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(existingPckCert.PckCerts[certIndex]))
		if err != nil {
			log.WithError(err).Error("Could not write pck cert data to response")
		}
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

		if err := validateQueryParams(r.URL.Query(), pckCrlRetrieveParams); err != nil {
			slog.Errorf("resource/platform_ops: getPckCrl() %s", err.Error())
			return &resourceError{Message: "invalid query param", StatusCode: http.StatusBadRequest}
		}

		ca := strings.TrimSpace(strings.ToLower(r.URL.Query().Get("ca")))

		if !validateInputString(constants.CaKey, ca) {
			slog.Errorf("resource/quote_provider_ops: getPckCrl() Input validation failed for query parameter")
			return &resourceError{Message: "invalid query param",
				StatusCode: http.StatusBadRequest}
		}

		pckCrl := &types.PckCrl{Ca: ca}

		existingPckCrl, err := db.PckCrlRepository().Retrieve(pckCrl)
		if existingPckCrl == nil {
			existingPckCrl, err = getLazyCachePckCrl(db, ca, constants.CacheInsert)
			if existingPckCrl == nil || err != nil {
				return &resourceError{Message: "Error retrieving required PCK CRL", StatusCode: http.StatusNotFound}
			}
		}

		w.Header()["SGX-PCK-CRL-Issuer-Chain"] = []string{existingPckCrl.PckCrlCertChain}
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(existingPckCrl.PckCrl))
		if err != nil {
			log.WithError(err).Error("Could not write pck crl data to response")
		}
		slog.Infof("%s: PCK CRL retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

// api to get quoting enclave identity information for a sgx platform
func getQeIdentityInfo(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		existingQeInfo, err := db.QEIdentityRepository().Retrieve()
		if existingQeInfo == nil {
			existingQeInfo, err = getLazyCacheQEIdentityInfo(db, constants.CacheInsert)
			if err != nil || existingQeInfo == nil {
				return &resourceError{Message: "Error retrieving QEIdentity info", StatusCode: http.StatusNotFound}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header()["Sgx-Qe-Identity-Issuer-Chain"] = []string{existingQeInfo.QeIssuerChain}
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(existingQeInfo.QeInfo))
		if err != nil {
			log.WithError(err).Error("Could not write qe info data to response")
		}
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

		if err := validateQueryParams(r.URL.Query(), tcbInfoRetrieveParams); err != nil {
			slog.Errorf("resource/platform_ops: getTcbInfo() %s", err.Error())
			return &resourceError{Message: "invalid query param", StatusCode: http.StatusBadRequest}
		}

		fmspc := r.URL.Query().Get("fmspc")

		if !validateInputString(constants.FmspcKey, fmspc) {
			slog.Errorf("resource/quote_provider_ops: getTcbInfo() Input validation failed for query parameter")
			return &resourceError{Message: "invalid query param", StatusCode: http.StatusBadRequest}
		}

		tcbInfo := &types.FmspcTcbInfo{Fmspc: fmspc}
		existingFmspc, err := db.FmspcTcbInfoRepository().Retrieve(tcbInfo)
		if existingFmspc == nil {
			existingFmspc, err = getLazyCacheFmspcTcbInfo(db, fmspc, constants.CacheInsert)
			if err != nil || existingFmspc == nil {
				return &resourceError{Message: "Error retrieving TCB info", StatusCode: http.StatusNotFound}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header()["SGX-TCB-Info-Issuer-Chain"] = []string{existingFmspc.TcbInfoIssuerChain}
		w.WriteHeader(http.StatusOK)
		_, err = w.Write([]byte(existingFmspc.TcbInfo))
		if err != nil {
			log.WithError(err).Error("Could not write tcbinfo data to response")
		}
		slog.Infof("%s: TCB Info retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}
