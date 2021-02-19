/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

/*
 #cgo LDFLAGS: -lPCKCertSelection
 #include <stdlib.h>
 #include "pck_cert_selection.h"
*/
import "C"

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"intel/isecl/scs/v3/constants"
	"intel/isecl/scs/v3/repository"
	"intel/isecl/scs/v3/types"
)

const (
	Error = iota
	EqualOrGreater
	Lower
	Undefined
)

type Response struct {
	Status  string
	Message string
}

type PlatformInfo struct {
	EncPpid     string `json:"enc_ppid"`
	CPUSvn      string `json:"cpu_svn"`
	PceSvn      string `json:"pce_svn"`
	PceID       string `json:"pce_id"`
	QeID        string `json:"qe_id"`
	Fmspc       string
	Manifest    string `json:"manifest"`
	CreatedTime time.Time
}

type PlatformTcbInfo struct {
	CPUSvn      string `json:"cpusvn"`
	PceSvn      string `json:"pcesvn"`
	PceID       string `json:"pceid"`
	QeID        string `json:"qeid"`
	Tcbm        string
	CreatedTime time.Time
}

type PckCertChainInfo struct {
	PckCertChain string
	CreatedTime  time.Time
}

type PckCRLInfo struct {
	PckCrl          string
	PckCrlCertChain string
	Ca              string
	CreatedTime     time.Time
}

type PckCertInfo struct {
	PceID         string `json:"pceId"`
	QeID          string `json:"qeId"`
	PckCerts      []string
	TotalPckCerts int
	Tcbms         []string
	CertIndex     uint8
	CreatedTime   time.Time
}

type FmspcTcbInfo struct {
	Fmspc              string
	TcbInfo            string
	TcbInfoIssuerChain string
	CreatedTime        time.Time
}

type QEInfo struct {
	QeInfo        string
	QeIssuerChain string
	CreatedTime   time.Time
}

type TcbLevels struct {
	SgxTcbComp01Svn uint8  `json:"sgxtcbcomp01svn"`
	SgxTcbComp02Svn uint8  `json:"sgxtcbcomp02svn"`
	SgxTcbComp03Svn uint8  `json:"sgxtcbcomp03svn"`
	SgxTcbComp04Svn uint8  `json:"sgxtcbcomp04svn"`
	SgxTcbComp05Svn uint8  `json:"sgxtcbcomp05svn"`
	SgxTcbComp06Svn uint8  `json:"sgxtcbcomp06svn"`
	SgxTcbComp07Svn uint8  `json:"sgxtcbcomp07svn"`
	SgxTcbComp08Svn uint8  `json:"sgxtcbcomp08svn"`
	SgxTcbComp09Svn uint8  `json:"sgxtcbcomp09svn"`
	SgxTcbComp10Svn uint8  `json:"sgxtcbcomp10svn"`
	SgxTcbComp11Svn uint8  `json:"sgxtcbcomp11svn"`
	SgxTcbComp12Svn uint8  `json:"sgxtcbcomp12svn"`
	SgxTcbComp13Svn uint8  `json:"sgxtcbcomp13svn"`
	SgxTcbComp14Svn uint8  `json:"sgxtcbcomp14svn"`
	SgxTcbComp15Svn uint8  `json:"sgxtcbcomp15svn"`
	SgxTcbComp16Svn uint8  `json:"sgxtcbcomp16svn"`
	PceSvn          uint16 `json:"pcesvn"`
}

type TcbLevelsType struct {
	Tcb       TcbLevels `json:"tcb"`
	TcbDate   string    `json:"tcbDate"`
	TcbStatus string    `json:"tcbStatus"`
}

type TcbInfoType struct {
	Version                 int             `json:"version"`
	IssueDate               string          `json:"issueDate"`
	NextUpdate              string          `json:"nextUpdate"`
	Fmspc                   string          `json:"fmspc"`
	PceID                   string          `json:"pceId"`
	TcbType                 int             `json:"tcbType"`
	TcbEvaluationDataNumber int             `josn:"tcbEvaluationDataNumber"`
	TcbLevels               []TcbLevelsType `json:"tcbLevels"`
}

type TcbInfoJSON struct {
	TcbInfo   TcbInfoType `josn:"tcbInfo"`
	Signature string      `json:"signature"`
}

type PckCertsInfo struct {
	Tcb  TcbLevels `json:"tcb"`
	Tcbm string    `json:"tcbm"`
	Cert string    `json:"cert"`
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
	Platform     *types.Platform
	PlatformTcb  *types.PlatformTcb
	PckCert      *types.PckCert
	PckCertChain *types.PckCertChain
	PckCrl       *types.PckCrl
	FmspcTcb     *types.FmspcTcbInfo
	QEIdentity   *types.QEIdentity
}

type cpuSvn struct {
	bytes []byte
}

func PlatformInfoOps(r *mux.Router, db repository.SCSDatabase) {
	r.Handle("/platforms", handlers.ContentTypeHandler(pushPlatformInfo(db), "application/json")).Methods("POST")
	r.Handle("/refreshes", handlers.ContentTypeHandler(refreshPlatformInfo(db), "application/json")).Methods("GET")
	r.Handle("/tcbstatus", handlers.ContentTypeHandler(getTcbStatus(db), "application/json")).Methods("GET")
}

// This function invokes SGX DCAP PCK Certificate Selection Library (C++)
// we pass following parameters to the C++ library
// 1. current taw tcb level of the platform (cpusvn and pcesvn value)
// 2. pce id of the platform
// 3. TCBInfo for the platform
// 4. All PCK Certficates for all the TCB levels of the platform
// 5. Number of PCK certificates
// C++ library chooses best suited PCK certificate for the current TCB level
// and returns index to the certificate
func getBestPckCert(in *SgxData) (uint8, error) {
	var err error
	var cpusvn cpuSvn

	cpusvn.bytes, err = hex.DecodeString(in.PlatformInfo.CPUSvn)
	if err != nil {
		log.WithError(err).Error("could not decode cpusvn string")
		return 0, err
	}
	pceSvn, _ := strconv.ParseUint(in.PlatformInfo.PceSvn, 16, 32)
	if err != nil {
		log.WithError(err).Error("could not parse pcesvn string")
		return 0, err
	}
	pceID, _ := strconv.ParseUint(in.PlatformInfo.PceID, 16, 32)
	if err != nil {
		log.WithError(err).Error("could not parse pceid string")
		return 0, err
	}
	totalPckPcerts := in.PckCertInfo.TotalPckCerts

	tcbInfo := C.CString(in.FmspcTcbInfo.TcbInfo)
	if tcbInfo != nil {
		defer C.free(unsafe.Pointer(tcbInfo))
	} else {
		return 0, errors.New("failed to allocate memory for tcbinfo")
	}

	var certIdx C.uint

	certs := make([]*C.char, totalPckPcerts)
	for i := 0; i < totalPckPcerts; i++ {
		certs[i] = C.CString(in.PckCertInfo.PckCerts[i])
		if certs[i] != nil {
			defer C.free(unsafe.Pointer(certs[i]))
		} else {
			return 0, errors.New("failed to allocate memory for pckcert")
		}
	}
	ret := C.pck_cert_select((*C.cpu_svn_t)(unsafe.Pointer(&cpusvn.bytes[0])), C.ushort(pceSvn),
		C.ushort(pceID), (*C.char)(unsafe.Pointer(tcbInfo)),
		(**C.char)(unsafe.Pointer(&certs[0])), C.uint(totalPckPcerts), &certIdx)

	certError := [...]string{
		"PCK Cert Select Lib selected best suited PCK cert",
		"Invalid Arguments provided to PCK Cert Select Lib",
		"Invalid PCK Certificate",
		"PCK certificate CPUSVN doesn't match TCB Components",
		"Invalid PCK Certificate Version",
		"PCK Cert Lib returned Unexpected Error",
		"PCKs PCEID doesn't match other PCKs",
		"PCKs PPID doesn't match other PCKs",
		"PCKs FMSPC doesn't match other PCKs",
		"Invalid TCB Info provided as input to PCK Cert Select Lib",
		"TCB Info PceID does not match input PceID Value",
		"TCBInfo TCB Type is not supported",
		"Raw TCB is lower than all input PCKs",
	}

	if ret != 0 {
		err = errors.New(certError[ret])
	}
	return uint8(certIdx), err
}

func fetchPckCertInfo(in *SgxData) error {
	log.Trace("resource/platform_ops: fetchPckCertInfo() Entering")
	defer log.Trace("resource/platform_ops: fetchPckCertInfo() Leaving")

	// using platform sgx values, fetch the pck certs from intel pcs server
	var resp *http.Response
	var err error
	if in.PlatformInfo.PceID == "" && in.PlatformInfo.Manifest == "" {
		log.Error("invalid request")
		return errors.New("invalid request, enc_ppid or platform_manifest is null")
	}

	if in.PlatformInfo.Manifest != "" {
		resp, err = getPckCertsWithManifestFromProvServer(in.PlatformInfo.Manifest,
			in.PlatformInfo.PceID)
	} else {
		resp, err = getPckCertFromProvServer(in.PlatformInfo.EncPpid,
			in.PlatformInfo.PceID)
	}
	if resp != nil {
		defer func() {
			derr := resp.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing pckcert response body")
			}
		}()
	}

	if err != nil {
		log.WithError(err).Error("Intel PCS Server getPckCerts api failed")
		return err
	}

	if resp.StatusCode != http.StatusOK {
		dump, _ := httputil.DumpResponse(resp, true)
		log.WithField("Status Code", resp.StatusCode).Error(string(dump))
		return errors.New("get pckcerts api call failed with pcs")
	}

	// read the PCKCertChain from HTTP response header
	in.PckCertChainInfo.PckCertChain = resp.Header.Get("Sgx-Pck-Certificate-Issuer-Chain")
	if resp.ContentLength == 0 {
		return errors.New("no content found in getPCkCerts Http Response")
	}

	// read the fmspc value of the platform for which pck certs are being returned
	in.FmspcTcbInfo.Fmspc = resp.Header.Get("Sgx-Fmspc")
	in.PlatformInfo.Fmspc = in.FmspcTcbInfo.Fmspc

	// read the type of SGX intermediate CA that issued requested pck certs(either processor or platform)
	in.PckCRLInfo.Ca = resp.Header.Get("Sgx-Pck-Certificate-Ca-Type")

	// read the set  of PCKCerts blob sent as part of HTTP response body
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("could not read getPckCerts http Response body")
		return err
	}

	// we unmarshal the json response to read set of pck certs and tcbm values
	var pckCerts []PckCertsInfo
	err = json.Unmarshal(body, &pckCerts)
	if err != nil {
		log.WithError(err).Error("Could not decode the pckCerts json response")
		return err
	}

	pckCertList := make([]string, len(pckCerts))
	tcbmList := make([]string, len(pckCerts))

	certCount := 0
	// PCS Service can return "Not available" string instead of a PCK certificate,
	// if PCK certificate is not available for a TCB level.
	// Iterate through the array and filter out TCB levels for which PCK Certs is
	// marked as "Not available". The filtered bunch is then sent to PCK Cert
	// Selection Lib to choose best suited PCK cert for the current TCB level
	for i := 0; i < len(pckCerts); i++ {
		if pckCerts[i].Cert != "Not available" {
			pckCertList[certCount], _ = url.QueryUnescape(pckCerts[i].Cert)
			tcbmList[certCount] = pckCerts[i].Tcbm
			certCount++
		}
	}

	// Now we have the bunch of PCK certificates which can be safely passed
	// to PCK Cert Selection Lib
	in.PckCertInfo.TotalPckCerts = certCount
	in.PckCertInfo.PckCerts = make([]string, certCount)
	in.PckCertInfo.Tcbms = make([]string, certCount)

	for i := 0; i < certCount; i++ {
		in.PckCertInfo.PckCerts[i] = pckCertList[i]
		in.PckCertInfo.Tcbms[i] = tcbmList[i]
	}

	in.PckCertInfo.QeID = in.PlatformInfo.QeID
	in.PckCertInfo.PceID = in.PlatformInfo.PceID

	err = fetchFmspcTcbInfo(in)
	if err != nil {
		return err
	}

	// From bunch of PCK certificates, choose best suited PCK certificate for the
	// current raw TCB level
	in.PckCertInfo.CertIndex, err = getBestPckCert(in)
	if err != nil {
		log.WithError(err).Error("failed to get best suited pckcert for the current tcb level")
		return err
	}
	return nil
}

// Fetches the latest PCK Certificate Revocation List for the sgx intel processor
// SVS will make use of this to verify if PCK certificate in a quote is valid
// by comparing against this CRL
func fetchPckCrlInfo(in *SgxData) error {
	resp, err := getPckCrlFromProvServer(in.PckCRLInfo.Ca, constants.EncodingValue)
	if resp != nil {
		defer func() {
			derr := resp.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing pckcrl response body")
			}
		}()
	}

	if err != nil {
		log.WithError(err).Error("Intel PCS Server getPckCrl api failed")
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("get revocation list api call failed with pcs")
	}

	in.PckCRLInfo.PckCrlCertChain = resp.Header.Get("Sgx-Pck-Crl-Issuer-Chain")

	if resp.ContentLength == 0 {
		return errors.New("no content found in getPCkCrl Http Response")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("could not read getPckCrl http response")
		return err
	}
	in.PckCRLInfo.PckCrl = base64.StdEncoding.EncodeToString(body)
	return nil
}

// for a platform FMSPC value, fetches corresponding TCBInfo structure from Intel PCS server
func fetchFmspcTcbInfo(in *SgxData) error {
	resp, err := getFmspcTcbInfoFromProvServer(in.FmspcTcbInfo.Fmspc)
	if resp != nil {
		defer func() {
			derr := resp.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing tcbinfo response body")
			}
		}()
	}

	if err != nil {
		log.WithError(err).Error("Intel PCS Server getTCBInfo api failed")
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("get tcb info api call failed with pcs")
	}
	in.FmspcTcbInfo.TcbInfoIssuerChain = resp.Header.Get("Sgx-Tcb-Info-Issuer-Chain")

	if resp.ContentLength == 0 {
		return errors.New("no content found in getTCBInfo Http Response")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("could not read getTCBInfo http response")
		return err
	}
	in.FmspcTcbInfo.TcbInfo = string(body)
	return nil
}

// Fetches Quoting Enclave ID details for a platform from intel PCS server
func fetchQeIdentityInfo(in *SgxData) error {
	resp, err := getQeInfoFromProvServer()
	if resp != nil {
		defer func() {
			derr := resp.Body.Close()
			if derr != nil {
				log.WithError(derr).Error("Error closing qeidentity response body")
			}
		}()
	}

	if err != nil {
		log.WithError(err).Error("Intel PCS Server getQEIdentity api failed")
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("get qe identity api call failed with pcs")
	}

	in.QEInfo.QeIssuerChain = resp.Header.Get("Sgx-Enclave-Identity-Issuer-Chain")

	if resp.ContentLength == 0 {
		return errors.New("no content found in getQeIdentity Http Response")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("could not read getQeIdentity http response")
		return err
	}
	in.QEInfo.QeInfo = string(body)
	return nil
}

func cachePckCertInfo(db repository.SCSDatabase, data *SgxData) error {
	var err error
	data.PckCert = &types.PckCert{
		PceID:     data.PckCertInfo.PceID,
		QeID:      data.PckCertInfo.QeID,
		Tcbms:     data.PckCertInfo.Tcbms,
		Fmspc:     data.PlatformInfo.Fmspc,
		CertIndex: data.PckCertInfo.CertIndex,
		PckCerts:  data.PckCertInfo.PckCerts}

	if data.Type == constants.CacheRefresh {
		data.PckCert.UpdatedTime = time.Now().UTC()
		data.PckCert.CreatedTime = data.PckCertInfo.CreatedTime
		err = db.PckCertRepository().Update(data.PckCert)
		if err != nil {
			log.WithError(err).Error("PckCerts record could not be updated in db")
			return err
		}
	} else {
		data.PckCert.CreatedTime = time.Now().UTC()
		data.PckCert.UpdatedTime = time.Now().UTC()
		data.PckCert, err = db.PckCertRepository().Create(data.PckCert)
		if err != nil {
			log.WithError(err).Error("PckCerts record could not be created in db")
			return err
		}
	}
	return nil
}

func cacheQeIdentityInfo(db repository.SCSDatabase, data *SgxData) error {
	data.QEIdentity = &types.QEIdentity{
		QeInfo:        data.QEInfo.QeInfo,
		QeIssuerChain: data.QEInfo.QeIssuerChain}

	var err error
	data.QEIdentity.UpdatedTime = time.Now().UTC()

	if data.Type == constants.CacheRefresh {
		data.QEIdentity.CreatedTime = data.QEInfo.CreatedTime
		err = db.QEIdentityRepository().Update(data.QEIdentity)
		if err != nil {
			log.WithError(err).Error("QE Identity record could not be updated in db")
			return err
		}
	} else {
		data.QEIdentity.CreatedTime = time.Now().UTC()
		data.QEIdentity, err = db.QEIdentityRepository().Create(data.QEIdentity)
		if err != nil {
			log.WithError(err).Error("QE Identity record could not created in db")
			return err
		}
	}
	return nil
}

func cachePckCertChainInfo(db repository.SCSDatabase, data *SgxData) error {
	var err error
	data.PckCertChain = &types.PckCertChain{
		PckCertChain: data.PckCertChainInfo.PckCertChain}

	data.PckCertChain.UpdatedTime = time.Now().UTC()
	if data.Type == constants.CacheRefresh {
		data.PckCertChain.CreatedTime = data.PckCertChainInfo.CreatedTime
		err = db.PckCertChainRepository().Update(data.PckCertChain)
		if err != nil {
			log.WithError(err).Error("PckCertChain record could not be updated in db")
			return err
		}
	} else {
		data.PckCertChain.CreatedTime = time.Now().UTC()
		data.PckCertChain, err = db.PckCertChainRepository().Create(data.PckCertChain)
		if err != nil {
			log.WithError(err).Error("PckCertChain record could not be created in db")
			return err
		}
	}
	return nil
}

func cacheFmspcTcbInfo(db repository.SCSDatabase, data *SgxData) error {
	data.FmspcTcb = &types.FmspcTcbInfo{
		Fmspc:              data.FmspcTcbInfo.Fmspc,
		TcbInfo:            data.FmspcTcbInfo.TcbInfo,
		TcbInfoIssuerChain: data.FmspcTcbInfo.TcbInfoIssuerChain}
	var err error

	data.FmspcTcb.UpdatedTime = time.Now().UTC()
	if data.Type == constants.CacheRefresh {
		data.FmspcTcb.CreatedTime = data.FmspcTcbInfo.CreatedTime
		err = db.FmspcTcbInfoRepository().Update(data.FmspcTcb)
		if err != nil {
			log.WithError(err).Error("FmspcTcb record could not be Updated in db")
			return err
		}
	} else {
		data.FmspcTcb.CreatedTime = time.Now().UTC()
		data.FmspcTcb, err = db.FmspcTcbInfoRepository().Create(data.FmspcTcb)
		if err != nil {
			log.WithError(err).Error("FmspcTcb record could not be created in db")
			return err
		}
	}
	log.WithField("Fmspc", data.FmspcTcb.Fmspc).Debug("Cached inside Db")
	return nil
}

func cachePlatformInfo(db repository.SCSDatabase, data *SgxData) error {
	data.Platform = &types.Platform{
		Encppid:  data.PlatformInfo.EncPpid,
		CPUSvn:   data.PlatformInfo.CPUSvn,
		PceSvn:   data.PlatformInfo.PceSvn,
		PceID:    data.PlatformInfo.PceID,
		QeID:     data.PlatformInfo.QeID,
		Fmspc:    data.PlatformInfo.Fmspc,
		Manifest: data.PlatformInfo.Manifest}

	var err error
	data.Platform.UpdatedTime = time.Now().UTC()
	if data.Type == constants.CacheRefresh {
		data.Platform.CreatedTime = data.PlatformInfo.CreatedTime
		err = db.PlatformRepository().Update(data.Platform)
		if err != nil {
			log.WithError(err).Error("Platform values record could not be updated in db")
			return err
		}
	} else {
		data.Platform.CreatedTime = time.Now().UTC()
		data.Platform, err = db.PlatformRepository().Create(data.Platform)
		if err != nil {
			log.WithError(err).Error("Platform values record could not be created in db")
			return err
		}
	}
	return nil
}

func cachePlatformTcbInfo(db repository.SCSDatabase, data *SgxData) error {
	data.PlatformTcb = &types.PlatformTcb{
		Tcbm:   data.PckCertInfo.Tcbms[data.PckCertInfo.CertIndex],
		CPUSvn: data.PlatformInfo.CPUSvn,
		PceSvn: data.PlatformInfo.PceSvn,
		PceID:  data.PlatformInfo.PceID,
		QeID:   data.PlatformInfo.QeID,
	}

	var err error
	data.PlatformTcb.UpdatedTime = time.Now().UTC()
	if data.Type == constants.CacheRefresh {
		data.PlatformTcb.CreatedTime = data.PlatformTcbInfo.CreatedTime
		err = db.PlatformTcbRepository().Update(data.PlatformTcb)
		if err != nil {
			log.WithError(err).Error("PlatformTcb values record could not be updated in db")
			return err
		}
	} else {
		data.PlatformTcb.CreatedTime = time.Now().UTC()
		data.PlatformTcb, err = db.PlatformTcbRepository().Create(data.PlatformTcb)
		if err != nil {
			log.WithError(err).Error("PlatformTcb values record could not be created in db")
			return err
		}
	}
	return nil
}

func cachePckCrlInfo(db repository.SCSDatabase, data *SgxData) error {
	data.PckCrl = &types.PckCrl{
		Ca:              data.PckCRLInfo.Ca,
		PckCrl:          data.PckCRLInfo.PckCrl,
		PckCrlCertChain: data.PckCRLInfo.PckCrlCertChain}
	var err error
	data.PckCrl.UpdatedTime = time.Now().UTC()
	if data.Type == constants.CacheRefresh {
		data.PckCrl.CreatedTime = data.PckCRLInfo.CreatedTime
		err = db.PckCrlRepository().Update(data.PckCrl)
		if err != nil {
			log.WithError(err).Error("PckCrl record could not be updated in db")
			return err
		}
	} else {
		data.PckCrl.CreatedTime = time.Now().UTC()
		data.PckCrl, err = db.PckCrlRepository().Create(data.PckCrl)
		if err != nil {
			log.WithError(err).Error("PckCrl record could not be created in db")
			return err
		}
	}
	return nil
}

func pushPlatformInfo(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		err := authorizeEndpoint(r, constants.HostDataUpdaterGroupName, true)
		if err != nil {
			return err
		}
		var data SgxData

		if r.ContentLength == 0 {
			slog.Error("resource/platform_ops: pushPlatformInfo() The request body was not provided")
			return &resourceError{Message: "platform data not provided",
				StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&data.PlatformInfo)
		if err != nil {
			slog.WithError(err).Errorf("resource/platform_ops: pushPlatformInfo() %s :  Failed to decode request body", commLogMsg.InvalidInputBadEncoding)
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}
		if !validateInputString(constants.EncPPIDKey, data.PlatformInfo.EncPpid) ||
			!validateInputString(constants.CPUSvnKey, data.PlatformInfo.CPUSvn) ||
			!validateInputString(constants.PceSvnKey, data.PlatformInfo.PceSvn) ||
			!validateInputString(constants.PceIDKey, data.PlatformInfo.PceID) ||
			!validateInputString(constants.QeIDKey, data.PlatformInfo.QeID) {
			slog.Error("resource/platform_ops: pushPlatformInfo() Input validation failed")
			return &resourceError{Message: "invalid query param data",
				StatusCode: http.StatusBadRequest}
		}

		data.Platform = &types.Platform{QeID: data.PlatformInfo.QeID}

		existingPlaformData, err := db.PlatformRepository().Retrieve(data.Platform)
		if existingPlaformData != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			res := Response{Status: "Success", Message: "platform info already cached"}
			js, err := json.Marshal(res)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			_, err = w.Write(js)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			return nil
		}

		data.Type = constants.CacheInsert
		err = fetchPckCertInfo(&data)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		pckCertChain, err := db.PckCertChainRepository().Retrieve()
		if pckCertChain == nil {
			err = cachePckCertChainInfo(db, &data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		data.PckCrl = &types.PckCrl{Ca: data.PckCRLInfo.Ca}
		pckCrl, err := db.PckCrlRepository().Retrieve(data.PckCrl)
		if pckCrl == nil {
			err = fetchPckCrlInfo(&data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			err = cachePckCrlInfo(db, &data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		err = cachePlatformTcbInfo(db, &data)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		err = cachePlatformInfo(db, &data)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		err = cachePckCertInfo(db, &data)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		TcbInfo := &types.FmspcTcbInfo{Fmspc: data.PlatformInfo.Fmspc}
		existingFmspc, err := db.FmspcTcbInfoRepository().Retrieve(TcbInfo)
		if existingFmspc == nil {
			err = fetchFmspcTcbInfo(&data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}

			err = cacheFmspcTcbInfo(db, &data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		qeIdentity, err := db.QEIdentityRepository().Retrieve()
		if qeIdentity == nil {
			err = fetchQeIdentityInfo(&data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			err = cacheQeIdentityInfo(db, &data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)

		res := Response{Status: "Created", Message: "platform data pushed to scs"}
		js, err := json.Marshal(res)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.Infof("%s: platform data pushed by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func refreshPckCerts(db repository.SCSDatabase) error {
	existingPlaformData, err := db.PlatformRepository().RetrieveAll()
	if len(existingPlaformData) == 0 {
		return errors.New("no platform value records are found in db, cannot perform refresh")
	}

	var data SgxData
	data.Type = constants.CacheRefresh

	for n := 0; n < len(existingPlaformData); n++ {
		tmp := existingPlaformData[n]
		data.PlatformInfo.EncPpid = tmp.Encppid
		data.PlatformInfo.CPUSvn = tmp.CPUSvn
		data.PlatformInfo.PceSvn = tmp.PceSvn
		data.PlatformInfo.PceID = tmp.PceID
		data.PlatformInfo.QeID = tmp.QeID
		data.PlatformInfo.CreatedTime = tmp.CreatedTime
		data.PlatformInfo.Manifest = tmp.Manifest

		err = fetchPckCertInfo(&data)
		if err != nil {
			return fmt.Errorf("pck cert refresh failed: %s", string(err.Error()))
		}

		data.PlatformTcbInfo.CreatedTime = tmp.CreatedTime

		err = cachePlatformTcbInfo(db, &data)
		if err != nil {
			return fmt.Errorf("tcbinfo refresh failed: %s", err.Error())
		}

		existingPckCertData := &types.PckCert{QeID: tmp.QeID}
		existingPckCertData, err = db.PckCertRepository().Retrieve(existingPckCertData)
		if existingPckCertData == nil {
			return errors.New("Error in fetching existing pck cert data")
		}

		data.PckCertChainInfo.CreatedTime = existingPckCertData.CreatedTime

		err = cachePckCertChainInfo(db, &data)
		if err != nil {
			return fmt.Errorf("Error in Cache Pck CertChain Info: %s", err.Error())
		}

		data.PckCertInfo.CreatedTime = existingPckCertData.CreatedTime

		err = cachePckCertInfo(db, &data)
		if err != nil {
			return fmt.Errorf("Error in Cache Pck Cert Info: %s", err.Error())
		}
	}
	log.Debug("All PckCerts for the platform refeteched from PCS as part of refresh")
	return nil
}

func refreshAllPckCrl(db repository.SCSDatabase) error {
	existingPckCrlData, err := db.PckCrlRepository().RetrieveAll()
	if len(existingPckCrlData) == 0 {
		return errors.New("no pck crl record found in db, cannot perform refresh operation")
	}

	var data SgxData
	data.Type = constants.CacheRefresh
	for n := 0; n < len(existingPckCrlData); n++ {
		data.PckCRLInfo.Ca = existingPckCrlData[n].Ca
		err = fetchPckCrlInfo(&data)
		if err != nil {
			return fmt.Errorf("refresh of pckcrl failed: %s", err.Error())
		}

		data.PckCRLInfo.CreatedTime = existingPckCrlData[n].CreatedTime
		err = cachePckCrlInfo(db, &data)
		if err != nil {
			return fmt.Errorf("refresh of pckcrl failed: %s", err.Error())
		}
	}
	log.Debug("All PckCrls for the platform refeteched from PCS as part of refresh")
	return nil
}

func refreshAllTcbInfo(db repository.SCSDatabase) error {
	existingTcbInfoData, err := db.FmspcTcbInfoRepository().RetrieveAll()
	if len(existingTcbInfoData) == 0 {
		return errors.New("no tcbinfo record found in db, cannot perform refresh operation")
	}

	log.Debug("Existing Fmspc count:", len(existingTcbInfoData))
	var data SgxData
	data.Type = constants.CacheRefresh
	for n := 0; n < len(existingTcbInfoData); n++ {
		data.FmspcTcbInfo.Fmspc = existingTcbInfoData[n].Fmspc
		err = fetchFmspcTcbInfo(&data)
		if err != nil {
			return fmt.Errorf("Error in Fetch Tcb info: %s", err.Error())
		}

		data.FmspcTcbInfo.CreatedTime = existingTcbInfoData[n].CreatedTime
		err = cacheFmspcTcbInfo(db, &data)
		if err != nil {
			return fmt.Errorf("Error in Cache Fmspc Tcb info: %s", err.Error())
		}
	}
	log.Debug("TCBInfo for the platform refeteched from PCS as part of refresh")
	return nil
}

func refreshAllQE(db repository.SCSDatabase) error {
	existingQEData, err := db.QEIdentityRepository().Retrieve()
	if existingQEData == nil {
		return errors.New("no qe identity record found in db, cannot perform refresh operation")
	}

	var data SgxData
	data.Type = constants.CacheRefresh
	err = fetchQeIdentityInfo(&data)
	if err != nil {
		return fmt.Errorf("Error in Fetch QEIdentity info: %s", err.Error())
	}
	data.QEInfo.CreatedTime = existingQEData.CreatedTime
	err = cacheQeIdentityInfo(db, &data)
	if err != nil {
		return fmt.Errorf("Error in Cache QEIdentity info: %s", err.Error())
	}
	log.Debug("QEIdentity for the platform refeteched from PCS as part of refresh")
	return nil
}

func refreshNonPCKCollaterals(db repository.SCSDatabase) error {
	err := refreshAllPckCrl(db)
	if err != nil {
		log.WithError(err).Error("could not complete refresh of PCK Crl")
		return err
	}

	err = refreshAllTcbInfo(db)
	if err != nil {
		log.WithError(err).Error("could not complete refresh of TcbInfo")
		return err
	}

	err = refreshAllQE(db)
	if err != nil {
		log.WithError(err).Error("could not complete refresh of QE Identity")
		return err
	}
	return nil
}

func RefreshPlatformInfoTimer(db repository.SCSDatabase, rtype string) error {
	var err error
	if strings.Compare(rtype, constants.TypeRefreshCert) == 0 {
		err = refreshPckCerts(db)
		if err != nil {
			log.WithError(err).Error("could not complete refresh of Pck Certificates")
			return err
		}
	} else if strings.Compare(rtype, constants.TypeRefreshTcb) == 0 {
		err = refreshNonPCKCollaterals(db)
		if err != nil {
			log.WithError(err).Error("could not complete refresh of TcbInfo")
			return err
		}
	}
	log.Debug("Refresh Timer Callback: refreshPlatformInfoTimer, completed")
	return nil
}

func refreshPlatformInfo(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		err := authorizeEndpoint(r, constants.CacheManagerGroupName, true)
		if err != nil {
			return err
		}

		w.Header().Set("Content-Type", "application/json")

		err = refreshPckCerts(db)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)

			res := Response{Status: "Failure", Message: "could not find platform info in database"}
			js, err := json.Marshal(res)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
			}
			_, err = w.Write(js)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			return err
		}

		err = refreshNonPCKCollaterals(db)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)

			res := Response{Status: "Failure", Message: "could not find platform info in database"}
			js, err := json.Marshal(res)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
			}
			_, err = w.Write(js)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			return err
		}

		w.WriteHeader(http.StatusOK)

		res := Response{Status: "Success", Message: "sgx collaterals refreshed successfully"}
		js, err := json.Marshal(res)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.Infof("%s: Platform data refreshed by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}

func compareTcbComponents(pckComponents []byte, pckpcesvn uint16, tcbComponents []byte, tcbpcesvn uint16) int {
	leftLower := false
	rightLower := false

	if len(pckComponents) != constants.MaxTcbLevels || len(tcbComponents) != constants.MaxTcbLevels {
		return Error
	}
	if pckpcesvn < tcbpcesvn {
		leftLower = true
	}
	if pckpcesvn > tcbpcesvn {
		rightLower = true
	}

	for i := 0; i < constants.MaxTcbLevels; i++ {
		if pckComponents[i] < tcbComponents[i] {
			leftLower = true
		}
		if pckComponents[i] > tcbComponents[i] {
			rightLower = true
		}
	}
	// this should not happen as either one can be greater
	if leftLower && rightLower {
		return Undefined
	}
	if leftLower {
		return Lower
	}
	return EqualOrGreater
}

func getTcbCompList(tcbLevelList *TcbLevels) []byte {
	tcbCompLevel := make([]byte, constants.MaxTcbLevels)

	tcbCompLevel[0] = tcbLevelList.SgxTcbComp01Svn
	tcbCompLevel[1] = tcbLevelList.SgxTcbComp02Svn
	tcbCompLevel[2] = tcbLevelList.SgxTcbComp03Svn
	tcbCompLevel[3] = tcbLevelList.SgxTcbComp04Svn
	tcbCompLevel[4] = tcbLevelList.SgxTcbComp05Svn
	tcbCompLevel[5] = tcbLevelList.SgxTcbComp06Svn
	tcbCompLevel[6] = tcbLevelList.SgxTcbComp07Svn
	tcbCompLevel[7] = tcbLevelList.SgxTcbComp08Svn
	tcbCompLevel[8] = tcbLevelList.SgxTcbComp09Svn
	tcbCompLevel[9] = tcbLevelList.SgxTcbComp10Svn
	tcbCompLevel[10] = tcbLevelList.SgxTcbComp11Svn
	tcbCompLevel[11] = tcbLevelList.SgxTcbComp12Svn
	tcbCompLevel[12] = tcbLevelList.SgxTcbComp13Svn
	tcbCompLevel[13] = tcbLevelList.SgxTcbComp14Svn
	tcbCompLevel[14] = tcbLevelList.SgxTcbComp15Svn
	tcbCompLevel[15] = tcbLevelList.SgxTcbComp16Svn

	return tcbCompLevel
}

/*
 * To Determine, if a Platform's TCB status is uptodate or not, following mechanism is employed
 * 1. Retrieve FMSPC value from SGX PCK Certificate assigned to a given platform.
 * 2. Retrieve TCB Info matching the FMSPC value
 * 3. Iterate over the sorted collection of TCB Levels retrieved from TCB Info starting from the first item on the list
 * 4. Compare all the SGX TCB Comp SVNs retrieved from the SGX PCK Certificate with the corresponding values in the TCB Level
 *    If all SGX TCB Comp SVNs in the certificate are greater or equal to the corresponding values in TCB Level, go to next step
 *    otherwise move to the next item on TCB Levels list.
 * 5. Compare PCESVN value retrieved from the SGX PCK certificate with the corresponding value in the TCB Level.
 *    If it is greater or equal to the value in TCB Level, read status assigned to this TCB level
 *    Otherwise, move to the next item on TCB Levels list
 * 6. If no TCB level matches SGX PCK Certificate, then TCB Level is not supported
 */
func getTcbStatus(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {
		err := authorizeEndpoint(r, constants.HostDataReaderGroupName, true)
		if err != nil {
			return err
		}

		if len(r.URL.Query()) == 0 {
			return &resourceError{Message: "query data not provided",
				StatusCode: http.StatusBadRequest}
		}
		qeID := r.URL.Query().Get("qeid")
		if !validateInputString(constants.QeIDKey, qeID) {
			slog.Errorf("resource/platform_ops: getTcbStatus() Input validation failed for query parameter")
			return &resourceError{Message: "invalid qeid",
				StatusCode: http.StatusBadRequest}
		}

		pckinfo := &types.PckCert{QeID: qeID}
		existingPckCertData, err := db.PckCertRepository().Retrieve(pckinfo)
		if existingPckCertData == nil {
			return &resourceError{Message: "no pck cert record found: " + err.Error(),
				StatusCode: http.StatusNotFound}
		}

		certIndex := existingPckCertData.CertIndex
		existingPlatformData := &types.Platform{QeID: qeID}
		existingPlatformData, err = db.PlatformRepository().Retrieve(existingPlatformData)
		if existingPlatformData == nil {
			return &resourceError{Message: "no platform record found: " + err.Error(),
				StatusCode: http.StatusNotFound}
		}

		tcbInf := &types.FmspcTcbInfo{Fmspc: existingPlatformData.Fmspc}
		existingFmspc, err := db.FmspcTcbInfoRepository().Retrieve(tcbInf)
		if existingFmspc == nil {
			return &resourceError{Message: "no tcb info record found: " + err.Error(),
				StatusCode: http.StatusNotFound}
		}

		// for the selected pck cert, select corresponding raw tcb level (tcbm)
		tcbm, err := hex.DecodeString(existingPckCertData.Tcbms[certIndex])
		if err != nil {
			return &resourceError{Message: "cannot decode tcbm: " + err.Error(),
				StatusCode: http.StatusInternalServerError}
		}

		// tcbm (current raw tcb level) is 18 byte array with first 16 bytes for cpusvn
		//  and next 2 bytes for pcesvn
		pckComponents := tcbm[:16]
		pckPceSvn := binary.LittleEndian.Uint16(tcbm[16:])

		var tcbInfo TcbInfoJSON

		// unmarshal the json encoded TcbInfo response for a platform
		err = json.Unmarshal([]byte(existingFmspc.TcbInfo), &tcbInfo)
		if err != nil {
			return &resourceError{Message: "cannot unmarshal tcbinfo: " + err.Error(),
				StatusCode: http.StatusInternalServerError}
		}

		var status string
		var response Response
		response.Status = "false"
		response.Message = "TCB Status is not UpToDate"

		var tcbComponents []byte
		// iterate through all TCB Levels present in TCBInfo
		for i := 0; i < len(tcbInfo.TcbInfo.TcbLevels); i++ {
			tcbPceSvn := tcbInfo.TcbInfo.TcbLevels[i].Tcb.PceSvn
			tcbComponents = getTcbCompList(&tcbInfo.TcbInfo.TcbLevels[i].Tcb)
			tcbError := compareTcbComponents(pckComponents, pckPceSvn, tcbComponents, tcbPceSvn)
			if tcbError == EqualOrGreater {
				status = tcbInfo.TcbInfo.TcbLevels[i].TcbStatus
				break
			}
		}

		if status == "UpToDate" || status == "ConfigurationNeeded" {
			response.Status = "true"
			response.Message = "TCB Status is UpToDate"
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)

		res := Response{Status: response.Status, Message: response.Message}
		js, err := json.Marshal(res)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		_, err = w.Write(js)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		slog.Infof("%s: TCB status retrieved by: %s", commLogMsg.AuthorizedAccess, r.RemoteAddr)
		return nil
	}
}
