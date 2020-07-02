/*
 * Copyright (C) 2019 Intel Corporation
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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"intel/isecl/scs/config"
	"intel/isecl/scs/constants"
	"intel/isecl/scs/repository"
	"intel/isecl/scs/types"
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
	EncPpid          string `json:"enc_ppid"`
	CpuSvn           string `json:"cpu_svn"`
	PceSvn           string `json:"pce_svn"`
	PceId            string `json:"pce_id"`
	QeId             string `json:"qe_id"`
	Fmspc            string
	PlatformManifest string `json:"manifest"`
	CreatedTime      time.Time
}

type PlatformTcbInfo struct {
	CpuSvn      string `json:"cpu_svn"`
	PceSvn      string `json:"pce_svn"`
	PceId       string `json:"pce_id"`
	QeId        string `json:"qe_id"`
	Tcbm        string
	CreatedTime time.Time
}

type PckCertChainInfo struct {
	Id           uint
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
	PceId          string `json:"pce_id"`
	QeId           string `json:"qe_id"`
	PckCerts       []string
	TotalPckCerts  int
	Tcbms          []string
	CertIndex      uint
	PckCertChainId uint
	CreatedTime    time.Time
}

type FmspcTcbInfo struct {
	Fmspc              string
	TcbInfo            string
	TcbInfoIssuerChain string
	CreatedTime        time.Time
}

type QEInfo struct {
	ID            uint
	QeInfo        string
	QeIssuerChain string
	CreatedTime   time.Time
}

type TcbLevels struct {
	SgxTcbComp01Svn uint   `json:"sgxtcbcomp01svn"`
	SgxTcbComp02Svn uint   `json:"sgxtcbcomp02svn"`
	SgxTcbComp03Svn uint   `json:"sgxtcbcomp03svn"`
	SgxTcbComp04Svn uint   `json:"sgxtcbcomp04svn"`
	SgxTcbComp05Svn uint   `json:"sgxtcbcomp05svn"`
	SgxTcbComp06Svn uint   `json:"sgxtcbcomp06svn"`
	SgxTcbComp07Svn uint   `json:"sgxtcbcomp07svn"`
	SgxTcbComp08Svn uint   `json:"sgxtcbcomp08svn"`
	SgxTcbComp09Svn uint   `json:"sgxtcbcomp09svn"`
	SgxTcbComp10Svn uint   `json:"sgxtcbcomp10svn"`
	SgxTcbComp11Svn uint   `json:"sgxtcbcomp11svn"`
	SgxTcbComp12Svn uint   `json:"sgxtcbcomp12svn"`
	SgxTcbComp13Svn uint   `json:"sgxtcbcomp13svn"`
	SgxTcbComp14Svn uint   `json:"sgxtcbcomp14svn"`
	SgxTcbComp15Svn uint   `json:"sgxtcbcomp15svn"`
	SgxTcbComp16Svn uint   `json:"sgxtcbcomp16svn"`
	PceSvn          uint16 `json: "pcesvn"`
}

type TcbLevelsType struct {
	Tcb       TcbLevels `json: "tcb"`
	TcbDate   string    `json: "tcbDate"`
	TcbStatus string    `json: "tcbStatus"`
}

type TcbInfoType struct {
	Version                 int             `json:"version"`
	IssueDate               string          `json:"issueDate"`
	NextUpdate              string          `json:"nextUpdate"`
	Fmspc                   string          `json:"fmspc"`
	PceId                   string          `json:"pceId"`
	TcbType                 int             `json:"tcbType"`
	TcbEvaluationDataNumber int             `josn:"tcbEvaluationDataNumber"`
	TcbLevels               []TcbLevelsType `json:"tcbLevels"`
}

type TcbInfoJson struct {
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

type cpu_svn struct {
	bytes []byte
}

func PlatformInfoOps(r *mux.Router, db repository.SCSDatabase) {
	r.Handle("/push", handlers.ContentTypeHandler(pushPlatformInfo(db), "application/json")).Methods("POST")
	r.Handle("/refresh", handlers.ContentTypeHandler(refreshPlatformInfo(db), "application/json")).Methods("GET")
	r.Handle("/tcbstatus", handlers.ContentTypeHandler(getTcbStatus(db), "application/json")).Methods("GET")
}

func mapPckCertSelectErrorToSCSError(pckErr uint) string {
	var errorStr string

	switch pckErr {
	case 0:
		errorStr = "PCK Cert Select Lib selected best suited PCK cert"
	case 1:
		errorStr = "Invalid Arguments provided to PCK Cert Select Lib"
	case 2:
		errorStr = "Invalid PCK Certificate"
	case 3:
		errorStr = "PCK certificate CPUSVN doesn't match TCB Components"
	case 4:
		errorStr = "Invalid PCK Certificate Version"
	case 5:
		errorStr = "PCK Cert Lib returned Unexpected Error"
	case 6:
		errorStr = "PCKs PCEID doesn't match other PCKs"
	case 7:
		errorStr = "PCKs PPID doesn't match other PCKs"
	case 8:
		errorStr = "PCKs FMSPC doesn't match other PCKs"
	case 9:
		errorStr = "Invalid TCB Info provided as input to PCK Cert Select Lib"
	case 10:
		errorStr = "TCB Info PceID does not match input PceID Value"
	case 11:
		errorStr = "TCBInfo TCB Type is not supported"
	case 12:
		errorStr = "Raw TCB is lower than all input PCKs"
	}
	return errorStr
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

func getBestPckCert(in *SgxData) (uint, error) {
	var err error
	var cpusvn cpu_svn

	cpusvn.bytes, _ = hex.DecodeString(in.PlatformInfo.CpuSvn)
	pce_svn, _ := strconv.ParseUint(in.PlatformInfo.PceSvn, 16, 32)
	pce_id, _ := strconv.ParseUint(in.PlatformInfo.PceId, 16, 32)
	TotalPckPcerts := in.PckCertInfo.TotalPckCerts

	tcbInfo := C.CString(in.FmspcTcbInfo.TcbInfo)
	defer C.free(unsafe.Pointer(tcbInfo))

	var certIdx C.uint

	certs := make([]*C.char, TotalPckPcerts)
	for i, s := range in.PckCertInfo.PckCerts {
		certs[i] = C.CString(s)
		defer C.free(unsafe.Pointer(certs[i]))
	}
	ret := C.pck_cert_select((*C.cpu_svn_t)(unsafe.Pointer(&cpusvn.bytes[0])), C.ushort(pce_svn),
		C.ushort(pce_id), (*C.char)(unsafe.Pointer(tcbInfo)),
		(**C.char)(unsafe.Pointer(&certs[0])), C.uint(TotalPckPcerts), &certIdx)
	errorStr := mapPckCertSelectErrorToSCSError(uint(ret))

	if ret != 0 {
		err = errors.New(errorStr)
	}
	return uint(certIdx), err
}

// parse the PCK certificate and parse Intel custom extensions to extract the fmpsc value
func getFmspcVal(CertBuf *pem.Block) (string, error) {
	var fmspcHex string
	cert, err := x509.ParseCertificate(CertBuf.Bytes)
	if err != nil {
		return fmspcHex, err
	}

	SgxExtensionsOid := asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1}
	FmspcSgxExtensionsOid := asn1.ObjectIdentifier{1, 2, 840, 113741, 1, 13, 1, 4}
	var ext pkix.Extension

	for i := 0; i < len(cert.Extensions); i++ {
		ext = cert.Extensions[i]
		if SgxExtensionsOid.Equal(ext.Id) == true {
			var asn1Extensions []asn1.RawValue
			_, err := asn1.Unmarshal(ext.Value, &asn1Extensions)
			if err != nil {
				log.Debug("Could not parse extension")
				return fmspcHex, err
			}

			var fmspcExt pkix.Extension
			for j := 0; j < len(asn1Extensions); j++ {
				_, err = asn1.Unmarshal(asn1Extensions[j].FullBytes, &fmspcExt)
				if err != nil {
					log.Debug("Could not parse sub extension")
				}
				if FmspcSgxExtensionsOid.Equal(fmspcExt.Id) == true {
					fmspcHex = hex.EncodeToString(fmspcExt.Value)
					log.WithField("FMSPC hex value", fmspcHex).Debug("Fmspc Value extracted from PCK cert")
					return fmspcHex, nil
				}
			}
		}
	}
	return fmspcHex, errors.New("Fmspc value not found in PCK Certificate")
}

func fetchPckCertInfo(in *SgxData) error {
	log.Trace("resource/platform_ops: fetchPckCertInfo() Entering")
	defer log.Trace("resource/platform_ops: fetchPckCertInfo() Leaving")

	// Using the Platform SGX Values, fetch the PCK Certs from Intel PCS Server
	var resp *http.Response
	var err error
	if in.PlatformInfo.PceId == "" && in.PlatformInfo.PlatformManifest == "" {
		log.Error("invalid request")
		return errors.New("invalid request, enc_ppid or platform_manifest is null")
	}

	if in.PlatformInfo.PlatformManifest != "" && getPcsVersion() >= 3 {
		resp, err = getPckCertsWithManifestFromProvServer(in.PlatformInfo.PlatformManifest,
			in.PlatformInfo.PceId)
	} else {
		resp, err = getPckCertFromProvServer(in.PlatformInfo.EncPpid,
			in.PlatformInfo.PceId)
	}

	if err != nil {
		log.WithError(err).Error("Intel PCS Server getPckCerts api failed")
		return err
	}

	if resp.StatusCode != http.StatusOK {
		dump, _ := httputil.DumpResponse(resp, true)
		log.WithField("Status Code", resp.StatusCode).Error(string(dump))
		return errors.New("could not fetch pck certs from Intel PCS Server")
	}

	headers := resp.Header
	// read the PCKCertChain from HTTP response header
	in.PckCertChainInfo.PckCertChain = headers["Sgx-Pck-Certificate-Issuer-Chain"][0]
	if resp.ContentLength == 0 {
		return errors.New("no content found in getPCkCerts Http Response")
	}

	defer resp.Body.Close()
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

	in.PckCertInfo.TotalPckCerts = len(pckCerts)
	in.PckCertInfo.PckCerts = make([]string, in.PckCertInfo.TotalPckCerts)
	in.PckCertInfo.Tcbms = make([]string, in.PckCertInfo.TotalPckCerts)
	// read individual pck certs and corresponding tcbm value
	for i := 0; i < in.PckCertInfo.TotalPckCerts; i++ {
		in.PckCertInfo.PckCerts[i], _ = url.QueryUnescape(pckCerts[i].Cert)
		in.PckCertInfo.Tcbms[i] = pckCerts[i].Tcbm
	}

	in.PckCertInfo.QeId = in.PlatformInfo.QeId
	in.PckCertInfo.PceId = in.PlatformInfo.PceId
	// From bunch of PCK certs received, choose random PCK Cert
	CertBuf, _ := pem.Decode([]byte(in.PckCertInfo.PckCerts[0]))

	if CertBuf == nil {
		return errors.New("Failed to parse PEM block ")
	}

	// extract fmpsc value from randomly chosen PCK certificate
	in.FmspcTcbInfo.Fmspc, err = getFmspcVal(CertBuf)
	if err != nil {
		log.WithError(err).Error("failed to get fmspc value from pck cert")
		return err
	}
	in.PlatformInfo.Fmspc = in.FmspcTcbInfo.Fmspc
	// using the extacted fmspc value, get the TCBInfo structure fo platform
	err = fetchFmspcTcbInfo(in)
	if err != nil {
		return err
	}

	// From bunch of PCK certificates, choose best suited PCK certificate for the
	// current raw TCB level
	in.PckCertInfo.CertIndex, err = getBestPckCert(in)
	if err != nil {
		log.WithError(err).Error("failed to get pck cert for the current tcb level")
		return err
	}
	return nil
}

// Fetches the latest PCK Certificate Revocation List for the sgx intel processor
// SVS will make use of this to verify if PCK certificate in a quote is valid
// by comparing against this CRL
func fetchPckCrlInfo(in *SgxData) error {
	resp, err := getPckCrlFromProvServer(in.PckCRLInfo.Ca)
	if err != nil {
		log.WithError(err).Error("Intel PCS Server getPckCrl api failed")
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("invalid response received from intel SGX provisioning server")
	}

	headers := resp.Header
	in.PckCRLInfo.PckCrlCertChain = headers["Sgx-Pck-Crl-Issuer-Chain"][0]
	log.WithField("PckCrlCertChain", in.PckCRLInfo.PckCrlCertChain).Debug("Values")

	if resp.ContentLength == 0 {
		return errors.New("No content found in getPCkCrl Http Response")
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("could not read getPckCrl http response")
		return err
	}
	in.PckCRLInfo.PckCrl = string(body)
	CrlBuf, _ := pem.Decode(body)
	if CrlBuf == nil {
		return errors.New("Failed to parse Crl PEM block")
	}
	log.WithField("PckCrl", in.PckCRLInfo.PckCrl).Debug("Values")
	return nil
}

// for a platform FMSPC value, fetches corresponding TCBInfo structure from Intel PCS server
func fetchFmspcTcbInfo(in *SgxData) error {
	resp, err := getFmspcTcbInfoFromProvServer(in.FmspcTcbInfo.Fmspc)
	if err != nil {
		log.WithError(err).Error("Intel PCS Server getTCBInfo api failed")
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("Invalid response from Intel SGX Provisioning Server")
	}
	headers := resp.Header
	in.FmspcTcbInfo.TcbInfoIssuerChain = headers["Sgx-Tcb-Info-Issuer-Chain"][0]
	log.WithField("TcbInfoIssuerChain", in.FmspcTcbInfo.TcbInfoIssuerChain).Debug("Values")

	if resp.ContentLength == 0 {
		return errors.New("No content found in getTCBInfo Http Response")
	}

	defer resp.Body.Close()
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
	if err != nil {
		log.WithError(err).Error("Intel PCS Server getQEIdentity api failed")
		return err
	}

	if resp.StatusCode != http.StatusOK {
		log.WithField("Status Code", resp.StatusCode).Error(httputil.DumpResponse(resp, true))
		return errors.New("Invalid response from Intel SGX Provisioning Server")
	}

	headers := resp.Header
	in.QEInfo.QeIssuerChain = headers["Sgx-Enclave-Identity-Issuer-Chain"][0]
	log.WithField("QEIssuerChain", in.QEInfo.QeIssuerChain).Debug("Values")

	if resp.ContentLength == 0 {
		return errors.New("No content found in getQeIdentity Http Response")
	}

	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.WithError(err).Error("could not read getQeIdentity http response")
		return err
	}
	in.QEInfo.QeInfo = string(body)
	log.WithField("QEInfo", string(body)).Debug("Values")
	return nil
}

func cachePckCertInfo(db repository.SCSDatabase, data *SgxData) error {
	var err error
	data.PckCert = &types.PckCert{
		PceId:          data.PckCertInfo.PceId,
		QeId:           data.PckCertInfo.QeId,
		Tcbms:          data.PckCertInfo.Tcbms,
		Fmspc:          data.PlatformInfo.Fmspc,
		CertIndex:      data.PckCertInfo.CertIndex,
		PckCerts:       data.PckCertInfo.PckCerts,
		PckCertChainId: data.PckCertChain.ID}

	if data.Type == constants.CacheRefresh {
		data.PckCert.UpdatedTime = time.Now()
		data.PckCert.CreatedTime = data.PckCertInfo.CreatedTime
		err = db.PckCertRepository().Update(*data.PckCert)
		if err != nil {
			log.WithError(err).Error("PckCerts record could not be updated in db")
			return err
		}
	} else {
		data.PckCert.CreatedTime = time.Now()
		data.PckCert.UpdatedTime = time.Now()
		data.PckCert, err = db.PckCertRepository().Create(*data.PckCert)
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
		QeIssuerChain: data.QEInfo.QeIssuerChain,
		CreatedTime:   time.Now(),
		UpdatedTime:   time.Now()}
	var err error
	if data.Type == constants.CacheRefresh {
		data.QEIdentity.UpdatedTime = time.Now()
		data.QEIdentity.CreatedTime = data.QEInfo.CreatedTime
		data.QEIdentity.ID = data.QEInfo.ID
		err = db.QEIdentityRepository().Update(*data.QEIdentity)
		if err != nil {
			log.WithError(err).Error("QE Identity record could not be updated in db")
			return err
		}
	} else {
		data.QEIdentity.UpdatedTime = time.Now()
		data.QEIdentity.CreatedTime = time.Now()
		data.QEIdentity, err = db.QEIdentityRepository().Create(*data.QEIdentity)
		if err != nil {
			log.WithError(err).Error("QE Identity record could not created in db")
			return err
		}
	}
	log.WithField("QE Identity Id", data.QEIdentity.ID).Debug("Db value")
	return nil
}

func cachePckCertChainInfo(db repository.SCSDatabase, data *SgxData) error {
	var err error
	data.PckCertChain = &types.PckCertChain{
		PckCertChain: data.PckCertChainInfo.PckCertChain}

	if data.Type == constants.CacheRefresh {
		data.PckCertChain.ID = data.PckCertChainInfo.Id
		data.PckCertChain.CreatedTime = data.PckCertChainInfo.CreatedTime
		data.PckCertChain.UpdatedTime = time.Now()
		err = db.PckCertChainRepository().Update(*data.PckCertChain)
		if err != nil {
			log.WithError(err).Error("PckCertChain record could not be updated in db")
			return err
		}
	} else {
		data.PckCertChain.UpdatedTime = time.Now()
		data.PckCertChain.CreatedTime = time.Now()
		data.PckCertChain, err = db.PckCertChainRepository().Create(*data.PckCertChain)
		if err != nil {
			log.WithError(err).Error("PckCertChain record could not be created in db")
			return err
		}
	}
	log.WithField("PCK Cert Chain ID", data.PckCertChain.ID).Debug("Db value")
	return nil
}

func cacheFmspcTcbInfo(db repository.SCSDatabase, data *SgxData) error {
	data.FmspcTcb = &types.FmspcTcbInfo{
		Fmspc:              data.FmspcTcbInfo.Fmspc,
		TcbInfo:            data.FmspcTcbInfo.TcbInfo,
		TcbInfoIssuerChain: data.FmspcTcbInfo.TcbInfoIssuerChain}
	var err error

	if data.Type == constants.CacheRefresh {
		data.FmspcTcb.CreatedTime = data.FmspcTcbInfo.CreatedTime
		data.FmspcTcb.UpdatedTime = time.Now()
		err = db.FmspcTcbInfoRepository().Update(*data.FmspcTcb)
		if err != nil {
			log.WithError(err).Error("FmspcTcb record could not be Updated in db")
			return err
		}
	} else {
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

func cachePlatformInfo(db repository.SCSDatabase, data *SgxData) error {
	data.Platform = &types.Platform{
		Encppid:          data.PlatformInfo.EncPpid,
		CpuSvn:           data.PlatformInfo.CpuSvn,
		PceSvn:           data.PlatformInfo.PceSvn,
		PceId:            data.PlatformInfo.PceId,
		QeId:             data.PlatformInfo.QeId,
		Fmspc:            data.PlatformInfo.Fmspc,
		PlatformManifest: data.PlatformInfo.PlatformManifest}

	var err error
	if data.Type == constants.CacheRefresh {
		data.Platform.CreatedTime = data.PlatformInfo.CreatedTime
		data.Platform.UpdatedTime = time.Now()
		err = db.PlatformRepository().Update(*data.Platform)
		if err != nil {
			log.WithError(err).Error("Platform values record could not be updated in db")
			return err
		}
	} else {
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

func cachePlatformTcbInfo(db repository.SCSDatabase, data *SgxData) error {
	data.PlatformTcb = &types.PlatformTcb{
		Tcbm:   data.PckCertInfo.Tcbms[data.PckCertInfo.CertIndex],
		CpuSvn: data.PlatformInfo.CpuSvn,
		PceSvn: data.PlatformInfo.PceSvn,
		PceId:  data.PlatformInfo.PceId,
		QeId:   data.PlatformInfo.QeId,
	}

	var err error
	if data.Type == constants.CacheRefresh {
		data.PlatformTcb.CreatedTime = data.PlatformTcbInfo.CreatedTime
		data.PlatformTcb.UpdatedTime = time.Now()
		err = db.PlatformTcbRepository().Update(*data.PlatformTcb)
		if err != nil {
			log.WithError(err).Error("PlatformTcb values record could not be updated in db")
			return err
		}
	} else {
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

func cachePckCrlInfo(db repository.SCSDatabase, data *SgxData) error {
	data.PckCrl = &types.PckCrl{
		Ca:              data.PckCRLInfo.Ca,
		PckCrl:          data.PckCRLInfo.PckCrl,
		PckCrlCertChain: data.PckCRLInfo.PckCrlCertChain}
	var err error
	if data.Type == constants.CacheRefresh {
		data.PckCrl.CreatedTime = data.PckCRLInfo.CreatedTime
		data.PckCrl.UpdatedTime = time.Now()
		err = db.PckCrlRepository().Update(*data.PckCrl)
		if err != nil {
			log.WithError(err).Error("PckCrl record could not be updated in db")
			return err
		}
	} else {
		data.PckCrl.CreatedTime = time.Now()
		data.PckCrl.UpdatedTime = time.Now()
		data.PckCrl, err = db.PckCrlRepository().Create(*data.PckCrl)
		if err != nil {
			log.WithError(err).Error("PckCrl record could not be created in db")
			return err
		}
	}
	return nil
}

func pushPlatformInfo(db repository.SCSDatabase) errorHandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) error {

		err := AuthorizeEndpoint(r, constants.HostDataUpdaterGroupName, true)
		if err != nil {
			return err
		}

		var data SgxData
		var platform PlatformInfo
		if r.ContentLength == 0 {
			return &resourceError{Message: "platform data not provided",
				StatusCode: http.StatusBadRequest}
		}

		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		err = dec.Decode(&platform)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusBadRequest}
		}

		data.PlatformInfo.EncPpid = platform.EncPpid
		data.PlatformInfo.CpuSvn = platform.CpuSvn
		data.PlatformInfo.PceSvn = platform.PceSvn
		data.PlatformInfo.PceId = platform.PceId
		data.PlatformInfo.QeId = platform.QeId
		data.PlatformInfo.PlatformManifest = platform.PlatformManifest

		if !validateInputString(constants.EncPPID_Key, data.PlatformInfo.EncPpid) ||
			!validateInputString(constants.CpuSvn_Key, data.PlatformInfo.CpuSvn) ||
			!validateInputString(constants.PceSvn_Key, data.PlatformInfo.PceSvn) ||
			!validateInputString(constants.PceId_Key, data.PlatformInfo.PceId) ||
			!validateInputString(constants.QeId_Key, data.PlatformInfo.QeId) {
			return &resourceError{Message: "invalid query param Data",
				StatusCode: http.StatusBadRequest}
		}

		data.Platform = &types.Platform{
			CpuSvn:           data.PlatformInfo.CpuSvn,
			PceSvn:           data.PlatformInfo.PceSvn,
			PceId:            data.PlatformInfo.PceId,
			QeId:             data.PlatformInfo.QeId,
			PlatformManifest: data.PlatformInfo.PlatformManifest}

		existingPlaformData, err := db.PlatformRepository().Retrieve(*data.Platform)
		if existingPlaformData != nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			res := Response{Status: "Success", Message: "platform info already cached"}
			js, err := json.Marshal(res)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
			w.Write(js)
			return nil
		}

		data.Type = constants.CacheInsert
		err = fetchPckCertInfo(&data)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		err = cachePlatformTcbInfo(db, &data)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		err = cachePlatformInfo(db, &data)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		err = cachePckCertChainInfo(db, &data)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		err = cachePckCertInfo(db, &data)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}

		pckCrl := types.PckCrl{Ca: constants.Ca_Processor}
		existingPckCrl, err := db.PckCrlRepository().Retrieve(pckCrl)
		if existingPckCrl == nil {
			data.PckCRLInfo.Ca = constants.Ca_Processor
			err = fetchPckCrlInfo(&data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}

			err = cachePckCrlInfo(db, &data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		}

		TcbInfo := types.FmspcTcbInfo{Fmspc: data.PlatformInfo.Fmspc}
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

		existingQEData, err := db.QEIdentityRepository().RetrieveAll()
		if existingPlaformData != nil {
			return &resourceError{Message: "platform info already cached", StatusCode: http.StatusBadRequest}
		}

		if len(existingQEData) == 0 {
			err = fetchQeIdentityInfo(&data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}

			err = cacheQeIdentityInfo(db, &data)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
			}
		} else {
			log.WithField("qe data count", len(existingQEData)).Debug("qe identity already cached")
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)

		res := Response{Status: "Created", Message: "platform data pushed to scs"}
		js, err := json.Marshal(res)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		w.Write(js)
		return nil
	}
}

func refreshPckCerts(db repository.SCSDatabase) error {
	existingPlaformData, err := db.PlatformRepository().RetrieveAllPlatformInfo()
	if len(existingPlaformData) == 0 {
		return errors.New("no platform value records are found in db, cannot perform refresh")
	}

	var data SgxData
	data.Type = constants.CacheRefresh

	for n := 0; n < len(existingPlaformData); n++ {
		tmp := existingPlaformData[n]
		data.PlatformInfo.EncPpid = tmp.Encppid
		data.PlatformInfo.CpuSvn = tmp.CpuSvn
		data.PlatformInfo.PceSvn = tmp.PceSvn
		data.PlatformInfo.PceId = tmp.PceId
		data.PlatformInfo.QeId = tmp.QeId
		data.PlatformInfo.CreatedTime = tmp.CreatedTime
		data.PlatformInfo.PlatformManifest = tmp.PlatformManifest

		err = fetchPckCertInfo(&data)
		if err != nil {
			return errors.New(fmt.Sprintf("pck cert refresh failed: %s", string(err.Error())))
		}

		data.PlatformTcbInfo.CreatedTime = tmp.CreatedTime

		err = cachePlatformTcbInfo(db, &data)
		if err != nil {
			return errors.New(fmt.Sprintf("tcbinfo refresh failed: %s", err.Error()))
		}

		existingPckCertData := &types.PckCert{
			PceId: tmp.PceId,
			QeId:  tmp.QeId}
		existingPckCertData, err = db.PckCertRepository().Retrieve(*existingPckCertData)
		if existingPckCertData == nil {
			return errors.New("Error in fetching existing pck cert data")
		}

		data.PckCertChainInfo.Id = existingPckCertData.PckCertChainId
		data.PckCertChainInfo.CreatedTime = existingPckCertData.CreatedTime

		err = cachePckCertChainInfo(db, &data)
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Cache Pck CertChain Info: %s", err.Error()))
		}

		data.PckCertInfo.CreatedTime = existingPckCertData.CreatedTime

		err = cachePckCertInfo(db, &data)
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Cache Pck Cert Info: %s", err.Error()))
		}
	}
	log.Debug("All PckCerts for the platform refeteched from PCS as part of refresh")
	return nil
}

func refreshAllPckCrl(db repository.SCSDatabase) error {
	existingPckCrlData, err := db.PckCrlRepository().RetrieveAllPckCrls()
	if len(existingPckCrlData) == 0 {
		return errors.New("no pck crl record found in db, cannot perform refresh operation")
	}

	var data SgxData
	data.Type = constants.CacheRefresh
	for n := 0; n < len(existingPckCrlData); n++ {
		data.PckCRLInfo.Ca = existingPckCrlData[n].Ca
		err = fetchPckCrlInfo(&data)
		if err != nil {
			return errors.New(fmt.Sprintf("refresh of pckcrl failed: %s", err.Error()))
		}

		data.PckCRLInfo.CreatedTime = existingPckCrlData[n].CreatedTime
		err = cachePckCrlInfo(db, &data)
		if err != nil {
			return errors.New(fmt.Sprintf("refresh of pckcrl failed: %s", err.Error()))
		}
	}
	log.Debug("All PckCrls for the platform refeteched from PCS as part of refresh")
	return nil
}

func refreshAllTcbInfo(db repository.SCSDatabase) error {
	existingTcbInfoData, err := db.FmspcTcbInfoRepository().RetrieveAllFmspcTcbInfos()
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
			return errors.New(fmt.Sprintf("Error in Fetch Tcb info: %s", err.Error()))
		}

		data.FmspcTcbInfo.CreatedTime = existingTcbInfoData[n].CreatedTime
		err = cacheFmspcTcbInfo(db, &data)
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Cache Fmspc Tcb info: %s", err.Error()))
		}
	}
	log.Debug("TCBInfo for the platform refeteched from PCS as part of refresh")
	return nil
}

func refreshAllQE(db repository.SCSDatabase) error {
	existingQEData, err := db.QEIdentityRepository().RetrieveAll()
	if len(existingQEData) == 0 {
		return errors.New("no qe identity record found in db, cannot perform refresh operation")
	}

	log.Debug("Existing QEIdentity count:", len(existingQEData))
	var data SgxData
	data.Type = constants.CacheRefresh
	for n := 0; n < len(existingQEData); n++ {
		err = fetchQeIdentityInfo(&data)
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Fetch QEIdentity info: %s", err.Error()))
		}
		data.QEInfo.CreatedTime = existingQEData[n].CreatedTime
		data.QEInfo.ID = existingQEData[n].ID
		err = cacheQeIdentityInfo(db, &data)
		if err != nil {
			return errors.New(fmt.Sprintf("Error in Cache QEIdentity info: %s", err.Error()))
		}
	}
	log.Debug("QEIdentity for the platform refeteched from PCS as part of refresh")
	return nil
}

func refreshTcbInfos(db repository.SCSDatabase) error {
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
	if strings.Compare(rtype, constants.Type_Refresh_Cert) == 0 {
		err = refreshPckCerts(db)
		if err != nil {
			log.WithError(err).Error("could not complete refresh of Pck Certificates")
			return err
		}
	} else if strings.Compare(rtype, constants.Type_Refresh_Tcb) == 0 {
		err = refreshTcbInfos(db)
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

		err := AuthorizeEndpoint(r, constants.CacheManagerGroupName, true)
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
			w.Write(js)
			return err
		}

		err = refreshTcbInfos(db)
		if err != nil {
			w.WriteHeader(http.StatusNotFound)

			res := Response{Status: "Failure", Message: "could not find platform info in database"}
			js, err := json.Marshal(res)
			if err != nil {
				return &resourceError{Message: err.Error(), StatusCode: http.StatusNotFound}
			}
			w.Write(js)
			return err
		}

		w.WriteHeader(http.StatusOK)

		res := Response{Status: "Success", Message: "sgx collaterals refreshed successfully"}
		js, err := json.Marshal(res)
		if err != nil {
			return &resourceError{Message: err.Error(), StatusCode: http.StatusInternalServerError}
		}
		w.Write(js)

		return nil
	}
}

func compareTcbComponents(pckComponents []byte, pckpcesvn uint16, tcbComponents []byte, tcbpcesvn uint16) int {
	left_lower := false
	right_lower := false

	if len(pckComponents) != constants.MaxTcbLevels || len(tcbComponents) != constants.MaxTcbLevels {
		return Error
	}
	if pckpcesvn < tcbpcesvn {
		left_lower = true
	}
	if pckpcesvn > tcbpcesvn {
		right_lower = true
	}

	for i := 0; i < constants.MaxTcbLevels; i++ {
		if pckComponents[i] < tcbComponents[i] {
			left_lower = true
		}
		if pckComponents[i] > tcbComponents[i] {
			right_lower = true
		}
	}
	// this should not happen as either one can be greater
	if left_lower && right_lower {
		return Undefined
	}
	if left_lower {
		return Lower
	}
	return EqualOrGreater
}

func getTcbCompList(TcbLevelList *TcbLevels) []byte {
	TcbCompLevel := make([]byte, constants.MaxTcbLevels)

	TcbCompLevel[0] = byte(TcbLevelList.SgxTcbComp01Svn)
	TcbCompLevel[1] = byte(TcbLevelList.SgxTcbComp02Svn)
	TcbCompLevel[2] = byte(TcbLevelList.SgxTcbComp03Svn)
	TcbCompLevel[3] = byte(TcbLevelList.SgxTcbComp04Svn)
	TcbCompLevel[4] = byte(TcbLevelList.SgxTcbComp05Svn)
	TcbCompLevel[5] = byte(TcbLevelList.SgxTcbComp06Svn)
	TcbCompLevel[6] = byte(TcbLevelList.SgxTcbComp07Svn)
	TcbCompLevel[7] = byte(TcbLevelList.SgxTcbComp08Svn)
	TcbCompLevel[8] = byte(TcbLevelList.SgxTcbComp09Svn)
	TcbCompLevel[9] = byte(TcbLevelList.SgxTcbComp10Svn)
	TcbCompLevel[10] = byte(TcbLevelList.SgxTcbComp11Svn)
	TcbCompLevel[11] = byte(TcbLevelList.SgxTcbComp12Svn)
	TcbCompLevel[12] = byte(TcbLevelList.SgxTcbComp13Svn)
	TcbCompLevel[13] = byte(TcbLevelList.SgxTcbComp14Svn)
	TcbCompLevel[14] = byte(TcbLevelList.SgxTcbComp15Svn)
	TcbCompLevel[15] = byte(TcbLevelList.SgxTcbComp16Svn)

	return TcbCompLevel
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

		err := AuthorizeEndpoint(r, constants.HostDataReaderGroupName, true)
		if err != nil {
			return err
		}

		if len(r.URL.Query()) == 0 {
			return &resourceError{Message: "query data not provided",
				StatusCode: http.StatusBadRequest}
		}
		QeId := r.URL.Query().Get("qeid")
		if !validateInputString(constants.QeId_Key, QeId) {
			return &resourceError{Message: "invalid qeid",
				StatusCode: http.StatusBadRequest}
		}
		var data SgxData

		pckinfo := &types.PckCert{QeId: QeId}
		existingPckCertData, err := db.PckCertRepository().Retrieve(*pckinfo)
		if existingPckCertData == nil {
			return &resourceError{Message: "no pck cert record found: " + err.Error(),
				StatusCode: http.StatusNotFound}
		}

		data.PckCertInfo.PckCerts = existingPckCertData.PckCerts
		data.PckCertInfo.Tcbms = existingPckCertData.Tcbms
		data.PckCertInfo.TotalPckCerts = len(existingPckCertData.PckCerts)

		existingPlatformData := &types.Platform{QeId: QeId}
		existingPlatformData, err = db.PlatformRepository().Retrieve(*existingPlatformData)
		if existingPlatformData == nil {
			return &resourceError{Message: "no platform record found: " + err.Error(),
				StatusCode: http.StatusNotFound}
		}

		data.PlatformInfo.CpuSvn = existingPlatformData.CpuSvn
		data.PlatformInfo.PceSvn = existingPlatformData.PceSvn
		data.PlatformInfo.PceId = existingPlatformData.PceId
		data.PlatformInfo.Fmspc = existingPlatformData.Fmspc

		TcbInfo := types.FmspcTcbInfo{Fmspc: data.PlatformInfo.Fmspc}
		existingFmspc, err := db.FmspcTcbInfoRepository().Retrieve(TcbInfo)
		if existingFmspc == nil {
			return &resourceError{Message: "no tcb info record found: " + err.Error(),
				StatusCode: http.StatusNotFound}
		}
		data.FmspcTcbInfo.TcbInfo = existingFmspc.TcbInfo

		certIdx, err := getBestPckCert(&data)
		if err != nil {
			return &resourceError{Message: "cannot select pck cert for current tcb level: " + err.Error(),
				StatusCode: http.StatusInternalServerError}
		}

		// for the selected pck cert, select corresponding raw tcb level (tcbm)
		tcbm, err1 := hex.DecodeString(data.PckCertInfo.Tcbms[certIdx])
		if err1 != nil {
			return &resourceError{Message: "cannot decode tcbm: " + err1.Error(),
				StatusCode: http.StatusInternalServerError}
		}

		// tcbm (current raw tcb level) is 18 byte array with first 16 bytes for cpusvn
		//  and next 2 bytes for pcesvn
		PckComponents := tcbm[:16]
		PckPceSvn := binary.LittleEndian.Uint16(tcbm[16:])

		var tcbInfo TcbInfoJson

		// unmarshal the json encoded TcbInfo response for a platform
		err = json.Unmarshal([]byte(data.FmspcTcbInfo.TcbInfo), &tcbInfo)
		if err != nil {
			return &resourceError{Message: "cannot unmarshal tcbinfo: " + err.Error(),
				StatusCode: http.StatusInternalServerError}
		}

		var Status string
		var response Response
		response.Status = "false"
		response.Message = "TCB Status is not UpToDate"

		var TcbComponents []byte
		// iterate through all TCB Levels present in TCBInfo
		for i := 0; i < len(tcbInfo.TcbInfo.TcbLevels); i++ {
			TcbPceSvn := tcbInfo.TcbInfo.TcbLevels[i].Tcb.PceSvn
			TcbComponents = getTcbCompList(&tcbInfo.TcbInfo.TcbLevels[i].Tcb)
			TcbError := compareTcbComponents(PckComponents, PckPceSvn, TcbComponents, TcbPceSvn)
			if TcbError == EqualOrGreater {
				Status = tcbInfo.TcbInfo.TcbLevels[i].TcbStatus
				break
			}
		}

		if Status == "UpToDate" || Status == "ConfigurationNeeded" {
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
		w.Write(js)

		return nil
	}
}

func getPcsVersion() int {
	conf := config.Global()
	pcs_url := conf.ProvServerInfo.ProvServerUrl
	PCS_Url := regexp.MustCompile(`^(https:\/\/)(.*)\.intel\.com\/sgx\/certification\/v([1-9]{0,9})$`)
	if PCS_Url.MatchString(pcs_url) {
		str := PCS_Url.FindStringSubmatch(pcs_url)
		version, _ := strconv.Atoi(str[3])
		return version
	} else {
		log.Error("failed to get pcs server version")
		return 0
	}
}
