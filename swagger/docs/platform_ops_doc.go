/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package docs

import "intel/isecl/scs/v5/resource"

type PlatformInfoInput struct {
	EncPpid          string `json:"enc_ppid"`
	CPUSvn           string `json:"cpu_svn"`
	PceSvn           string `json:"pce_svn"`
	PceID            string `json:"pce_id"`
	QeID             string `json:"qe_id"`
	PlatformManifest string `json:"manifest"`
	HardwareUUID     string `json:"hardware_uuid"`
}

// PlatformInfoReq request payload
// swagger:parameters PlatformInfoReq
type PlatformInfoReq struct {
	// in:body
	Body PlatformInfoInput
}

// StatusResponse response payload
// swagger:response StatusResponse
type StatusResponse struct {
	// in:body
	Body resource.Response
}

// swagger:operation POST /platforms PlatformInfo pushPlatformInfo
// ---
//
// description: |
//   SGX Agent uses this API to push the platform values (such as enc_ppi, pceid, cpisvn, pcesvn, qeid and manifest) to SCS.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// consumes:
//  - application/json
// produces:
//  - application/json
// parameters:
// - name: request body
//   in: body
//   required: true
//   schema:
//     "$ref": "#/definitions/PlatformInfoInput"
// responses:
//   '201':
//     description: Successfully pushed the platform values to SCS.
//     schema:
//       "$ref": "#/definitions/Response"
//
// x-sample-call-endpoint: https://scs.server.com:9000/scs/sgx/certification/v1/platforms
// x-sample-call-input: |
//    {
//       "enc_ppid": "00f51b4272163732be2101ee62dfdb175205a5179c5b5faff4b2ae103cb1150ef7d4e6041775543930600e41dd2e6aee7f4079
//             0f5a0380f6b29b1f1f7e6aad75bfa666153bb325c6db5b67f694d14bff98996c4994ce153278bfeb1b455dd4acbeacc97df6a3cd439a838218c
//             1e07dae91a62195b803b9d3808d5b8470d46b0af3f275b6f6573871eb4eeb43ed9c5a5647729f25648fa74f1ce43621618b266abde6f44e92ce
//             65bbbbe2c50e3e7a8b84d1ed38f53a1d99d3f15fc8c39b0ee568580c37a4eb19dbe87cd447c78f05544684701c01e64e0273dc69c27e46f732f
//             7a7ee8cc4dfaf3b921bf6bbc3ee83f8de5f4e86039595cddaf7cadfce599f0eb92509ff2a90d189bda51fdd298fa1cffd4e8d79095f104c073a
//             2b71cf61c727f4e5718cb7ea2f8fc6d7694bf3b40764234dfbe0d35f40f557545e1729ca639be4f1bcdc9028cb590b3ad3fd176bfea3cef13e5
//             7db057b3bae7ae8553a454515aecb21e4c58c670b19d8ee12668ab8af16d56b285153589eb85d15cd9e56fe459b",
//       "pce_id": "0000",
//       "cpu_svn": "1bf8deed6f929ce40bd658e61ea722eb",
//       "pce_svn": "0a00",
//       "qe_id": "0518145496973c5e69577195511e9080"
//       "manifest": "178e874b49e44aa599bb3057170925b41d6e010000000000000000000000000084947ac684404189902a7e76cd658926bc0101000000
//             00000000000000000000e5db57cfd1af3e45ddfbd7f52e74a44871d542e3893c9f6f88ef999a7969eacc38e156d8233e6479997f6daa3553d90
//             2bb6a7fd6e6db21c43c13993c91c2eb95b6654b70d3e1602d5c236f9c5e8209a6a9923f49628eb7ba934913ccee4ae3df1c9ce11d0dac1c2e6e
//             bbeb7b036e1288ad98d0aac44e5dbe3e01ea40eb7301c513c388d7e87b6630fcee23dccc28e5466a3669137e79021e386db75569606a481ac81
//             bcd03fdc30a142bce8cca274dc044f2b40dc9abaef952bb4f0d01058d590d6950cd56bd036c7385272789e38de9b7302fafd5514248de83c18a
//             edc9fb3c4a60754b41d8038be2c85d9e109742450b76989ff262cb0a7a979546018c7c76109ec6dd7965eead462bbd1edf6124e4a7da00de497
//             408e44869496138cc1383f2caef7b6bf456c1f494c2b539e1741d904515414816a5096e96350b5decc84cdb9c29fe6ffa7a1982b55fe6fb258e
//             18f03c1724b296aab446a9f4e10de1d49485f4360dfade7bc6abf70c0f1ed59c15ab30face19e3cfee43e1bee2f2800095576af52b46344ea4e
//             7e08c2bc1d568dd01000100bcf7744b0929b513d15794280f82233b5684b73af7f86c073d1ecec86f6cd34c0000010001000000fd8f5c411b61
//             4b97a74796f08926757b39050100000000000000000000000000200000000300000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
//             00000000000000000000000",
//        "hardware_uuid": "ee37c360-7eae-4250-a677-6ee12adce8e2"
//    }
// x-sample-call-output: |
//    {
//        "Status": "Created",
//        "Message": "platform data pushed to scs"
//    }
// ---

// swagger:operation GET /refreshes PlatformInfo refreshPlatformInfo
// ---
// description: |
//   This API is used to refresh the platform collaterals stored in the SGX Caching Service (SCS) database,
//   outside of the periodic refresh cycles. An Admin can make use of this REST endpoint to force the refresh of
//   PCK Certificates, PCK CRL, TCB info and QE Identity information. This is useful in scenarios like TCB recovery.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// responses:
//   '200':
//     description: Successfully refreshed the platform collaterals.
//     schema:
//       "$ref": "#/definitions/Response"
//
// x-sample-call-endpoint: https://scs.server.com:9000/scs/sgx/certification/v1/refreshes
// x-sample-call-output: |
//    {
//        "Status": "Success",
//        "Message": "sgx collaterals refreshed successfully"
//    }
// ---

// swagger:operation GET /tcbstatus PlatformInfo getTcbStatus
// ---
// description: |
//   This API is used by SGX Agent to determine the TCB up-to-date status of a platform.
//   A valid bearer token should be provided to authorize this REST call.
//
// security:
//  - bearerAuth: []
// produces:
//  - application/json
// parameters:
// - name: qeid
//   description: Quoting Enclave ID specific to a platform.
//   in: query
//   type: string
// - name: pceid
//   description: Provisioning Certificate Enclave ID specific to a platform.
//   in: query
//   type: string
// responses:
//   '200':
//     description: Successfully retrieved the latest TCB up-to-date status for the provided qeid.
//     schema:
//       "$ref": "#/definitions/Response"
//
// x-sample-call-endpoint: https://scs.server.com:9000/scs/sgx/certification/v1/tcbstatus?qeid=0f16dfa4033e66e642af8fe358c18751
// x-sample-call-output: |
//    {
//        "Status": "true",
//        "Message": "TCB Status is UpToDate"
//    }
// ---
