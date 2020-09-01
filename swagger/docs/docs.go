// SGX Caching Service
//
// SGX Caching Service (SCS) provides an interface to fetch all the SGX platform collaterals and PCK Certificate
// from Intel PCS Server and stores them in a local database.
// Every SKC SGX Service that needs platform collaterals and workloads that needs PCK Certificate shall always contact SGX SCS.
// SGX SCS listening port is user-configurable.
//
//  License: Copyright (C) 2020 Intel Corporation. SPDX-License-Identifier: BSD-3-Clause
//
//  Version: 1.0
//  Host: scs.server.com:9000
//  BasePath: /scs
//
//  Schemes: https
//
//  SecurityDefinitions:
//   bearerAuth:
//     type: apiKey
//     in: header
//     name: Authorization
//     description: Enter your bearer token in the format **Bearer &lt;token&gt;**
//
// swagger:meta
package docs

// swagger:operation GET /sgx/certification/v1/version Version getVersion
// ---
// description: Retrieves the version of the SGX Caching Service.
//
// produces:
// - text/plain
// responses:
//   "200":
//     description: Successfully retrieved the version of SGX Caching Service.
//     schema:
//       type: string
//       example: skc_M12-SKC_SCS_M10_WW01.01-58-g2efaa71
//
// x-sample-call-endpoint: https://scs.server.com:9000/scs/sgx/certification/v1/version
// x-sample-call-output: skc_M12-SKC_SCS_M10_WW01.01-58-g2efaa71
// ---
