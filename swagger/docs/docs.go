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
//  BasePath: /scs/sgx/certification/v1/
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
