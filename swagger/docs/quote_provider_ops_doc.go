/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package docs

import "intel/isecl/scs/v3/resource"

// TcbInfoJsonResp response payload
// swagger:response TcbInfoJsonResp
type TcbInfoJsonResp struct {
	// in:body
	Body resource.TcbInfoJson
}

// swagger:operation GET /sgx/certification/v1/pckcert Certificates getPckCertificate
// ---
// description: |
//   Retrieves the Platform Certification Key (PCK) Certificate for the current TCB level of SGX enabled platform
//   with the provided platform values.
//
// produces:
//  - application/x-pem-file
// parameters:
// - name: encrypted_ppid
//   description: Encrypted Platform Provisioning ID.
//   in: query
//   type: string
// - name: cpusvn
//   description: CPU SVN of the platform.
//   in: query
//   type: string
// - name: pcesvn
//   description: PCE SVN of the platform.
//   in: query
//   type: string
// - name: pceid
//   description: PCE ID of the platform.
//   in: query
//   type: string
// - name: qeid
//   description: Quoting Enclave ID specific to a platform.
//   in: query
//   type: string
// responses:
//   '200':
//     description: Successfully retrieved the PCK certificate for the platform.
//     schema:
//       type: string
//
// x-sample-call-endpoint: |
//   https://scs.server.com:9000/scs/sgx/certification/v1/pckcert?encrypted_ppid=82b1bc029231d52e27b4d7bf3fd2a21df8fd4ced21e11e42c96c27d959be56f2973d80aff2b359db8590d2f05d4175c80755dfb0a3c7111e3be35792cf80c3ca5708481e6a1448e51021df0ccf525002b8c31a707171847b49b969491b6bc339837fe62881e39e064620f6c09a1cbdcd29ab7d5922f961ef1f20d6a294cb92ff9a5f42f82baefefe0eabb25872716cf1ea55cd5f65d903ee5605d89e26cb61cc2e5b064409cc53e012b5ada765b7c28dcb3d8d3d2418b56d10abcecd19c920ba3941240a659d42a5212da9ea938b73b6b78366a09b26994634e95b2a01915689266247acafa8545ac6b734843e03c37ee2200e0f6c48589e4ad0d6dc4fb65be5e9242ed0c4122caf720962eac6f7a2ce43ff8b00ea566e1c087d18ae08d1417bb072ac196b050849f97235c40486453d6ab19c9859951b401edb69abddb074c4b1aa1a306d4d631fcef18d46c44af74cd9c117ce817d582c70fa3ec5b7b3037b16e166165d43156c3e2b463adef2615940e9dd119582ca14e152ca3d654289ea&cpusvn=1bf8deed6f929ce40bd658e61ea722eb&pcesvn=0a00&pceid=0000&qeid=0518145496973c5e69577195511e9080
// x-sample-call-output: |
//    -----BEGIN CERTIFICATE-----
//    MIIE5jCCBI2gAwIBAgIUNpxbNVz2bbSgFUKTNewIizm6qHEwCgYIKoZIzj0EAwIwcDEiMCAGA1UE
//    AwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24x
//    FDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTELMAkGA1UEBhMCVVMwHhcNMjAwNjE1
//    MDY0MjAwWhcNMjcwNjE1MDY0MjAwWjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENLIENlcnRpZmlj
//    YXRlMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJ
//    BgNVBAgMAkNBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABH1IQvYf6Vso
//    Y4FR6CPQLeUyeG6ZP0rf5sD/jw5Gc/D8EkyiQCiTVyt47/UZa+kmvGGtLW26NKQcvls/ZrXOrGuj
//    ggMDMIIC/zAfBgNVHSMEGDAWgBRZI9OnSqhjVC45cK3gDwcrVyQqtzBiBgNVHR8EWzBZMFegVaBT
//    hlFodHRwczovL3NieC5hcGkudHJ1c3RlZHNlcnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNh
//    dGlvbi92My9wY2tjcmw/Y2E9cGxhdGZvcm0wHQYDVR0OBBYEFNCyP3X/+Q+mKvcHnJelhFGvTLwO
//    MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMIICOQYJKoZIhvhNAQ0BBIICKjCCAiYwHgYK
//    KoZIhvhNAQ0BAQQQK1ICWHdapgGvTsGQnrKGuTCCAWMGCiqGSIb4TQENAQIwggFTMBAGCyqGSIb4
//    TQENAQIBAgECMBAGCyqGSIb4TQENAQICAgECMBAGCyqGSIb4TQENAQIDAgEAMBAGCyqGSIb4TQEN
//    AQIEAgEAMBAGCyqGSIb4TQENAQIFAgEAMBAGCyqGSIb4TQENAQIGAgEAMBAGCyqGSIb4TQENAQIH
//    AgEAMBAGCyqGSIb4TQENAQIIAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIKAgEA
//    MBAGCyqGSIb4TQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4TQENAQINAgEAMBAG
//    CyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAGCyqGSIb4TQENAQIQAgEAMBAGCyqG
//    SIb4TQENAQIRAgEKMB8GCyqGSIb4TQENAQISBBACAgAAAAAAAAAAAAAAAAAAMBAGCiqGSIb4TQEN
//    AQMEAgAAMBQGCiqGSIb4TQENAQQEBiBgagAAADAPBgoqhkiG+E0BDQEFCgEBMB4GCiqGSIb4TQEN
//    AQYEEOXbV8/Rrz5F3fvX9S50pEgwRAYKKoZIhvhNAQ0BBzA2MBAGCyqGSIb4TQENAQcBAQH/MBAG
//    CyqGSIb4TQENAQcCAQH/MBAGCyqGSIb4TQENAQcDAQH/MAoGCCqGSM49BAMCA0cAMEQCIE6gwTxP
//    C2kacUlGEjRWcz84BTnqZExC87NZqrlCF/HyAiA0qmvZocv+UQ1VnqtGQFrku/HdZdW171dBr4v2
//    UYU+3g==
//    -----END CERTIFICATE-----
// ---

// swagger:operation GET /sgx/certification/v1/pckcrl Certificates getPckCrl
// ---
// description: |
//   Retrieves the latest PCK Certificate Revocation List (CRL) for any SGX enabled platforms.
//   A CRL is a list of revoked SGX PCK Certificates that are issued by Intel SGX Processor CA.
//   The query parameter 'ca' should be provided as mandatory for this REST call.
//
// produces:
//  - application/x-pem-file
// parameters:
// - name: ca
//   description: PCK CRL issuing Certificate Authority (CA). CA can be either "processor" or "platform".
//   in: query
//   type: string
// responses:
//   '200':
//     description: Successfully retrieved the PCK CRL for a platform.
//     schema:
//       type: string
//
// x-sample-call-endpoint: https://scs.server.com:9000/scs/sgx/certification/v1/pckcrl?ca=processor
// x-sample-call-output: |
//    -----BEGIN X509 CRL-----
//    MIIBKjCB0QIBATAKBggqhkjOPQQDAjBxMSMwIQYDVQQDDBpJbnRlbCBTR1ggUENLIFByb2Nlc3Nv
//    ciBDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQsw
//    CQYDVQQIDAJDQTELMAkGA1UEBhMCVVMXDTIwMDQyODE2NTkyM1oXDTIwMDUyODE2NTkyM1qgLzAt
//    MAoGA1UdFAQDAgEBMB8GA1UdIwQYMBaAFNDoqtp11/kuSReYPHsUZdDV8llNMAoGCCqGSM49BAMC
//    A0gAMEUCIAKZ+B0OOFZgzMrwQ0T0GlIritTNKNr0ayW7wchYlgdlAiEAuQifgQcxCYU/lkOUgNcl
//    gG6ZSVMMjfliJZK2q6fnM6s=
//    -----END X509 CRL-----
// ---

// swagger:operation GET /sgx/certification/v1/tcb Certificates getTcbInfo
// ---
// description: |
//   Retrieves the Trusted Computing Base (TCB) information for all TCB levels of the SGX enabled platform
//   with the provided FMPSC value.
//
// produces:
//  - application/json
// parameters:
// - name: fmspc
//   description: FMSPC value of the platform.
//   in: query
//   type: string
// responses:
//   '200':
//     description: Successfully retrieved the TCB info of the platform with the matching fmpsc value.
//     schema:
//       "$ref": "#/definitions/TcbInfoJson"
//
// x-sample-call-endpoint: https://scs.server.com:9000/scs/sgx/certification/v1/tcb?fmspc=20606a000000
// x-sample-call-output: |
//    {
//        "tcbInfo": {
//            "version": 2,
//            "issueDate": "2020-06-15T06:42:01Z",
//            "nextUpdate": "2020-07-15T06:42:01Z",
//            "fmspc": "20606a000000",
//            "pceId": "0000",
//            "tcbType": 0,
//            "tcbEvaluationDataNumber": 5,
//            "tcbLevels": [
//                {
//                    "tcb": {
//                        "sgxtcbcomp01svn": 2,
//                        "sgxtcbcomp02svn": 2,
//                        "sgxtcbcomp03svn": 0,
//                        "sgxtcbcomp04svn": 0,
//                        "sgxtcbcomp05svn": 0,
//                        "sgxtcbcomp06svn": 0,
//                        "sgxtcbcomp07svn": 0,
//                        "sgxtcbcomp08svn": 0,
//                        "sgxtcbcomp09svn": 0,
//                        "sgxtcbcomp10svn": 0,
//                        "sgxtcbcomp11svn": 0,
//                        "sgxtcbcomp12svn": 0,
//                        "sgxtcbcomp13svn": 0,
//                        "sgxtcbcomp14svn": 0,
//                        "sgxtcbcomp15svn": 0,
//                        "sgxtcbcomp16svn": 0,
//                        "pcesvn": 10
//                    },
//                    "tcbDate": "2020-05-28T00:00:00Z",
//                    "tcbStatus": "UpToDate"
//                },
//                {
//                    "tcb": {
//                        "sgxtcbcomp01svn": 1,
//                        "sgxtcbcomp02svn": 1,
//                        "sgxtcbcomp03svn": 0,
//                        "sgxtcbcomp04svn": 0,
//                        "sgxtcbcomp05svn": 0,
//                        "sgxtcbcomp06svn": 0,
//                        "sgxtcbcomp07svn": 0,
//                        "sgxtcbcomp08svn": 0,
//                        "sgxtcbcomp09svn": 0,
//                        "sgxtcbcomp10svn": 0,
//                        "sgxtcbcomp11svn": 0,
//                        "sgxtcbcomp12svn": 0,
//                        "sgxtcbcomp13svn": 0,
//                        "sgxtcbcomp14svn": 0,
//                        "sgxtcbcomp15svn": 0,
//                        "sgxtcbcomp16svn": 0,
//                        "pcesvn": 9
//                    },
//                    "tcbDate": "2020-03-22T00:00:00Z",
//                    "tcbStatus": "OutOfDate"
//                },
//                {
//                    "tcb": {
//                        "sgxtcbcomp01svn": 1,
//                        "sgxtcbcomp02svn": 1,
//                        "sgxtcbcomp03svn": 0,
//                        "sgxtcbcomp04svn": 0,
//                        "sgxtcbcomp05svn": 0,
//                        "sgxtcbcomp06svn": 0,
//                        "sgxtcbcomp07svn": 0,
//                        "sgxtcbcomp08svn": 0,
//                        "sgxtcbcomp09svn": 0,
//                        "sgxtcbcomp10svn": 0,
//                        "sgxtcbcomp11svn": 0,
//                        "sgxtcbcomp12svn": 0,
//                        "sgxtcbcomp13svn": 0,
//                        "sgxtcbcomp14svn": 0,
//                        "sgxtcbcomp15svn": 0,
//                        "sgxtcbcomp16svn": 0,
//                        "pcesvn": 0
//                    },
//                    "tcbDate": "2020-03-22T00:00:00Z",
//                    "tcbStatus": "OutOfDate"
//                }
//            ]
//        },
//        "signature": "40b3536ee9c7028df7f0a976eaa405bc82768a258512be95fd151731f756f20a35c4a2642b91ba8083dca067932af75f1f92265dbdbd12573b05a959f6e3a677"
//    }
// ---

// swagger:operation GET /sgx/certification/v1/qe/identity Certificates getQeIdentityInfo
// ---
// description: |
//   Retrieves the Quote Identity information for Quoting Enclave issued by Intel for a platform.
//
// produces:
//  - application/json
// responses:
//   '200':
//     description: Successfully retrieved the QE Identity information of a platform.
//     schema:
//       type: string
//
// x-sample-call-endpoint: https://scs.server.com:9000/scs/sgx/certification/v1/qe/identity
// x-sample-call-output: |
//    {
//        "enclaveIdentity": {
//            "id": "QE",
//            "version": 2,
//            "issueDate": "2020-06-15T06:42:01Z",
//            "nextUpdate": "2020-07-15T06:42:01Z",
//            "tcbEvaluationDataNumber": 5,
//            "miscselect": "00000000",
//            "miscselectMask": "FFFFFFFF",
//            "attributes": "11000000000000000000000000000000",
//            "attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
//            "mrsigner": "8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF",
//            "isvprodid": 1,
//            "tcbLevels": [
//                {
//                    "tcb": {
//                        "isvsvn": 2
//                    },
//                    "tcbDate": "2019-05-15T00:00:00Z",
//                    "tcbStatus": "UpToDate"
//                },
//                {
//                    "tcb": {
//                        "isvsvn": 1
//                    },
//                    "tcbDate": "2018-08-15T00:00:00Z",
//                    "tcbStatus": "OutOfDate"
//                }
//            ]
//        },
//        "signature": "2c50f0f4297781594e4d86c864ef1bd6797ab77566c9ddc417330ca7f37456f2f998a44e8230c57c2c8f51258ce5044cf0ac0af58e5c953e466f51981dc1390c"
//    }
// ---
