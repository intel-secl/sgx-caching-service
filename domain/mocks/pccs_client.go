/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package mocks

import (
	"bytes"
	"encoding/hex"
	"errors"
	"intel/isecl/scs/v5/domain"
	"io/ioutil"
	"net/http"
	"strings"
)

const (
	certFilePath = "../test/testcert.pem"
)

type ClientMock struct {
	ResponseCode int
}

func NewClientMock(respCode int) domain.HttpClient {
	return &ClientMock{
		ResponseCode: respCode,
	}
}

// sample response

// < HTTP/1.1 200 OK
// < Content-Length: 9147
// < Content-Type: application/json
// < Request-ID: 9c3716a720f74411a173d8937e2260e9
// < SGX-PCK-Certificate-Issuer-Chain: -----BEGIN%20CERTIFICATE-----%0AMIICmjCCAkCgAwIBAgIUWSPTp0qoY1QuOXCt4A8HK1ckKrcwCgYIKoZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ%0ABgNVBAYTAlVTMB4XDTE5MTAzMTEyMzM0N1oXDTM0MTAzMTEyMzM0N1owcDEiMCAG%0AA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwRSW50ZWwg%0AQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEL%0AMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQwp%2BLc%2BTUBtg1H%0A%2BU8JIsMsbjHjCkTtXb8jPM6r2dhu9zIblhDZ7INfqt3Ix8XcFKD8k0NEXrkZ66qJ%0AXa1KzLIKo4G%2FMIG8MB8GA1UdIwQYMBaAFOnoRFJTNlxLGJoR%2FEMYLKXcIIBIMFYG%0AA1UdHwRPME0wS6BJoEeGRWh0dHBzOi8vc2J4LWNlcnRpZmljYXRlcy50cnVzdGVk%0Ac2VydmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQU%0AWSPTp0qoY1QuOXCt4A8HK1ckKrcwDgYDVR0PAQH%2FBAQDAgEGMBIGA1UdEwEB%2FwQI%0AMAYBAf8CAQAwCgYIKoZIzj0EAwIDSAAwRQIhAJ1q%2BFTz%2BgUuVfBQuCgJsFrL2TTS%0Ae1aBZ53O52TjFie6AiAriPaRahUX9Oa9kGLlAchWXKT6j4RWSR50BqhrN3UT4A%3D%3D%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIIClDCCAjmgAwIBAgIVAOnoRFJTNlxLGJoR%2FEMYLKXcIIBIMAoGCCqGSM49BAMC%0AMGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD%0Ab3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw%0ACQYDVQQGEwJVUzAeFw0xOTEwMzEwOTQ5MjFaFw00OTEyMzEyMzU5NTlaMGgxGjAY%0ABgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3Jh%0AdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYDVQQG%0AEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE%2F6D%2F1WHNrWwPmNMIyBKMW5%0AJ6JzMsjo6xP2vkK1cdZGb1PGRP%2FC%2F8ECgiDkmklmzwLzLi%2B000m7LLrtKJA3oC2j%0Agb8wgbwwHwYDVR0jBBgwFoAU6ehEUlM2XEsYmhH8QxgspdwggEgwVgYDVR0fBE8w%0ATTBLoEmgR4ZFaHR0cHM6Ly9zYngtY2VydGlmaWNhdGVzLnRydXN0ZWRzZXJ2aWNl%0Acy5pbnRlbC5jb20vSW50ZWxTR1hSb290Q0EuZGVyMB0GA1UdDgQWBBTp6ERSUzZc%0ASxiaEfxDGCyl3CCASDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH%2FBAgwBgEB%2FwIB%0AATAKBggqhkjOPQQDAgNJADBGAiEAzw9zdUiUHPMUd0C4mx41jlFZkrM3y5f1lgnV%0AO7FbjOoCIQCoGtUmT4cXt7V%2BySHbJ8Hob9AanpvXNH1ER%2B%2FgZF%2BopQ%3D%3D%0A-----END%20CERTIFICATE-----%0A
// < SGX-PCK-Certificate-CA-Type: platform
// < SGX-FMSPC: 10606A000000
// < Date: Tue, 21 Jun 2022 11:39:56 GMT
// <
var respBody = []byte(`[	
    {
        "tcb":{
            "sgxtcbcomp01svn":3,
            "sgxtcbcomp02svn":3,
            "sgxtcbcomp03svn":0,
            "sgxtcbcomp04svn":0,
            "sgxtcbcomp05svn":0,
            "sgxtcbcomp06svn":0,
            "sgxtcbcomp07svn":0,
            "sgxtcbcomp08svn":0,
            "sgxtcbcomp09svn":0,
            "sgxtcbcomp10svn":0,
            "sgxtcbcomp11svn":0,
            "sgxtcbcomp12svn":0,
            "sgxtcbcomp13svn":0,
            "sgxtcbcomp14svn":0,
            "sgxtcbcomp15svn":0,
            "sgxtcbcomp16svn":0,
            "pcesvn":10
        },
        "cert":"-----BEGIN%20CERTIFICATE-----%0AMIIE9DCCBJugAwIBAgIVAK7PhD9pHlDkPeO8tYUNnwULbH58MAoGCCqGSM49BAMC%0AMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoM%0AEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UE%0ACAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTIyMDYyMTExMjQ1NloXDTI5MDYyMTExMjQ1%0ANlowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZpY2F0ZTEaMBgGA1UE%0ACgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYD%0AVQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAARK%0Atli3VtoAsjc2wHoHA5A5uswJ84%2F6SwdFyww3t%2B22vqaSqRbp1RMb7ld6PI5BznER%0A3y5pMERdh1V%2BE57Tf3u3o4IDEDCCAwwwHwYDVR0jBBgwFoAUWSPTp0qoY1QuOXCt%0A4A8HK1ckKrcwbwYDVR0fBGgwZjBkoGKgYIZeaHR0cHM6Ly9zYnguYXBpLnRydXN0%0AZWRzZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjMvcGNrY3Js%0AP2NhPXBsYXRmb3JtJmVuY29kaW5nPWRlcjAdBgNVHQ4EFgQUK296v3LdemDLePvZ%0AJG0BktPkvTkwDgYDVR0PAQH%2FBAQDAgbAMAwGA1UdEwEB%2FwQCMAAwggI5BgkqhkiG%0A%2BE0BDQEEggIqMIICJjAeBgoqhkiG%2BE0BDQEBBBBs86EguQbat2gRPlmMR4cFMIIB%0AYwYKKoZIhvhNAQ0BAjCCAVMwEAYLKoZIhvhNAQ0BAgECAQMwEAYLKoZIhvhNAQ0B%0AAgICAQMwEAYLKoZIhvhNAQ0BAgMCAQAwEAYLKoZIhvhNAQ0BAgQCAQAwEAYLKoZI%0AhvhNAQ0BAgUCAQAwEAYLKoZIhvhNAQ0BAgYCAQAwEAYLKoZIhvhNAQ0BAgcCAQAw%0AEAYLKoZIhvhNAQ0BAggCAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0B%0AAgoCAQAwEAYLKoZIhvhNAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZI%0AhvhNAQ0BAg0CAQAwEAYLKoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAw%0AEAYLKoZIhvhNAQ0BAhACAQAwEAYLKoZIhvhNAQ0BAhECAQowHwYLKoZIhvhNAQ0B%0AAhIEEAMDAAAAAAAAAAAAAAAAAAAwEAYKKoZIhvhNAQ0BAwQCAAAwFAYKKoZIhvhN%0AAQ0BBAQGEGBqAAAAMA8GCiqGSIb4TQENAQUKAQEwHgYKKoZIhvhNAQ0BBgQQ4yeH%0A%2BonkuTCa7WVk9vLfSjBEBgoqhkiG%2BE0BDQEHMDYwEAYLKoZIhvhNAQ0BBwEBAf8w%0AEAYLKoZIhvhNAQ0BBwIBAQAwEAYLKoZIhvhNAQ0BBwMBAf8wCgYIKoZIzj0EAwID%0ARwAwRAIgI6U5N%2BizqP%2FNB3RJ1LM9or3tYxnesV3papgZnuUd6m4CICvFefdvmH61%0A3aFl0jPP%2FCTbwaAYHaRiRIiLCGl8pr0f%0A-----END%20CERTIFICATE-----%0A",
        "tcbm":"030300000000000000000000000000000A00"
    },
    {
        "tcb":{
            "sgxtcbcomp01svn":2,
            "sgxtcbcomp02svn":2,
            "sgxtcbcomp03svn":0,
            "sgxtcbcomp04svn":0,
            "sgxtcbcomp05svn":0,
            "sgxtcbcomp06svn":0,
            "sgxtcbcomp07svn":0,
            "sgxtcbcomp08svn":0,
            "sgxtcbcomp09svn":0,
            "sgxtcbcomp10svn":0,
            "sgxtcbcomp11svn":0,
            "sgxtcbcomp12svn":0,
            "sgxtcbcomp13svn":0,
            "sgxtcbcomp14svn":0,
            "sgxtcbcomp15svn":0,
            "sgxtcbcomp16svn":0,
            "pcesvn":10
        },
        "cert":"-----BEGIN%20CERTIFICATE-----%0AMIIE9DCCBJugAwIBAgIVAJG%2BYb06dvJE9tiXsdnd%2BZiQyQOzMAoGCCqGSM49BAMC%0AMHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoM%0AEUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UE%0ACAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTIyMDYyMTExMjQ1NloXDTI5MDYyMTExMjQ1%0ANlowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZpY2F0ZTEaMBgGA1UE%0ACgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYD%0AVQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR7%0AdqdCK58qGU0BowGa%2FwX%2BCTGRS8kIepigkPZyTc8xWZ8op2SeyMpzBydO54dA2dgp%0Adkk%2Baoa3KgdHTnIUpdQKo4IDEDCCAwwwHwYDVR0jBBgwFoAUWSPTp0qoY1QuOXCt%0A4A8HK1ckKrcwbwYDVR0fBGgwZjBkoGKgYIZeaHR0cHM6Ly9zYnguYXBpLnRydXN0%0AZWRzZXJ2aWNlcy5pbnRlbC5jb20vc2d4L2NlcnRpZmljYXRpb24vdjMvcGNrY3Js%0AP2NhPXBsYXRmb3JtJmVuY29kaW5nPWRlcjAdBgNVHQ4EFgQUQ%2FbEfNb8WELZ7vlG%0A09SZdyeyczEwDgYDVR0PAQH%2FBAQDAgbAMAwGA1UdEwEB%2FwQCMAAwggI5BgkqhkiG%0A%2BE0BDQEEggIqMIICJjAeBgoqhkiG%2BE0BDQEBBBBs86EguQbat2gRPlmMR4cFMIIB%0AYwYKKoZIhvhNAQ0BAjCCAVMwEAYLKoZIhvhNAQ0BAgECAQIwEAYLKoZIhvhNAQ0B%0AAgICAQIwEAYLKoZIhvhNAQ0BAgMCAQAwEAYLKoZIhvhNAQ0BAgQCAQAwEAYLKoZI%0AhvhNAQ0BAgUCAQAwEAYLKoZIhvhNAQ0BAgYCAQAwEAYLKoZIhvhNAQ0BAgcCAQAw%0AEAYLKoZIhvhNAQ0BAggCAQAwEAYLKoZIhvhNAQ0BAgkCAQAwEAYLKoZIhvhNAQ0B%0AAgoCAQAwEAYLKoZIhvhNAQ0BAgsCAQAwEAYLKoZIhvhNAQ0BAgwCAQAwEAYLKoZI%0AhvhNAQ0BAg0CAQAwEAYLKoZIhvhNAQ0BAg4CAQAwEAYLKoZIhvhNAQ0BAg8CAQAw%0AEAYLKoZIhvhNAQ0BAhACAQAwEAYLKoZIhvhNAQ0BAhECAQowHwYLKoZIhvhNAQ0B%0AAhIEEAICAAAAAAAAAAAAAAAAAAAwEAYKKoZIhvhNAQ0BAwQCAAAwFAYKKoZIhvhN%0AAQ0BBAQGEGBqAAAAMA8GCiqGSIb4TQENAQUKAQEwHgYKKoZIhvhNAQ0BBgQQ4yeH%0A%2BonkuTCa7WVk9vLfSjBEBgoqhkiG%2BE0BDQEHMDYwEAYLKoZIhvhNAQ0BBwEBAf8w%0AEAYLKoZIhvhNAQ0BBwIBAQAwEAYLKoZIhvhNAQ0BBwMBAf8wCgYIKoZIzj0EAwID%0ARwAwRAIgDpQxFeH4ndzEz6hc3izAIIMIaFR3PMAcYujk4%2BT8obcCIB%2BmkNA73HVj%0AhoNiVdBkV50Qxnv%2FSY3GQrw4z3wV4XLh%0A-----END%20CERTIFICATE-----%0A",
        "tcbm":"020200000000000000000000000000000A00"
    },
    {
        "tcb":{
            "sgxtcbcomp01svn":1,
            "sgxtcbcomp02svn":1,
            "sgxtcbcomp03svn":0,
            "sgxtcbcomp04svn":0,
            "sgxtcbcomp05svn":0,
            "sgxtcbcomp06svn":0,
            "sgxtcbcomp07svn":0,
            "sgxtcbcomp08svn":0,
            "sgxtcbcomp09svn":0,
            "sgxtcbcomp10svn":0,
            "sgxtcbcomp11svn":0,
            "sgxtcbcomp12svn":0,
            "sgxtcbcomp13svn":0,
            "sgxtcbcomp14svn":0,
            "sgxtcbcomp15svn":0,
            "sgxtcbcomp16svn":0,
            "pcesvn":9
            },
        "cert":"-----BEGIN%20CERTIFICATE-----%0AMIIE9DCCBJqgAwIBAgIUb6rZwuxZc5cIkp6%2Foqqz7HdGyFwwCgYIKoZIzj0EAwIw%0AcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwR%0ASW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQI%0ADAJDQTELMAkGA1UEBhMCVVMwHhcNMjIwNjIxMTEyNDU2WhcNMjkwNjIxMTEyNDU2%0AWjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENLIENlcnRpZmljYXRlMRowGAYDVQQK%0ADBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV%0ABAgMAkNBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOB3%0AWFm1ziJAlu79StgxfAuz8AWCkoiraneuAGgrFExeiukczJvjWdtDTM2O7w8GiZAt%0A1h84AyDRUb%2BHoNaflACjggMQMIIDDDAfBgNVHSMEGDAWgBRZI9OnSqhjVC45cK3g%0ADwcrVyQqtzBvBgNVHR8EaDBmMGSgYqBghl5odHRwczovL3NieC5hcGkudHJ1c3Rl%0AZHNlcnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92My9wY2tjcmw%2F%0AY2E9cGxhdGZvcm0mZW5jb2Rpbmc9ZGVyMB0GA1UdDgQWBBQ6mE6WHjgoVSRiUaG%2F%0A0QmQDpX7LjAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH%2FBAIwADCCAjkGCSqGSIb4%0ATQENAQSCAiowggImMB4GCiqGSIb4TQENAQEEEGzzoSC5Btq3aBE%2BWYxHhwUwggFj%0ABgoqhkiG%2BE0BDQECMIIBUzAQBgsqhkiG%2BE0BDQECAQIBATAQBgsqhkiG%2BE0BDQEC%0AAgIBATAQBgsqhkiG%2BE0BDQECAwIBADAQBgsqhkiG%2BE0BDQECBAIBADAQBgsqhkiG%0A%2BE0BDQECBQIBADAQBgsqhkiG%2BE0BDQECBgIBADAQBgsqhkiG%2BE0BDQECBwIBADAQ%0ABgsqhkiG%2BE0BDQECCAIBADAQBgsqhkiG%2BE0BDQECCQIBADAQBgsqhkiG%2BE0BDQEC%0ACgIBADAQBgsqhkiG%2BE0BDQECCwIBADAQBgsqhkiG%2BE0BDQECDAIBADAQBgsqhkiG%0A%2BE0BDQECDQIBADAQBgsqhkiG%2BE0BDQECDgIBADAQBgsqhkiG%2BE0BDQECDwIBADAQ%0ABgsqhkiG%2BE0BDQECEAIBADAQBgsqhkiG%2BE0BDQECEQIBCTAfBgsqhkiG%2BE0BDQEC%0AEgQQAQEAAAAAAAAAAAAAAAAAADAQBgoqhkiG%2BE0BDQEDBAIAADAUBgoqhkiG%2BE0B%0ADQEEBAYQYGoAAAAwDwYKKoZIhvhNAQ0BBQoBATAeBgoqhkiG%2BE0BDQEGBBDjJ4f6%0AieS5MJrtZWT28t9KMEQGCiqGSIb4TQENAQcwNjAQBgsqhkiG%2BE0BDQEHAQEB%2FzAQ%0ABgsqhkiG%2BE0BDQEHAgEBADAQBgsqhkiG%2BE0BDQEHAwEB%2FzAKBggqhkjOPQQDAgNI%0AADBFAiBJwRZ5Dkvmz41SMH%2FFojZqiPxfzpQo78iqcvTdo0DwTQIhAPzZkuFcwZUV%0Al0yBja8lgLWp%2F8eMKpx5hOAw1dDV2iST%0A-----END%20CERTIFICATE-----%0A",
        "tcbm":"010100000000000000000000000000000900"
    },
    {
        "tcb":{
            "sgxtcbcomp01svn":1,
            "sgxtcbcomp02svn":1,
            "sgxtcbcomp03svn":0,
            "sgxtcbcomp04svn":0,
            "sgxtcbcomp05svn":0,
            "sgxtcbcomp06svn":0,
            "sgxtcbcomp07svn":0,
            "sgxtcbcomp08svn":0,
            "sgxtcbcomp09svn":0,
            "sgxtcbcomp10svn":0,
            "sgxtcbcomp11svn":0,
            "sgxtcbcomp12svn":0,
            "sgxtcbcomp13svn":0,
            "sgxtcbcomp14svn":0,
            "sgxtcbcomp15svn":0,
            "sgxtcbcomp16svn":0,
            "pcesvn":0
            },
        "cert":"-----BEGIN%20CERTIFICATE-----%0AMIIE8zCCBJqgAwIBAgIUSLHNGWSkGvuA1w7%2BQHgQ7POzIe4wCgYIKoZIzj0EAwIw%0AcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwR%0ASW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQI%0ADAJDQTELMAkGA1UEBhMCVVMwHhcNMjIwNjIxMTEyNDU2WhcNMjkwNjIxMTEyNDU2%0AWjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENLIENlcnRpZmljYXRlMRowGAYDVQQK%0ADBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV%0ABAgMAkNBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAU2%0ARaPHnPRqm8plcNRFrIrnldDTc6%2Bo42aHwEHxE4tGFNBDHgVai8b5hzy3xyor%2BatU%0AUIb0%2FS30zcKD9SOx3IijggMQMIIDDDAfBgNVHSMEGDAWgBRZI9OnSqhjVC45cK3g%0ADwcrVyQqtzBvBgNVHR8EaDBmMGSgYqBghl5odHRwczovL3NieC5hcGkudHJ1c3Rl%0AZHNlcnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92My9wY2tjcmw%2F%0AY2E9cGxhdGZvcm0mZW5jb2Rpbmc9ZGVyMB0GA1UdDgQWBBSFTFdtw1Y7S9Jq9zXP%0AYs4e%2BFZKijAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH%2FBAIwADCCAjkGCSqGSIb4%0ATQENAQSCAiowggImMB4GCiqGSIb4TQENAQEEEGzzoSC5Btq3aBE%2BWYxHhwUwggFj%0ABgoqhkiG%2BE0BDQECMIIBUzAQBgsqhkiG%2BE0BDQECAQIBATAQBgsqhkiG%2BE0BDQEC%0AAgIBATAQBgsqhkiG%2BE0BDQECAwIBADAQBgsqhkiG%2BE0BDQECBAIBADAQBgsqhkiG%0A%2BE0BDQECBQIBADAQBgsqhkiG%2BE0BDQECBgIBADAQBgsqhkiG%2BE0BDQECBwIBADAQ%0ABgsqhkiG%2BE0BDQECCAIBADAQBgsqhkiG%2BE0BDQECCQIBADAQBgsqhkiG%2BE0BDQEC%0ACgIBADAQBgsqhkiG%2BE0BDQECCwIBADAQBgsqhkiG%2BE0BDQECDAIBADAQBgsqhkiG%0A%2BE0BDQECDQIBADAQBgsqhkiG%2BE0BDQECDgIBADAQBgsqhkiG%2BE0BDQECDwIBADAQ%0ABgsqhkiG%2BE0BDQECEAIBADAQBgsqhkiG%2BE0BDQECEQIBADAfBgsqhkiG%2BE0BDQEC%0AEgQQAQEAAAAAAAAAAAAAAAAAADAQBgoqhkiG%2BE0BDQEDBAIAADAUBgoqhkiG%2BE0B%0ADQEEBAYQYGoAAAAwDwYKKoZIhvhNAQ0BBQoBATAeBgoqhkiG%2BE0BDQEGBBDjJ4f6%0AieS5MJrtZWT28t9KMEQGCiqGSIb4TQENAQcwNjAQBgsqhkiG%2BE0BDQEHAQEB%2FzAQ%0ABgsqhkiG%2BE0BDQEHAgEBADAQBgsqhkiG%2BE0BDQEHAwEB%2FzAKBggqhkjOPQQDAgNH%0AADBEAiACfBStYl5LPvRWCoaSh071d8pNJNZeOoFP3pK2snGcSgIgHxPfWTs7F4Iv%0A%2BLGphup7F67taRLedlWK2%2Fgbmyqx0fo%3D%0A-----END%20CERTIFICATE-----%0A",
        "tcbm":"01010000000000000000"
    }
]`)

var tcbRespBody = []byte(`{
       "tcbInfo": {
		   "version": 2,
           "issueDate": "2022-06-15T06:42:01Z",
           "nextUpdate": "2030-12-15T06:42:01Z",
           "fmspc":"10606A000000",
           "pceId":"10606A000000",
           "tcbType":1,
           "tcbEvaluationDataNumber":1,
           "tcbLevels": [
               {
                    "tcb":{
                        "sgxtcbcomp01svn":1,
                        "sgxtcbcomp02svn":1,
                        "sgxtcbcomp03svn":0,
                        "sgxtcbcomp04svn":0,
                        "sgxtcbcomp05svn":0,
                        "sgxtcbcomp06svn":0,
                        "sgxtcbcomp07svn":0,
                        "sgxtcbcomp08svn":0,
                        "sgxtcbcomp09svn":0,
                        "sgxtcbcomp10svn":0,
                        "sgxtcbcomp11svn":0,
                        "sgxtcbcomp12svn":0,
                        "sgxtcbcomp13svn":0,
                        "sgxtcbcomp14svn":0,
                        "sgxtcbcomp15svn":0,
                        "sgxtcbcomp16svn":0,
                        "pcesvn":0
                        },
                   "tcbDate": "2019-05-15T00:00:00Z",
                   "tcbStatus": "UpToDate"
               },
               {
                   "tcb": {
                        "sgxtcbcomp01svn":2,
                        "sgxtcbcomp02svn":2,
                        "sgxtcbcomp03svn":0,
                        "sgxtcbcomp04svn":0,
                        "sgxtcbcomp05svn":0,
                        "sgxtcbcomp06svn":0,
                        "sgxtcbcomp07svn":0,
                        "sgxtcbcomp08svn":0,
                        "sgxtcbcomp09svn":0,
                        "sgxtcbcomp10svn":0,
                        "sgxtcbcomp11svn":0,
                        "sgxtcbcomp12svn":0,
                        "sgxtcbcomp13svn":0,
                        "sgxtcbcomp14svn":0,
                        "sgxtcbcomp15svn":0,
                        "sgxtcbcomp16svn":0,
                        "pcesvn":0
                   },
                   "tcbDate": "2018-08-15T00:00:00Z",
                   "tcbStatus": "OutOfDate"
               }
           ]
       },
       "signature": "2c50f0f4297781594e4d86c864ef1bd6797ab77566c9ddc417330ca7f37456f2f998a44e8230c57c2c8f51258ce5044cf0ac0af58e5c953e466f51981dc1390c"
   }`)

var pckCrlResp = "308201cc30820173020101300a06082a8648ce3d04030230703122302006035504030c19496e74656c205347582050434b20506c6174666f726d204341311a3018060355040a0c11496e74656c20436f72706f726174696f6e3114301206035504070c0b53616e746120436c617261310b300906035504080c024341310b3009060355040613025553170d3232303331393134313135315a170d3232303431383134313135315a3081a030330214639f139a5040fdcff191e8a4fb1bf086ed603971170d3232303331393134313135315a300c300a0603551d1504030a01013034021500959d533f9249dc1e513544cdc830bf19b7f1f301170d3232303331393134313135315a300c300a0603551d1504030a0101303302140fda43a00b68ea79b7c2deaeac0b498bdfb2af90170d3232303331393134313135315a300c300a0603551d1504030a0101a02f302d300a0603551d140403020101301f0603551d23041830168014956f5dcdbd1be1e94049c9d4f433ce01570bde54300a06082a8648ce3d0403020347003044022062f51c1b98adfcb87cb808aaf7a62bc7c79e4c71a6ee4ee130325d8c15b14f8902201908be237ee440008097d6ea978ab1d4ddfa61052ad76fcf0f8d6952861317cd"

func (c *ClientMock) Do(req *http.Request) (*http.Response, error) {

	respHeader := http.Header{}

	var responseBody []byte

	if strings.Contains(req.URL.String(), "pckcerts") {
		responseBody = respBody
	} else if strings.Contains(req.URL.String(), "pckcrl") {
		decodedResp, _ := hex.DecodeString(pckCrlResp)
		responseBody = decodedResp
	} else {
		responseBody = tcbRespBody
	}

	switch c.ResponseCode {
	case http.StatusBadRequest:
		return nil, errors.New("Bad request")
	case http.StatusUnauthorized:
		return &http.Response{
			StatusCode:    c.ResponseCode,
			ContentLength: 9147,
			Body:          nil,
			Header:        respHeader,
		}, errors.New("Unauthorized")
	case http.StatusCreated:
		return &http.Response{
			StatusCode:    http.StatusCreated,
			ContentLength: 0,
			Body:          ioutil.NopCloser(bytes.NewReader(responseBody)),
			Header:        respHeader,
		}, nil
	case http.StatusNoContent:
		return &http.Response{
			StatusCode:    http.StatusNoContent,
			ContentLength: 9147,
			Body:          ioutil.NopCloser(bytes.NewReader([]byte(""))),
			Header:        respHeader,
		}, nil
	case http.StatusResetContent:
		return &http.Response{
			StatusCode:    http.StatusResetContent,
			ContentLength: 9147,
			Body:          ioutil.NopCloser(bytes.NewReader([]byte("test"))),
			Header:        respHeader,
		}, nil
	case http.StatusOK:
		respHeader.Add("Content-Type", "application/json")
		respHeader.Add("Content-Length", "9147")
		respHeader.Add("Request-ID", "9c3716a720f74411a173d8937e2260e9")
		respHeader.Add("SGX-PCK-Certificate-Issuer-Chain", "-----BEGIN%20CERTIFICATE-----%0AMIICmjCCAkCgAwIBAgIUWSPTp0qoY1QuOXCt4A8HK1ckKrcwCgYIKoZIzj0EAwIw%0AaDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv%0AcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ%0ABgNVBAYTAlVTMB4XDTE5MTAzMTEyMzM0N1oXDTM0MTAzMTEyMzM0N1owcDEiMCAG%0AA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwRSW50ZWwg%0AQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEL%0AMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQwp%2BLc%2BTUBtg1H%0A%2BU8JIsMsbjHjCkTtXb8jPM6r2dhu9zIblhDZ7INfqt3Ix8XcFKD8k0NEXrkZ66qJ%0AXa1KzLIKo4G%2FMIG8MB8GA1UdIwQYMBaAFOnoRFJTNlxLGJoR%2FEMYLKXcIIBIMFYG%0AA1UdHwRPME0wS6BJoEeGRWh0dHBzOi8vc2J4LWNlcnRpZmljYXRlcy50cnVzdGVk%0Ac2VydmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQU%0AWSPTp0qoY1QuOXCt4A8HK1ckKrcwDgYDVR0PAQH%2FBAQDAgEGMBIGA1UdEwEB%2FwQI%0AMAYBAf8CAQAwCgYIKoZIzj0EAwIDSAAwRQIhAJ1q%2BFTz%2BgUuVfBQuCgJsFrL2TTS%0Ae1aBZ53O52TjFie6AiAriPaRahUX9Oa9kGLlAchWXKT6j4RWSR50BqhrN3UT4A%3D%3D%0A-----END%20CERTIFICATE-----%0A-----BEGIN%20CERTIFICATE-----%0AMIIClDCCAjmgAwIBAgIVAOnoRFJTNlxLGJoR%2FEMYLKXcIIBIMAoGCCqGSM49BAMC%0AMGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD%0Ab3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw%0ACQYDVQQGEwJVUzAeFw0xOTEwMzEwOTQ5MjFaFw00OTEyMzEyMzU5NTlaMGgxGjAY%0ABgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3Jh%0AdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQswCQYDVQQG%0AEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABE%2F6D%2F1WHNrWwPmNMIyBKMW5%0AJ6JzMsjo6xP2vkK1cdZGb1PGRP%2FC%2F8ECgiDkmklmzwLzLi%2B000m7LLrtKJA3oC2j%0Agb8wgbwwHwYDVR0jBBgwFoAU6ehEUlM2XEsYmhH8QxgspdwggEgwVgYDVR0fBE8w%0ATTBLoEmgR4ZFaHR0cHM6Ly9zYngtY2VydGlmaWNhdGVzLnRydXN0ZWRzZXJ2aWNl%0Acy5pbnRlbC5jb20vSW50ZWxTR1hSb290Q0EuZGVyMB0GA1UdDgQWBBTp6ERSUzZc%0ASxiaEfxDGCyl3CCASDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH%2FBAgwBgEB%2FwIB%0AATAKBggqhkjOPQQDAgNJADBGAiEAzw9zdUiUHPMUd0C4mx41jlFZkrM3y5f1lgnV%0AO7FbjOoCIQCoGtUmT4cXt7V%2BySHbJ8Hob9AanpvXNH1ER%2B%2FgZF%2BopQ%3D%3D%0A-----END%20CERTIFICATE-----%0A")
		respHeader.Add("SGX-PCK-Certificate-CA-Type", "platform")
		respHeader.Add("SGX-FMSPC", "10606A000000")

		respHeader.Add("Sgx-Pck-Crl-Issuer-Chain", "-----BEGIN%20CERTIFICATE-----%0AMIIE9DCCBJqgAwIBAgIUb6rZwuxZc5cIkp6%2Foqqz7HdGyFwwCgYIKoZIzj0EAwIw%0AcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBQbGF0Zm9ybSBDQTEaMBgGA1UECgwR%0ASW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQI%0ADAJDQTELMAkGA1UEBhMCVVMwHhcNMjIwNjIxMTEyNDU2WhcNMjkwNjIxMTEyNDU2%0AWjBwMSIwIAYDVQQDDBlJbnRlbCBTR1ggUENLIENlcnRpZmljYXRlMRowGAYDVQQK%0ADBFJbnRlbCBDb3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNV%0ABAgMAkNBMQswCQYDVQQGEwJVUzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABOB3%0AWFm1ziJAlu79StgxfAuz8AWCkoiraneuAGgrFExeiukczJvjWdtDTM2O7w8GiZAt%0A1h84AyDRUb%2BHoNaflACjggMQMIIDDDAfBgNVHSMEGDAWgBRZI9OnSqhjVC45cK3g%0ADwcrVyQqtzBvBgNVHR8EaDBmMGSgYqBghl5odHRwczovL3NieC5hcGkudHJ1c3Rl%0AZHNlcnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92My9wY2tjcmw%2F%0AY2E9cGxhdGZvcm0mZW5jb2Rpbmc9ZGVyMB0GA1UdDgQWBBQ6mE6WHjgoVSRiUaG%2F%0A0QmQDpX7LjAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH%2FBAIwADCCAjkGCSqGSIb4%0ATQENAQSCAiowggImMB4GCiqGSIb4TQENAQEEEGzzoSC5Btq3aBE%2BWYxHhwUwggFj%0ABgoqhkiG%2BE0BDQECMIIBUzAQBgsqhkiG%2BE0BDQECAQIBATAQBgsqhkiG%2BE0BDQEC%0AAgIBATAQBgsqhkiG%2BE0BDQECAwIBADAQBgsqhkiG%2BE0BDQECBAIBADAQBgsqhkiG%0A%2BE0BDQECBQIBADAQBgsqhkiG%2BE0BDQECBgIBADAQBgsqhkiG%2BE0BDQECBwIBADAQ%0ABgsqhkiG%2BE0BDQECCAIBADAQBgsqhkiG%2BE0BDQECCQIBADAQBgsqhkiG%2BE0BDQEC%0ACgIBADAQBgsqhkiG%2BE0BDQECCwIBADAQBgsqhkiG%2BE0BDQECDAIBADAQBgsqhkiG%0A%2BE0BDQECDQIBADAQBgsqhkiG%2BE0BDQECDgIBADAQBgsqhkiG%2BE0BDQECDwIBADAQ%0ABgsqhkiG%2BE0BDQECEAIBADAQBgsqhkiG%2BE0BDQECEQIBCTAfBgsqhkiG%2BE0BDQEC%0AEgQQAQEAAAAAAAAAAAAAAAAAADAQBgoqhkiG%2BE0BDQEDBAIAADAUBgoqhkiG%2BE0B%0ADQEEBAYQYGoAAAAwDwYKKoZIhvhNAQ0BBQoBATAeBgoqhkiG%2BE0BDQEGBBDjJ4f6%0AieS5MJrtZWT28t9KMEQGCiqGSIb4TQENAQcwNjAQBgsqhkiG%2BE0BDQEHAQEB%2FzAQ%0ABgsqhkiG%2BE0BDQEHAgEBADAQBgsqhkiG%2BE0BDQEHAwEB%2FzAKBggqhkjOPQQDAgNI%0AADBFAiBJwRZ5Dkvmz41SMH%2FFojZqiPxfzpQo78iqcvTdo0DwTQIhAPzZkuFcwZUV%0Al0yBja8lgLWp%2F8eMKpx5hOAw1dDV2iST%0A-----END%20CERTIFICATE-----%0A")

		return &http.Response{
			StatusCode:    c.ResponseCode,
			ContentLength: 9147,
			Body:          ioutil.NopCloser(bytes.NewReader(responseBody)),
			Header:        respHeader,
		}, nil
	default:
		return &http.Response{
			StatusCode: c.ResponseCode,
		}, nil
	}
}
