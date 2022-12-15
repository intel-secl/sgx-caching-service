/*
 * Copyright (C) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package resource

import (
	"intel/isecl/scs/v5/repository/postgres/mock"
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

var testTcbInfoJson = []byte(`{
	"tcbInfo": {
		"version": 2,
		"issueDate": "2020-06-15T06:42:01Z",
		"nextUpdate": "2020-07-15T06:42:01Z",
		"fmspc": "20606a000000",
		"pceId": "0000",
		"tcbType": 0,
		"tcbEvaluationDataNumber": 5,
		"tcbLevels": [
			{
				"tcb": {
					"sgxtcbcomp01svn": 2,
					"sgxtcbcomp02svn": 2,
					"sgxtcbcomp03svn": 0,
					"sgxtcbcomp04svn": 0,
					"sgxtcbcomp05svn": 0,
					"sgxtcbcomp06svn": 0,
					"sgxtcbcomp07svn": 0,
					"sgxtcbcomp08svn": 0,
					"sgxtcbcomp09svn": 0,
					"sgxtcbcomp10svn": 0,
					"sgxtcbcomp11svn": 0,
					"sgxtcbcomp12svn": 0,
					"sgxtcbcomp13svn": 0,
					"sgxtcbcomp14svn": 0,
					"sgxtcbcomp15svn": 0,
					"sgxtcbcomp16svn": 0,
					"pcesvn": 10
				},
				"tcbDate": "2020-05-28T00:00:00Z",
				"tcbStatus": "UpToDate"
			},
			{
				"tcb": {
					"sgxtcbcomp01svn": 1,
					"sgxtcbcomp02svn": 1,
					"sgxtcbcomp03svn": 0,
					"sgxtcbcomp04svn": 0,
					"sgxtcbcomp05svn": 0,
					"sgxtcbcomp06svn": 0,
					"sgxtcbcomp07svn": 0,
					"sgxtcbcomp08svn": 0,
					"sgxtcbcomp09svn": 0,
					"sgxtcbcomp10svn": 0,
					"sgxtcbcomp11svn": 0,
					"sgxtcbcomp12svn": 0,
					"sgxtcbcomp13svn": 0,
					"sgxtcbcomp14svn": 0,
					"sgxtcbcomp15svn": 0,
					"sgxtcbcomp16svn": 0,
					"pcesvn": 9
				},
				"tcbDate": "2020-03-22T00:00:00Z",
				"tcbStatus": "OutOfDate"
			},
			{
				"tcb": {
					"sgxtcbcomp01svn": 1,
					"sgxtcbcomp02svn": 1,
					"sgxtcbcomp03svn": 0,
					"sgxtcbcomp04svn": 0,
					"sgxtcbcomp05svn": 0,
					"sgxtcbcomp06svn": 0,
					"sgxtcbcomp07svn": 0,
					"sgxtcbcomp08svn": 0,
					"sgxtcbcomp09svn": 0,
					"sgxtcbcomp10svn": 0,
					"sgxtcbcomp11svn": 0,
					"sgxtcbcomp12svn": 0,
					"sgxtcbcomp13svn": 0,
					"sgxtcbcomp14svn": 0,
					"sgxtcbcomp15svn": 0,
					"sgxtcbcomp16svn": 0,
					"pcesvn": 0
				},
				"tcbDate": "2020-03-22T00:00:00Z",
				"tcbStatus": "OutOfDate"
			}
		]
	},
	"signature": "40b3536ee9c7028df7f0a976eaa405bc82768a258512be95fd151731f756f20a35c4a2642b91ba8083dca067932af75f1f92265dbdbd12573b05a959f6e3a677"
}`)

var qeInfo = []byte(`{
	"enclaveIdentity": {
		"id": "QE",
		"version": 2,
		"issueDate": "2020-06-15T06:42:01Z",
		"nextUpdate": "2020-07-15T06:42:01Z",
		"tcbEvaluationDataNumber": 5,
		"miscselect": "00000000",
		"miscselectMask": "FFFFFFFF",
		"attributes": "11000000000000000000000000000000",
		"attributesMask": "FBFFFFFFFFFFFFFF0000000000000000",
		"mrsigner": "8C4F5775D796503E96137F77C68A829A0056AC8DED70140B081B094490C57BFF",
		"isvprodid": 1,
		"tcbLevels": [
			{
				"tcb": {
					"isvsvn": 2
				},
				"tcbDate": "2019-05-15T00:00:00Z",
				"tcbStatus": "UpToDate"
			},
			{
				"tcb": {
					"isvsvn": 1
				},
				"tcbDate": "2018-08-15T00:00:00Z",
				"tcbStatus": "OutOfDate"
			}
		]
	},
	"signature": "2c50f0f4297781594e4d86c864ef1bd6797ab77566c9ddc417330ca7f37456f2f998a44e8230c57c2c8f51258ce5044cf0ac0af58e5c953e466f51981dc1390c"
}`)

func TestResource(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Resource Suite")
}

func getMockDatabase() *mock.MockDatabase {
	db := &mock.MockDatabase{
		MockPlatformRepository:     mock.NewMockPlatformRepository(),
		MockPlatformTcbRepository:  mock.NewMockPlatformTcbRepository(),
		MockFmspcTcbInfoRepository: mock.NewMockFmspcTcbInfoRepository(),
		MockPckCertChainRepository: mock.NewMockPckCertChainRepository(),
		MockPckCertRepository:      mock.NewMockPckCertRepository(),
		MockPckCrlRepository:       mock.NewMockPckCrlRepository(),
		MockLastRefreshRepository:  mock.NewMockLastRefreshRepository(),
		MockQEIdentityRepository:   mock.NewMockQEIdentityRepository(),
	}

	return db
}
