/*
 * Copyright (C) 2020 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	commLog "intel/isecl/lib/common/v3/log"
	commLogMsg "intel/isecl/lib/common/v3/log/message"
	"intel/isecl/scs/v3/repository"
	"intel/isecl/scs/v3/types"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
)

var log = commLog.GetDefaultLogger()
var slog = commLog.GetSecurityLogger()

type PostgresDatabase struct {
	DB *gorm.DB
}

func (pd *PostgresDatabase) Migrate() error {
	pd.DB.AutoMigrate(types.Platform{})
	pd.DB.AutoMigrate(types.PlatformTcb{})
	pd.DB.AutoMigrate(types.PckCertChain{})
	pd.DB.AutoMigrate(types.PckCert{})
	pd.DB.AutoMigrate(types.PckCrl{})
	pd.DB.AutoMigrate(types.FmspcTcbInfo{})
	pd.DB.AutoMigrate(types.QEIdentity{})
	return nil
}

func (pd *PostgresDatabase) PlatformRepository() repository.PlatformRepository {
	return &PostgresPlatformRepository{db: pd.DB}
}

func (pd *PostgresDatabase) PlatformTcbRepository() repository.PlatformTcbRepository {
	return &PostgresPlatformTcbRepository{db: pd.DB}
}

func (pd *PostgresDatabase) FmspcTcbInfoRepository() repository.FmspcTcbInfoRepository {
	return &PostgresFmspcTcbInfoRepository{db: pd.DB}
}

func (pd *PostgresDatabase) PckCertChainRepository() repository.PckCertChainRepository {
	return &PostgresPckCertChainRepository{db: pd.DB}
}

func (pd *PostgresDatabase) PckCertRepository() repository.PckCertRepository {
	return &PostgresPckCertRepository{db: pd.DB}
}

func (pd *PostgresDatabase) PckCrlRepository() repository.PckCrlRepository {
	return &PostgresPckCrlRepository{db: pd.DB}
}

func (pd *PostgresDatabase) QEIdentityRepository() repository.QEIdentityRepository {
	return &PostgresQEIdentityRepository{db: pd.DB}
}

func (pd *PostgresDatabase) Close() {
	if pd.DB != nil {
		err := pd.DB.Close()
		if err != nil {
			log.WithError(err).Error("failed to close the scs db")
		}
	}
}

func Open(host string, port int, dbname, user, password, sslMode, sslCert string) (*PostgresDatabase, error) {
	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	if sslMode != "allow" && sslMode != "prefer" && sslMode != "require" && sslMode != "verify-ca" {
		sslMode = "verify-full"
	}

	var sslCertParams string
	if sslMode == "verify-ca" || sslMode == "verify-full" {
		sslCertParams = " sslrootcert=" + sslCert
	}

	var db *gorm.DB
	var dbErr error
	const numAttempts = 4
	for i := 0; i < numAttempts; i = i + 1 {
		const retryTime = 1
		db, dbErr = gorm.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s%s",
			host, port, user, dbname, password, sslMode, sslCertParams))
		if dbErr != nil {
			log.WithError(dbErr).Infof("Failed to connect to DB, retrying attempt %d/%d", i+1, numAttempts)
		} else {
			break
		}
		time.Sleep(retryTime * time.Second)
	}
	if dbErr != nil {
		log.WithError(dbErr).Infof("Failed to connect to db after %d attempts\n", numAttempts)
		slog.Errorf("%s: Failed to connect to db after %d attempts", commLogMsg.BadConnection, numAttempts)
		return nil, dbErr
	}
	return &PostgresDatabase{DB: db}, nil
}
