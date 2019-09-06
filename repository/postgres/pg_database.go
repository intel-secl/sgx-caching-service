/*
 * Copyright (C) 2019 Intel Corporation
 * SPDX-License-Identifier: BSD-3-Clause
 */
package postgres

import (
	"fmt"
	"intel/isecl/sgx-caching-service/repository"
	"intel/isecl/sgx-caching-service/types"
	"io/ioutil"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	log "github.com/sirupsen/logrus"
)

type PostgresDatabase struct {
	DB *gorm.DB
}

func (pd *PostgresDatabase) ExecuteSql(sql *string) error {
	return pd.DB.Exec(*sql).Error
}

func (pd *PostgresDatabase) ExecuteSqlFile(file string) error {
	c, err := ioutil.ReadFile(file)
	if err != nil {
		return fmt.Errorf("could not read sql file - %s, error : %s", file, err.Error())
	}
	sql := string(c)
	if err := pd.ExecuteSql(&sql); err != nil {
		return fmt.Errorf(" could not execute contents of sql file %s, error :%s", file, err.Error())
	}
	return nil
}



func (pd *PostgresDatabase) Migrate() error {
	pd.DB.AutoMigrate(types.PlatformTcb{})
	pd.DB.AutoMigrate(types.PckCertChain{})
	pd.DB.AutoMigrate(types.PckCert{}).AddForeignKey("cert_chain_id", "pck_cert_chains(id)", "RESTRICT", "RESTRICT")
	pd.DB.AutoMigrate(types.PckCrl{})
	pd.DB.AutoMigrate(types.FmspcTcbInfo{})
	pd.DB.AutoMigrate(types.QEIdentity{})
	return nil
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
		pd.DB.Close()
	}
}

func Open(host string, port int, dbname, user, password, sslMode, sslCert string) (*PostgresDatabase, error) {

	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	if sslMode != "disable" && sslMode != "require" && sslMode != "allow" && sslMode != "prefer" && sslMode != "verify-ca" && sslMode != "verify-full" {
		sslMode = "require"
	}

	var sslCertParams string
	if sslMode == "verify-ca" || sslMode == "verify-full" {
		sslCertParams = " sslrootcert=" + sslCert
	}

	var db *gorm.DB
	var dbErr error
	const numAttempts = 4
	for i := 0; i < numAttempts; i = i + 1 {
		const retryTime = 5
		db, dbErr = gorm.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s%s",
			host, port, user, dbname, password, sslMode, sslCertParams))
		if dbErr != nil {
			log.WithError(dbErr).Infof("Failed to connect to DB, retrying attempt %d/%d", i, numAttempts)
		} else {
			break
		}
		time.Sleep(retryTime * time.Second)
	}
	if dbErr != nil {
		log.WithError(dbErr).Infof("Failed to connect to db after %d attempts\n", numAttempts)
		return nil, dbErr
	}
	return &PostgresDatabase{DB: db}, nil
}

func VerifyConnection(host string, port int, dbname, user, password, sslMode, sslCert string) error {

	sslMode = strings.TrimSpace(strings.ToLower(sslMode))
	if sslMode != "disable" && sslMode != "require" && sslMode != "allow" && sslMode != "prefer" && sslMode != "verify-ca" && sslMode != "verify-full" {
		sslMode = "require"
	}

	var sslCertParams string
	if sslMode == "verify-ca" || sslMode == "verify-full" {
		sslCertParams = " sslrootcert=" + sslCert
	}

	db, dbErr := gorm.Open("postgres", fmt.Sprintf("host=%s port=%d user=%s dbname=%s password=%s sslmode=%s%s",
		host, port, user, dbname, password, sslMode, sslCertParams))

	if dbErr != nil {
		return fmt.Errorf("could not connect to database - error : %s", dbErr.Error())
	}
	db.Close()
	return nil
}
