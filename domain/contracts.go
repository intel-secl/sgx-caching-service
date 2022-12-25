package domain

type BestPCKCertificate interface {
	GetBestPckCert() (uint8, error)
}
