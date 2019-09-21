package tasks

import (
	"intel/isecl/lib/common/setup"
	"io"
)

type CMS struct {
	Flags         []string
	ConsoleWriter io.Writer
}

func (cms CMS) Run(c setup.Context) error {

	// save root ca to a file under TrustedCAsStoreDir with SavePemCertWithShortSha1FileName
	// save cert to const.TLSCertFile

	return nil
}

func (cms CMS) Validate(c setup.Context) error {

	return nil
}
