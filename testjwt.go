package main

import (
	"encoding/pem"
	"fmt"
	"intel/isecl/lib/common/jwt"
	"intel/isecl/lib/common/crypt"
	cos "intel/isecl/lib/common/os"
	ct "intel/isecl/lib/common/types/aas"

	"os"
)

func (a* App) GenerateCertRequest() error {
	fmt.Println("Inside the TestTokenAuth Function")

	cert, privKeyDer, err := crypt.CreateKeyPairAndCertificateRequest("SCS JWT Signing", "", "", 0)
	if err != nil {
		return err
	}


	if err := pem.Encode(os.Stdout, &pem.Block{Type: "PKCS8 PRIVATE KEY", Bytes: privKeyDer}); err != nil {
		return fmt.Errorf("could not pem encode the private key: %v", err)
	}


	if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: cert}); err != nil {
		return fmt.Errorf("could not pem encode certificate request: %v", err)
	}
	return nil

}


func (a *App) TestTokenAuth() error {
	fmt.Println("Inside the TestTokenAuth Function")

	cert, privKeyDer, err := crypt.CreateKeyPairAndCertificate("SCS JWT Signing", "", "", 0)
	if err != nil {
		return err
	}
	
	//todo - after testing funnctionality writing to file, uncomment section as we have to create file in a particular dir
	/*
	err = os.MkdirAll(constants.TokenSignKeysAndCertDir, os.ModeDir)
	if err != nil {
		return err
	}
	// marshal private key to disk
	keyOut, err := os.OpenFile(constants.TokenSignKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0) // open file with restricted permissions
	if err != nil {
		return fmt.Errorf("tls setup: %v", err)
	}
	// private key should not be world readable
	os.Chmod(constants.TokenSignKeyFile, 0640)
	defer keyOut.Close()
	*/
	 
	if err := pem.Encode(os.Stdout, &pem.Block{Type: "PKCS8 PRIVATE KEY", Bytes: privKeyDer}); err != nil {
		return fmt.Errorf("could not pem encode the private key: %v", err)
	}
	
	//if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: certReq}); err != nil {
	//	return fmt.Errorf("could not pem encode certificate request: %v", err)
	//}

	if err := pem.Encode(os.Stdout, &pem.Block{Type: "CERTIFICATE", Bytes: cert}); err != nil {
		return fmt.Errorf("could not pem encode certificate request: %v", err)
	}

	certPemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert})

	factory, err := jwtauth.NewTokenFactory(privKeyDer, true, certPemBytes, "AAS JWT Signing", 0)
	if err != nil {
		fmt.Println(err)
		return err
	}
	ur := []ct.RoleInfo {ct.RoleInfo{"CMS","CertificateRequester","CN:aas.isecl.intel.com"}, ct.RoleInfo{"TDS","HostUpdater","HostA"}, ct.RoleInfo{"WLS","Administrator",""}}
	claims := ct.RoleSlice{ur}
	fmt.Println(claims)
	jwt, err := factory.Create(&claims,"Vinil's JWT", 0)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("\nJWT :",jwt)
	fmt.Printf("\n\n\n Token Generation Complete. Testing Token verification and retrieving claims\n\n\n")
	if err := a.ValidateToken(certPemBytes, jwt); err != nil{
		return err
	}
	fmt.Printf("\n\n Token Validation Complete.\n\n")
	return nil

}


func (a *App) ValidateToken(certPem []byte, jwtString string) error {
	v, err := jwtauth.NewVerifier(certPem, [][]byte{})
	if err != nil {
		return err
	}
	claims := ct.RoleSlice{}
	_, err = v.ValidateTokenAndGetClaims(jwtString, &claims)
	if err != nil {
		if noCertErr, ok := err.(*jwtauth.MatchingCertNotFoundError); ok {
			//fmt.Println(noCertErr)
			fmt.Println("Matching Certificate hash not found. Try to pull down and save the certificate now", noCertErr)
		}
		return err
	}
	fmt.Println(claims)

	return nil
}


func (a* App) PrintDirFileContents(dir string) error {
	if dir == "" {
		return fmt.Errorf("PrintDirFileContents needs a directory path to look for files")
	}
	data, err := cos.GetDirFileContents(dir, "")
	if err != nil {
		return err
	}
	for i, fileData := range data {
		fmt.Println("File :", i)
		fmt.Printf("%s",fileData)
	}
	return nil
}
