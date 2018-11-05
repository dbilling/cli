// +build pkcs11

package client

import (
	"fmt"

	"github.com/theupdateframework/notary"
	"github.com/theupdateframework/notary/trustmanager"
// removed for now...	"github.com/theupdateframework/notary/trustmanager/yubikey"
	"github.com/theupdateframework/notary/trustmanager/grpckeystore"
)

func getKeyStores(baseDir string, retriever notary.PassRetriever) ([]trustmanager.KeyStore, error) {
	fileKeyStore, err := trustmanager.NewKeyFileStore(baseDir, retriever)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key store in directory: %s", baseDir)
	}
	keyStores := []trustmanager.KeyStore{fileKeyStore}


	grpcKeyStore, err := grpckeystore.NewGRPCKeyStore()
	if err == nil {
	  keyStores = []trustmanager.KeyStore{grpcKeyStore, fileKeyStore}
		fmt.Println("-------------------")
		fmt.Printf("GRPCKeyStore connected and in use\n")
  } else {
		fmt.Println("-------------------")
		fmt.Printf("GRPCKeyStore disabled, connection error:%s\n", err)
	}
  // TODO:  restore all this so yubikeys work too!
	//	if yubiKeyStore != nil {
	//		keyStores = []trustmanager.KeyStore{yubiKeyStore, fileKeyStore}
	//	}
//	yubiKeyStore, _ := yubikey.NewYubiStore(fileKeyStore, retriever)
//	if yubiKeyStore != nil {
//		keyStores = []trustmanager.KeyStore{yubiKeyStore, fileKeyStore}
//	}
	return keyStores, nil
}
