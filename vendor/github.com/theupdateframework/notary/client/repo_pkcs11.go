// +build pkcs11

package client

import (
	"fmt"

	"github.com/sirupsen/logrus"
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
		logrus.Debug("GRPCKeyStore connected and in use")
  } else {
		logrus.Debugf("GRPCKeyStore disabled, connection error:%s", err)
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
