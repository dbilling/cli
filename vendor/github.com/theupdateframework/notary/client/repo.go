// +build !pkcs11

package client

import (
	"crypto/tls"
	"fmt"

	"github.com/theupdateframework/notary"
	"github.com/theupdateframework/notary/trustmanager"
	"github.com/theupdateframework/notary/trustmanager/grpckeystore"
)

func getKeyStores(baseDir string, retriever notary.PassRetriever,
	grpcKeyStoreConfig *grpckeystore.GRPCClientConfig) ([]trustmanager.KeyStore, error) {

	fileKeyStore, err := trustmanager.NewKeyFileStore(baseDir, retriever)

	fileKeyStore, err := trustmanager.NewKeyFileStore(baseDir, retriever)
	if err != nil {
		return nil, fmt.Errorf("failed to create private key store in directory: %s", baseDir)
	}
	keyStores := []trustmanager.KeyStore{fileKeyStore}

	// if there is a GRPC KeyStore in use, prepend it to the list
	if grpcKeyStoreConfig.Server != "" {
		grpcKeyStore, err = grpckeystore.NewGRPCKeyStore(grpcKeyStoreConfig)

 	  if err == nil {
			keyStores = append([]trustmanager.KeyStore{grpcKeyStore}, keyStores...)
			logrus.Debugf("GRPCKeyStore connection to %s succeeded", grpcKeyStoreConfig.Server)
		} else {
			logrus.Debugf("GRPCKeyStore connection attempt to %s failed:%s", grpcKeyStoreConfig.Server, err)
		}
	} else {
		logrus.Debug("No GRPCKeyStore server configured, using alternative key storage")
	}

	return keyStores, nil
}
