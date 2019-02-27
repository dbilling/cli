package grpckeystore

import (
	"net"
  "testing"


	"crypto"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"io/ioutil"
	"path/filepath"
	"runtime"


	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"github.com/sirupsen/logrus"
  "github.com/stretchr/testify/require"
)

type TestError struct{}

type GRPCServerKeyStore struct {
}

// NewGRPCServerKeyStore instantiates a new GRPC keystore server
func NewGRPCKeyStoreServer() *GRPCServer {
	return &GRPCServerKeyStore{
	}
}

func getCertsDir(t *testing.T) string {
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(file)
	certsDir := filepath.Join(dir, "../../fixtures/")
	return certsDir
}

func getServerTLS(t *testing.T) *tls.Config {
	certDir := getCertsDir(t)
	cert, err := tls.LoadX509KeyPair(
		filepath.Join(certDir, "notary-escrow.crt"),
		filepath.Join(certDir, "notary-escrow.key"),
	)
	require.NoError(t, err)
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
}

func getClientTLS(t *testing.T) *tls.Config {
	certDir := getCertsDir(t)
	pool := x509.NewCertPool()
	cert, err := ioutil.ReadFile(filepath.Join(certDir, "root-ca.crt"))
	require.NoError(t, err)
	pool.AppendCertsFromPEM(
		cert,
	)
	return &tls.Config{
		RootCAs: pool,
	}
}

func setupTestServer(t *testing.T, addr string) func() {
	s := grpc.NewServer(
		grpc.Creds(
			credentials.NewTLS(
				getServerTLS(t),
			),
		),
	)
	st := NewGRPCServerKeyStore()
	l, err := net.Listen(
		"tcp",
		st.addr,
	)
	require.NoError(t, err)
	RegisterGRPCKeyStoreServer(s, st)
	go func() {
		err := s.Serve(l)
		t.Logf("server errored %s", err)
	}()
	return func() {
		s.Stop()
		l.Close()
	}
}

func TestRemoteGRPCKeyStore(t *testing.T) {
	name := "testfile"
	bytes := []byte{'1'}
	addr := "localhost:9888"

	closer := setupTestServer(t, addr)
	defer closer()

  config = *GRPCClientConfig{
		Server:          "addr",
		TlsCertFile:     "",
		TlsKeyFile:      "",
	  TlsCAFile:       "",
		DialTimeout:      0,
		BlockingTimeout   0
	}

  // create the client
	c, err := NewGRPCKeyStore(config)
	require.NoError(t, err)

  // test the location string
	loc := c.Location()
	require.Equal(t, "Remote GRPC Key Store @ "+addr, loc)

	err = c.GenerateKey(keyInfo trustmanager.KeyInfo) (data.PrivateKey, error)
	require.NoError(t, err)
}


func (g *GRPCServer) Sign(ctx context.Context, msg *SignReq) ([]byte, error) {

  var err error = nil
   remoteKeyId
//	signature, err := TestGRPCServerSign(msg.KeyId, msg.RemoteKeyId, msg.Message)
  signature := [...]byte { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
	rsp := &SignRsp{
		Signature:          signature,
	}
	return rsp, err
}


func (g *GRPCServer) GenerateKey(ctx context.Context, msg *GenerateKeyReq) ([]byte, error) {


//	remoteKeyId, publicKey, algorithm, signatureAlgorithm, err := TestGRPCServerGenerateKey(msg.Gun, msg.Role)
  remoteKeyId := "1"
	publicKey := [...]byte { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }
	algorithm := "ecdsa"
	signatureAlgorithm = "ecdsa"

	rsp := &GenerateKeyRsp{
		RemoteKeyId:             remoteKeyId,
		PublicKey:               publicKey,
		Algorithm:               algorithm,
		SignatureAlgorithm:      signatureAlgorithm
	}
	return rsp, err
}

func (g *GRPCServer) AssociateKey(ctx context.Context, msg *AssociateKeyReq) ([]byte, error) {


	// err := TestGRPCServerAssociateKey(msg.RemoteKeyId, msg.KeyId)

		rsp := &AssociateKeyRsp{
		}
		return rsp, err
	}


// AddKey stores the contents of private key
func (g *GRPCServer) AddKey(ctx context.Context, msg *AddKeyReq) ([]byte, error) {


	// remoteKeyId, err := TestGRPCServerAddKey(msg.KeyId, msg.Gun, msg.Role, msg.Algorithm, msg.SignatureAlgorithm, msg.PublicKey, msg.PrivateKey)
	  remoteKeyId := "2"


		rsp := &AddKeyRsp{
			RemoteKeyId:             remoteKeyId,
		}
		return rsp, err
	}
}


// GetKey returns the PrivateKey given a KeyID
func (g *GRPCServer) GetKey(ctx context.Context, msg *GetKeyReq) ([]byte, error) {

//	role, algorithm, signatureAlgorithm, publicKey, err := TestGRPCServerGetKey(msg.KeyId, msg.RemoteKeyId)
  role := "root"
	algorithm := "ecdsa"
	signatureAlgorithm = "ecdsa"
	publicKey := [...]byte { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

	rsp := &GetKeyRsp{
		Role:                    role,
    Algorithm:               algorithm,
		SignatureAlgorithm:      signatureAlgorithm,
		PublicKey:               publicKey
	}
	return rsp, err
}


// ListKeys returns a list of unique PublicKeys present on the KeyFileStore
func (g *GRPCServer) ListKeys(ctx context.Context, msg *ListKeysReq) ([]byte, error) {


//	gun, role, remoteKeyId, err := TestGRPCServerListKeys()
//  gun := [...]string {"", "testgun"}
//  role := [...]string {"root","targets"}
//	remoteKeyId := [...]string {"1","2"}

// start with empty
	rsp := &ListKeysRsp{
		KeyData : {
		}
	}
	return rsp, err
}


// ListKeys returns a list of unique PublicKeys present on the KeyFileStore
func (g *GRPCServer) RemoveKey(ctx context.Context, msg *RemoveKeyReq) ([]byte, error) {


	rsp := &RemoveKeyRsp{
	}
	return rsp, err
}
