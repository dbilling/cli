package grpckeystore

import (
	// "crypto/tls"
	"crypto"
	//"crypto/ecdsa"
	//"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"
	"encoding/asn1"
	"math/big"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/grpc"
	// "google.golang.org/grpc/credentials"
	"github.com/sirupsen/logrus"
	"github.com/theupdateframework/notary/trustmanager"
	"github.com/theupdateframework/notary/tuf/data"
  "github.com/theupdateframework/notary/tuf/signed"
  // "github.com/theupdateframework/notary/tuf/utils"
)

// DefaultTimeout is the time a request will block waiting for a response
// from the server if no other timeout is configured.
const DefaultTimeout = time.Second * 30

// RemoteKeyStore is a wrapper around the GRPC client, translating between
// the Go and GRPC APIs.
type GRPCKeyStore struct {
	client   GRPCKeyStoreClient
	location string
	timeout  time.Duration
	keys          map[string]GRPCKey
}

// GRPCKey represents a remote key stored in the local key map
type GRPCKey struct {
	gun    data.GUN
	role   data.RoleName
	remoteKeyId string
}

// GRPCPrivateKey represents a private key from the remote key store
type GRPCPrivateKey struct {
	data.ECDSAPublicKey
	remoteKeyId string
	store *GRPCKeyStore
}

// GRPCkeySigner wraps a GRPCPrivateKey and implements the crypto.Signer interface
type GRPCkeySigner struct {
	GRPCPrivateKey
}

// NewGRPCPrivateKey returns a GRPCPrivateKey, which implements the data.PrivateKey
// interface except that the private material is inaccessible
func NewGRPCPrivateKey(remoteID string, store *GRPCKeyStore, pubKey data.ECDSAPublicKey) *GRPCPrivateKey {

	return &GRPCPrivateKey{
		ECDSAPublicKey:  pubKey,
		remoteKeyId:     remoteID,
		store:           store,
	}
}

// Public is a required method of the crypto.Signer interface
func (gs *GRPCkeySigner) Public() crypto.PublicKey {
	publicKey, err := x509.ParsePKIXPublicKey(gs.GRPCPrivateKey.Public())
	if err != nil {
		return nil
	}

	return publicKey
}

// CryptoSigner is a required method of the data.PrivateKey interfacere.
// Returns a crypto.Signer tha wraps the GRPCPrivateKey. Needed for
// Certificate generation only.
func (g *GRPCPrivateKey) CryptoSigner() crypto.Signer {
	return &GRPCkeySigner{GRPCPrivateKey: *g}
}

// Private is a required method of the data.PrivateKey interface
// is is not used for the remote store case
func (g *GRPCPrivateKey) Private() []byte {
	// We cannot return the private material from the remote store
	logrus.Debugf("GRPC remote key store: Invalid access for key: %s", g.ID())
	return nil
}

// SignatureAlgorithm is a required method of the data.PrivateKey interface.
// returns which algorithm this key uses to sign - currently
// hardcoded to ECDSA
// This will need updating as more key types are supported
func (g GRPCPrivateKey) SignatureAlgorithm() data.SigAlgorithm {
	return data.ECDSASignature
}

// Sign is a required method of the crypto.Signer interface and the data.PrivateKey
// interface
func (g *GRPCPrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) ([]byte, error) {
	v := signed.Verifiers[data.ECDSASignature]

  logrus.Debugf("GRPCkeystore Sign invoked for keyid: %s", g.ID())
  hash := sha256.Sum256(msg)
	var hashbytes []byte = hash[:]
	req := &SignReq{
		KeyId:              g.ID(),
		RemoteKeyId:        g.remoteKeyId,
		Message:            hashbytes,
	}

  s:= g.store
	ctx, cancel := s.getContext()
	defer cancel()
	rsp, err := s.client.Sign(ctx, req)

	if err != nil {
	  return nil, fmt.Errorf("GRPC Sign error: %s", rsp.DebugMsg)
	}

  // signature comes back as DER encoded.  TUF expects
  // just r and s concatenated together.  So we need to convert...
	type ecdsaSig struct {
		R *big.Int
		S *big.Int
	}
	ecdsasig := ecdsaSig{}
	_, err = asn1.Unmarshal(rsp.Signature, &ecdsasig)
  if err != nil {
		return nil, fmt.Errorf("failed to unmarshal ECDSA signature: %v", err)
  }
	rBytes, sBytes := ecdsasig.R.Bytes(), ecdsasig.S.Bytes()

	//ecdsaPubKey, ok := &g.ECDSAPublicKey.(*ecdsa.PublicKey)
	//if !ok {
	//	return nil, fmt.Errorf("Not working with a ECDSA public key")
	//}
  //octetLength := ((ecdsaPubKey.Params().BitSize + 7) >> 3)
	octetLength := 32 // hack!!!
	// MUST include leading zeros in the output
	rBuf := make([]byte, octetLength-len(rBytes), octetLength)
	sBuf := make([]byte, octetLength-len(sBytes), octetLength)
	rBuf = append(rBuf, rBytes...)
	sBuf = append(sBuf, sBytes...)
  sig := append(rBuf, sBuf...)

	err = v.Verify(&g.ECDSAPublicKey, sig, msg)
	if err != nil {
			return nil, fmt.Errorf("GRPC signature verfication error: %s", err)
	}
  logrus.Debug("GRPCkeystore Sign succeeded")
	return sig, nil
}

// NewGRPCKeyStore creates a GRPCKeyStore wrapping the provided
// RemoteKeyStore instance
func NewGRPCKeyStore() (*GRPCKeyStore, error) {

  var err error
  server := "127.0.0.1:10000"
	timeout := 5*time.Second

	cc, err := grpc.Dial(
		server,
		grpc.WithInsecure(),
		grpc.WithBlock(),
		grpc.WithTimeout(timeout),
	)
	if err != nil {
		return nil, err
	}

	ks := &GRPCKeyStore{
		client:   NewGRPCKeyStoreClient(cc),
		location: server,
		timeout:  timeout,
		keys:     make(map[string]GRPCKey),
  }

	ks.ListKeys() // populate keys field
  return ks, nil
}

// Name returns a user friendly name for the location this store
// keeps its data
func (s *GRPCKeyStore) Name() string {
	return "GRPC remote store"
}
// getContext returns a context with the timeout configured at initialization
// time of the RemoteStore.
func (s *GRPCKeyStore) getContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), s.timeout)
}

// Location returns a human readable indication of where the storage is located.
func (s *GRPCKeyStore) Location() string {
	return fmt.Sprintf("Remote Key Store @ %s", s.location)
}

// The following methods implement the PrivateKey inteface

// GetKeyInfo returns the corresponding gun and role key info for a keyID
func (s *GRPCKeyStore) GetKeyInfo(keyID string) (trustmanager.KeyInfo, error) {
	logrus.Debugf("GRPCKeystore GetKeyInfo invoked for keyID %s", keyID)
	logrus.Debug("GRPCKeystore GetKeyInfo not implemented")
	return trustmanager.KeyInfo{}, fmt.Errorf("Not yet implemented")
}

// GenerateKey requests that the keystore internally generate a key.
func (s *GRPCKeyStore) GenerateKey(keyInfo trustmanager.KeyInfo, algorithm string) (data.PrivateKey, error) {

  logrus.Debugf("GRPCKeystore GenerateKey invoked for role:%s gun:%s ", keyInfo.Role, keyInfo.Gun)
	// We only support generating root keys for now
	if keyInfo.Role != data.CanonicalRootRole {
		 logrus.Debugf("GRPC GenerateKey refused: currently only supporting root role, requested role:%s", keyInfo.Role)
		return nil, fmt.Errorf("GRPC keystore only supports generating root keys, got role %s", keyInfo.Role)
	}

	// TODO: support additional key types besides ecdsa
	if (algorithm != data.ECDSAKey) {
		return nil, fmt.Errorf("Currently Unsupported Key Type: %s", algorithm)
	}

	req := &MakeKeyReq{
		Gun:                string(keyInfo.Gun),
		Role:               string(keyInfo.Role),
		Algorithm:          algorithm,
		SignatureAlgorithm: algorithm,
	}
	ctx, cancel := s.getContext()
	defer cancel()
	rsp, err := s.client.MakeKey(ctx, req)

	if err != nil {
		return nil, fmt.Errorf("GRPC MakeKey error: %s", rsp.DebugMsg)
	}

  // The public key returned from the GRPC server is already expected
	// to be DER encoded.
	// TODO: support additional key types besides ecdsa...
	pubKey := data.NewECDSAPublicKey(rsp.PublicKey)
	privKey := NewGRPCPrivateKey(rsp.RemoteKeyId, s, *pubKey)
	if privKey == nil {
		return nil, fmt.Errorf("could not initialize new GRPCPrivateKey")
	}

	akreq := &AssociateKeyReq{
		KeyId:              privKey.ID(),
		RemoteKeyId:        privKey.remoteKeyId,
		Gun:                string(keyInfo.Gun),
		Role:               string(keyInfo.Role),
		Algorithm:          string(privKey.Algorithm()),
		SignatureAlgorithm: string(privKey.SignatureAlgorithm()),
	  PublicKey:          privKey.Public(),
	}
	ctx, cancel = s.getContext()
	defer cancel()
	akrsp, err := s.client.AssociateKey(ctx, akreq)

	if err != nil {
		return nil, fmt.Errorf("GRPC AssociateKey error: %s", akrsp.DebugMsg)
	}

	s.keys[privKey.ID()] = GRPCKey{
			gun:         keyInfo.Gun,
			role:        keyInfo.Role,
			remoteKeyId: rsp.RemoteKeyId,
	}

  logrus.Debugf("GRPC GenerateKey (MakeKey/AssociateKey Succeeded: %s", rsp.DebugMsg)
	return privKey, nil
}

// AddKey stores the contents of private key
func (s *GRPCKeyStore) AddKey(keyInfo trustmanager.KeyInfo, privKey data.PrivateKey) error {


	logrus.Debugf("GRPCKeystore AddKey invoked for role:%s gun:%s ", keyInfo.Role, keyInfo.Gun)

	// TODO:  currently for prototype, we don't do addkey
	if keyInfo.Role != "" {
	 logrus.Debug("GRPC AddKey operation is currently disabled", keyInfo.Role, keyInfo.Gun)
		return fmt.Errorf("Not supported yet")
	}

	// We only allow adding root keys for now
	if keyInfo.Role != data.CanonicalRootRole {
		return fmt.Errorf("GRPC keystore only supports storing root keys, got %s for key: %s", keyInfo.Role, privKey.ID())
	}

	req := &AddKeyReq{
		KeyId:              privKey.ID(),
		Gun:                string(keyInfo.Gun),
		Role:               string(keyInfo.Role),
		Algorithm:          string(privKey.Algorithm()),
		SignatureAlgorithm: string(privKey.SignatureAlgorithm()),
	  PublicKey:          privKey.Public(),
		PrivateKey:         privKey.Private(),
	}
	ctx, cancel := s.getContext()
	defer cancel()
	rsp, err := s.client.AddKey(ctx, req)

  if err != nil {
		return fmt.Errorf("GRPC AddKey error: %s", rsp.DebugMsg)
	}

	s.keys[privKey.ID()] = GRPCKey{
			gun:         keyInfo.Gun,
			role:        keyInfo.Role,
			remoteKeyId: rsp.RemoteKeyId,
	}

  logrus.Debugf("GRPC AddKey Operation Succeeded: %s", rsp.DebugMsg)
	return nil
}

// GetKey returns the PrivateKey given a KeyID
func (s *GRPCKeyStore) GetKey(keyID string) (data.PrivateKey, data.RoleName, error) {

	logrus.Debugf("GRPCkeystore GetKey operation called for keyId: %s", keyID)
	key, ok := s.keys[keyID]
	if !ok {
		return nil, "", trustmanager.ErrKeyNotFound{KeyID: keyID}
	}

	req := &GetKeyReq{
	  KeyId:              keyID,
		RemoteKeyId:        key.remoteKeyId,
	}
	ctx, cancel := s.getContext()
	defer cancel()
	rsp, err := s.client.GetKey(ctx, req)

	if err != nil {
		return nil, "", fmt.Errorf("GRPC GetKey error: %s", rsp.DebugMsg)
	}

	// The public key returned from the GRPC server is already expected
	// to be ASN.1 DER encoded, which is the format NewECDSAPublic key wants
	// TODO: support additional key types besides ecdsa...
	if (rsp.Algorithm != data.ECDSAKey) {
		return nil, "", fmt.Errorf("Currently Unsupported Key Type: %s", rsp.Algorithm)
	}
	pubKey := data.NewECDSAPublicKey(rsp.PublicKey)
	privKey := NewGRPCPrivateKey(key.remoteKeyId, s, *pubKey)
	if privKey == nil {
		return nil, "", fmt.Errorf("could not initialize new GRPCdata.RoleName(rsp.Role)")
	}
	logrus.Debugf("GRPC GetKey operation succeeded for role: %s", rsp.Role)
	return privKey, data.RoleName(rsp.Role), err
}

func buildKeyMap(keys map[string]GRPCKey) map[string]trustmanager.KeyInfo {
	res := make(map[string]trustmanager.KeyInfo)
	for k, v := range keys {
		res[k] = trustmanager.KeyInfo{Role: v.role, Gun: v.gun}
	}
	return res
}

// ListKeys returns a list of unique PublicKeys present on the KeyFileStore, by returning a copy of the keyInfoMap
func (s *GRPCKeyStore) ListKeys() map[string]trustmanager.KeyInfo {
	logrus.Debug("GRPCkeystore ListKeys operation invoked")
	if len(s.keys) > 0 {
	return buildKeyMap(s.keys)
  }

  keys := make(map[string]GRPCKey)

	req := &ListKeysReq{}
	ctx, cancel := s.getContext()
	defer cancel()
	rsp, err := s.client.ListKeys(ctx, req)


	if err != nil {
		logrus.Debugf("GRPC ListKeys error: %s", rsp.DebugMsg)
		return nil
	}

	rspkeys := rsp.GetKeyData()
	if len(rspkeys) > 0 {
		for _, ki := range rspkeys {
			keys[ki.GetKeyId()] = GRPCKey{
					gun:         data.GUN(ki.GetGun()),
					role:        data.RoleName(ki.GetRole()),
					remoteKeyId: ki.GetRemoteKeyId(),
			}
		}
	} else {
			// no keys found
	}
	s.keys = keys
	logrus.Debugf("GRPCKeystore ListKeys returned %d keys", len(keys))
	return buildKeyMap(keys)
}

// RemoveKey removes the key from the keyfilestore
func (s *GRPCKeyStore) RemoveKey(keyID string) error {
	logrus.Debug("GRPCkeystore RemoveKey operation invoked")
	logrus.Debug("GRPCkeystore RemoveKey not yet supported")
	return nil
}
