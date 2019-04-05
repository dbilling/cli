package grpckeystore

import (
  "net"
  "testing"
  "crypto/rand"
  "crypto/tls"
  "crypto/x509"
  "fmt"
  "io/ioutil"
  "path/filepath"
  "runtime"
  "time"


  "golang.org/x/net/context"
  "google.golang.org/grpc"
  "google.golang.org/grpc/credentials"
  "google.golang.org/grpc/metadata"
  "github.com/stretchr/testify/require"

  "github.com/theupdateframework/notary/trustmanager"
  "github.com/theupdateframework/notary/tuf/data"
  "github.com/theupdateframework/notary/tuf/utils"
  testutils "github.com/theupdateframework/notary/tuf/testutils/keys"
)

const testMetadataKey = "testmetadatakey"
const testMetadataValue = "testmetadatavalue"

// TestKeyData allows verification of the data exchanged across the GRPC connection
type TestKeyData struct{
   keyInfo trustmanager.KeyInfo
   privateKey data.PrivateKey
   remoteKeyID string
   associated bool
   injectError string
}


func setupTestKey(t *testing.T, tks *map[string]TestKeyData, keyName string,
                   keyType string, role data.RoleName, gun string,
                   associated bool) (err error) {

  var testKeys = *tks
  var tkd TestKeyData
  tkd.keyInfo.Gun =  data.GUN(gun)
  tkd.keyInfo.Role = role
  tkd.remoteKeyID = keyName
  // associated indicates weather or not the key is  "live" in then
  // server.  false = key must be activated by GenerateKey or AddKey before use
  // true = we are simulating the case of keys previously stored in the repo
  tkd.associated = associated
  switch keyType {
    case data.RSAKey: {
     // GenerateKey won't generate a RSAKey, so to test RSA, use GetRSAKey.
     //  Note that GetRSAKey always returns the same key, so testing with two
     // RSA keys is not supported unless a different way to get a RSAKey is
     // developed. (both keys would have the same KeyID)
      tkd.privateKey, err = testutils.GetRSAKey(4096)
      require.NoError(t, err)
    }
    default: {
      tkd.privateKey, err = utils.GenerateKey(keyType)
      require.NoError(t, err)
    }
  }
  testKeys[keyName] = tkd
  return(err)
}

func setupTestServer(t *testing.T, config *TestServerConfig,
   testServerData *TestServerData,
   testKeys map[string]TestKeyData) func() {

  var opts []grpc.ServerOption

  if (config.tlsCertFile != "") && (config.tlsKeyFile != "") {
    opts = append(opts, grpc.Creds(credentials.NewTLS(getServerTLS(t, config))))
  }
  s := grpc.NewServer(opts...)
  st := NewGRPCKeyStoreSrvr(t, testServerData, testKeys)
  l, err := net.Listen(
    "tcp",
    config.addr,
  )
  require.NoError(t, err)
  RegisterGRPCKeyStoreServer(s, st)
  go func() {
    err := s.Serve(l)
    t.Logf("GRPCKeyStore Test Server error: %s", err)
  }()
  return func() {
    // waiting 100 milliseconds in the closer function allows the
    // client to stop before stopping server.  This can avoid a
    // "use of closed network connection" error from showing up
    // on the server.
    time.Sleep(100000000 * time.Nanosecond)
    s.GracefulStop()
    l.Close()
  }
}

func setupClientandServerConfig(t *testing.T, verifyServerCert bool, mutualAuth bool) (*TestServerConfig, *TestServerData, *GRPCClientConfig) {
    serverTLSCertFile := ""
    serverTLSKeyFile := ""
    serverTLSCAFile := ""
    clientTLSCertFile := ""
    clientTLSKeyFile := ""
    clientTLSCAFile := ""
    addr := "localhost:9888"

    // configure the server tls files.  use a client CA Cert only if
    // mutual auth is requested
    serverTLSCertFile = "notary-escrow.crt"
    serverTLSKeyFile = "notary-escrow.key"
    if mutualAuth {
      serverTLSCAFile = "root-ca.crt"
    }

    // setup the grpc server config
    serverConfig := TestServerConfig{
      addr:            addr,
      tlsCertFile:     serverTLSCertFile,
      tlsKeyFile:      serverTLSKeyFile,
      tlsCAFile:       serverTLSCAFile,
    }

    // configure the server tls files.  use a client cert and key only when
    // mutual auth is requested.  configure the CA file when verifyServerCert
    // is requested
    certDir := getCertsDir(t)
    if mutualAuth {
      clientTLSCertFile = filepath.Join(certDir,"notary-escrow.crt")
      clientTLSKeyFile = filepath.Join(certDir,"notary-escrow.key")
    }
    if verifyServerCert {
      clientTLSCAFile = filepath.Join(certDir, "root-ca.crt")
    }

    // setup the test server data -- this controls
    // error injection and metadata verification on the server
    testServerData := TestServerData{
      injectErrorGenerateKey:  false,
      injectErrorAssociateKey: false,
      injectErrorAddKey:       false,
      injectErrorListKeys:     false,
      injectErrorGetKey:       false,
      injectErrorRemoveKey:    false,
      injectErrorSign:         false,
      injectErrorStr:          "Test Error String",
      metadata:                metadata.Pairs("key1", "value1"),
    }

    // setup the grpc client config
    clientConfig := GRPCClientConfig{
      Server:          addr,
      TLSCertFile:     clientTLSCertFile,
      TLSKeyFile:      clientTLSKeyFile,
      TLSCAFile:       clientTLSCAFile,
      DialTimeout:     0,
      BlockingTimeout: 0,
      Metadata:        metadata.Pairs("key1", "value1"),
    }

    return &serverConfig, &testServerData, &clientConfig
}

// TestGenerateKey is a full test of GPRC keystore operations
// using GenerateKey to populate the keys
func TestGenerateKey(t *testing.T) {
  var tkd TestKeyData
  var err error
  testKeys := make(map[string]TestKeyData)

  // setup three ECDSA keys for this test
  err = setupTestKey(t, &testKeys, "testrootkey", data.ECDSAKey,
               data.CanonicalRootRole, "", false)
  err = setupTestKey(t, &testKeys, "testtargetkeygun1", data.ECDSAKey,
               data.CanonicalTargetsRole, "myreg.com/myorg/gun1", false)
  err = setupTestKey(t, &testKeys, "testtargetkeygun2", data.ECDSAKey,
               data.CanonicalTargetsRole, "myreg.com/myorg/gun2", false)
  require.NoError(t, err)

  serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

  // start the GRPC test server
  t.Log("Starting GRPC Server")
  closer := setupTestServer(t, serverConfig, testServerData, testKeys)
  defer closer()

  // start the client for testing
  t.Log("Starting GRPC Client")
  c, err := NewGRPCKeyStore(clientConfig)
  require.NoError(t, err)

  // test the location
  // loc := c.Location()
  // require.Equal(t, "Remote GRPC KeyStore @ "+addr, loc)

  // test the name
  name := c.Name()
  require.Equal(t, "GRPC remote store", name)

  //
  // ListKeys Test: Verify no keys
  //
  km := c.ListKeys()
  // verify zero keys returned
  require.Equal(t, 0, len(km))

  // GenerateKey Test for root key
  tkd = testKeys["testrootkey"]
  pk, err := c.GenerateKey(tkd.keyInfo)
  require.NoError(t, err)
  // chect that all response fields from the GRPC server match
  require.Equal(t, pk.Public(), tkd.privateKey.Public())
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  // check that the generated key was stored locally in the key list
  k := c.keys[pk.ID()]
  require.Equal(t, k.gun, tkd.keyInfo.Gun)
  require.Equal(t, k.role, tkd.keyInfo.Role)
  require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
  require.NoError(t, err)

  // GenerateKey for gun 1
  tkd = testKeys["testtargetkeygun1"]
  pk, err = c.GenerateKey(tkd.keyInfo)
  require.NoError(t, err)
  // chect that all response fields from the GRPC server match
  require.Equal(t, pk.Public(), tkd.privateKey.Public())
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  // check that the generated key was stored locally in the key list
  k = c.keys[pk.ID()]
  require.Equal(t, k.gun, tkd.keyInfo.Gun)
  require.Equal(t, k.role, tkd.keyInfo.Role)
  require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
  require.NoError(t, err)

  // GenerateKey for gun 2
  tkd = testKeys["testtargetkeygun2"]
  pk, err = c.GenerateKey(tkd.keyInfo)
  require.NoError(t, err)
  // check that all response fields from the GRPC server match
  require.Equal(t, pk.Public(), tkd.privateKey.Public())
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  // check that the generated key was stored locally in the key list
  k = c.keys[pk.ID()]
  require.Equal(t, k.gun, tkd.keyInfo.Gun)
  require.Equal(t, k.role, tkd.keyInfo.Role)
  require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
  require.NoError(t, err)

  // ListKeys - verifiy all three keys listed
  km = c.ListKeys()
  require.Equal(t, 3, len(km))
  // walk through the test keys, make sure they are all correct
  for i := range testKeys {
     tkd = testKeys[i]
     require.Equal(t, tkd.keyInfo, km[tkd.privateKey.ID()])
  }

  // GetKey for all three keys
  var role data.RoleName
  tkd = testKeys["testrootkey"]
  pk, role, err = c.GetKey(tkd.privateKey.ID())
  require.NoError(t, err)
  require.Equal(t, role, tkd.keyInfo.Role)
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  require.Equal(t, pk.Public(), tkd.privateKey.Public())

  tkd = testKeys["testtargetkeygun1"]
  pk, role, err = c.GetKey(tkd.privateKey.ID())
  require.NoError(t, err)
  require.Equal(t, role, tkd.keyInfo.Role)
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  require.Equal(t, pk.Public(), tkd.privateKey.Public())

  tkd = testKeys["testtargetkeygun2"]
  pk, role, err = c.GetKey(tkd.privateKey.ID())
  require.NoError(t, err)
  require.Equal(t, role, tkd.keyInfo.Role)
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  require.Equal(t, pk.Public(), tkd.privateKey.Public())

  // Test a Signing Operation...
  msg := []byte("Sign this data")
  _, err = pk.Sign(rand.Reader, msg, nil)
  require.NoError(t, err)

  // RemoveKey  for all three keys
  tkd = testKeys["testrootkey"]
  err = c.RemoveKey(string(tkd.privateKey.ID()))
  require.NoError(t, err)

  tkd = testKeys["testtargetkeygun1"]
  err = c.RemoveKey(string(tkd.privateKey.ID()))
  require.NoError(t, err)

  tkd = testKeys["testtargetkeygun2"]
  err = c.RemoveKey(string(tkd.privateKey.ID()))
  require.NoError(t, err)

  // ListKeys and Verify all keys deleted
  km = c.ListKeys()
  // verify zero keys returned
  require.Equal(t, 0, len(km))

  // close the client GRPC connection
  c.closeClient()
}

// TestAddKey is a full test of GPRC keystore operations
// using AddKey to populate the keys
func TestAddKey(t *testing.T) {
  var tkd TestKeyData
  var err error
  testKeys := make(map[string]TestKeyData)

  // setup three ECDSA keys for this test
  err = setupTestKey(t, &testKeys, "testrootkey", data.ECDSAKey,
               data.CanonicalRootRole, "", false)
  err = setupTestKey(t, &testKeys, "testtargetkeygun1", data.ECDSAKey,
               data.CanonicalTargetsRole, "myreg.com/myorg/gun1", false)
  err = setupTestKey(t, &testKeys, "testtargetkeygun2", data.ECDSAKey,
               data.CanonicalTargetsRole, "myreg.com/myorg/gun2", false)
  require.NoError(t, err)

  serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

  // start the GRPC test server
  t.Log("Starting GRPC Server")
  closer := setupTestServer(t, serverConfig, testServerData, testKeys)
  defer closer()

  // start the client for testing
  t.Log("Starting GRPC Client")
  c, err := NewGRPCKeyStore(clientConfig)
  require.NoError(t, err)

  //
  // ListKeys Test: Verify no keys
  //
  km := c.ListKeys()
  // verify zero keys returned
  require.Equal(t, 0, len(km))

  // AddKey Test for root key
  tkd = testKeys["testrootkey"]
  err = c.AddKey(tkd.keyInfo, tkd.privateKey)
  require.NoError(t, err)

  // check that the added key was stored locally in the key list
  k := c.keys[tkd.privateKey.ID()]
  require.Equal(t, k.gun, tkd.keyInfo.Gun)
  require.Equal(t, k.role, tkd.keyInfo.Role)
  require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
  require.NoError(t, err)

  // AddKey for gun 1
  tkd = testKeys["testtargetkeygun1"]
  err = c.AddKey(tkd.keyInfo, tkd.privateKey)
  require.NoError(t, err)

  // check that the added key was stored locally in the key list
  k = c.keys[tkd.privateKey.ID()]
  require.Equal(t, k.gun, tkd.keyInfo.Gun)
  require.Equal(t, k.role, tkd.keyInfo.Role)
  require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
  require.NoError(t, err)

  // AddKey for gun 2
  tkd = testKeys["testtargetkeygun2"]
  err = c.AddKey(tkd.keyInfo, tkd.privateKey)
  require.NoError(t, err)
  // check that the generated key was stored locally in the key list
  k = c.keys[tkd.privateKey.ID()]
  require.Equal(t, k.gun, tkd.keyInfo.Gun)
  require.Equal(t, k.role, tkd.keyInfo.Role)
  require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
  require.NoError(t, err)

  // ListKeys - verifiy all three keys listed
  km = c.ListKeys()
  require.Equal(t, 3, len(km))
  // walk through the test keys, make sure they are all correct
  for i := range testKeys {
     tkd = testKeys[i]
     require.Equal(t, tkd.keyInfo, km[tkd.privateKey.ID()])
  }

  // GetKey for all three keys
  var role data.RoleName
  tkd = testKeys["testrootkey"]
  pk, role, err := c.GetKey(tkd.privateKey.ID())
  require.NoError(t, err)
  require.Equal(t, role, tkd.keyInfo.Role)
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  require.Equal(t, pk.Public(), tkd.privateKey.Public())

  tkd = testKeys["testtargetkeygun1"]
  pk, role, err = c.GetKey(tkd.privateKey.ID())
  require.NoError(t, err)
  require.Equal(t, role, tkd.keyInfo.Role)
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  require.Equal(t, pk.Public(), tkd.privateKey.Public())

  tkd = testKeys["testtargetkeygun2"]
  pk, role, err = c.GetKey(tkd.privateKey.ID())
  require.NoError(t, err)
  require.Equal(t, role, tkd.keyInfo.Role)
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  require.Equal(t, pk.Public(), tkd.privateKey.Public())

  // Test a Signing Operation...
  // The Sign operation does verfication so we know the signature is good
  msg := []byte("Sign this data")
  _, err = pk.Sign(rand.Reader, msg, nil)
  require.NoError(t, err)

  // RemoveKey  for all three keys
  tkd = testKeys["testrootkey"]
  err = c.RemoveKey(string(tkd.privateKey.ID()))
  require.NoError(t, err)

  tkd = testKeys["testtargetkeygun1"]
  err = c.RemoveKey(string(tkd.privateKey.ID()))
  require.NoError(t, err)

  tkd = testKeys["testtargetkeygun2"]
  err = c.RemoveKey(string(tkd.privateKey.ID()))
  require.NoError(t, err)

  // ListKeys and Verify all keys deleted
  km = c.ListKeys()
  // verify zero keys returned
  require.Equal(t, 0, len(km))

  // close the client GRPC connection
  c.closeClient()
}

// TestKeysAlreadyInStore is a full test of GPRC keystore operations
// where the keys are already in the keystore.
func TestKeysAlreadyInStore(t *testing.T) {
  var tkd TestKeyData
  var err error
  testKeys := make(map[string]TestKeyData)

  // setup three _pre-enabled_ ECDSA keys for this test
  err = setupTestKey(t, &testKeys, "testrootkey", data.ECDSAKey,
               data.CanonicalRootRole, "", true)
  err = setupTestKey(t, &testKeys, "testtargetkeygun1", data.ECDSAKey,
               data.CanonicalTargetsRole, "myreg.com/myorg/gun1", true)
  err = setupTestKey(t, &testKeys, "testtargetkeygun2", data.ECDSAKey,
               data.CanonicalTargetsRole, "myreg.com/myorg/gun2", true)
  require.NoError(t, err)

  serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

  // start the GRPC test server
  t.Log("Starting GRPC Server")
  closer := setupTestServer(t, serverConfig, testServerData, testKeys)
  defer closer()

  // start the client for testing
  t.Log("Starting GRPC Client")
  c, err := NewGRPCKeyStore(clientConfig)
  require.NoError(t, err)


  // ListKeys - verifiy all three keys listed
  km := c.ListKeys()
  require.Equal(t, 3, len(km))
  // walk through the test keys, make sure they are all correct
  for i := range testKeys {
     tkd = testKeys[i]
     require.Equal(t, tkd.keyInfo, km[tkd.privateKey.ID()])
  }

  // GetKey for all three keys
  var role data.RoleName
  tkd = testKeys["testrootkey"]
  pk, role, err := c.GetKey(tkd.privateKey.ID())
  require.NoError(t, err)
  require.Equal(t, role, tkd.keyInfo.Role)
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  require.Equal(t, pk.Public(), tkd.privateKey.Public())

  tkd = testKeys["testtargetkeygun1"]
  pk, role, err = c.GetKey(tkd.privateKey.ID())
  require.NoError(t, err)
  require.Equal(t, role, tkd.keyInfo.Role)
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  require.Equal(t, pk.Public(), tkd.privateKey.Public())

  tkd = testKeys["testtargetkeygun2"]
  pk, role, err = c.GetKey(tkd.privateKey.ID())
  require.NoError(t, err)
  require.Equal(t, role, tkd.keyInfo.Role)
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  require.Equal(t, pk.Public(), tkd.privateKey.Public())

  // Test a Signing Operation...
  // The Sign operation does verfication so we know the signature is good
  msg := []byte("Sign this data")
  _, err = pk.Sign(rand.Reader, msg, nil)
  require.NoError(t, err)

  // RemoveKey  for all three keys
  tkd = testKeys["testrootkey"]
  err = c.RemoveKey(string(tkd.privateKey.ID()))
  require.NoError(t, err)

  tkd = testKeys["testtargetkeygun1"]
  err = c.RemoveKey(string(tkd.privateKey.ID()))
  require.NoError(t, err)

  tkd = testKeys["testtargetkeygun2"]
  err = c.RemoveKey(string(tkd.privateKey.ID()))
  require.NoError(t, err)

  // ListKeys and Verify all keys deleted
  km = c.ListKeys()
  // verify zero keys returned
  require.Equal(t, 0, len(km))

  // close the client GRPC connection
  c.closeClient()
}

// Test two different key types -- RSA & ECDSA
func TestKeyTypes(t *testing.T) {
  var tkd TestKeyData
  var err error
  testKeys := make(map[string]TestKeyData)

  // setup two keys for this test
  // use a RSA Key for the root key, and ecdsa for target
  err = setupTestKey(t, &testKeys, "testrootkey", data.RSAKey,
               data.CanonicalRootRole, "", false)
  // use an ecdsa Key for gun 1
  err = setupTestKey(t, &testKeys, "testtargetkeygun1", data.ECDSAKey,
               data.CanonicalTargetsRole, "myreg.com/myorg/gun1", false)
  require.NoError(t, err)

  serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

  // start the GRPC test server
  t.Log("Starting GRPC Server")
  closer := setupTestServer(t, serverConfig, testServerData, testKeys)
  defer closer()

  // start the client for testing
  t.Log("Starting GRPC Client")
  c, err := NewGRPCKeyStore(clientConfig)
  require.NoError(t, err)

  // test the location
  // loc := c.Location()
  // require.Equal(t, "Remote GRPC KeyStore @ "+addr, loc)

  // test the name
  name := c.Name()
  require.Equal(t, "GRPC remote store", name)

  //
  // ListKeys Test: Verify no keys
  //
  km := c.ListKeys()
  // verify zero keys returned
  require.Equal(t, 0, len(km))

  // GenerateKey Test for root key
  tkd = testKeys["testrootkey"]
  pk, err := c.GenerateKey(tkd.keyInfo)
  require.NoError(t, err)
  // chect that all response fields from the GRPC server match
  require.Equal(t, pk.Public(), tkd.privateKey.Public())
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  // check that the generated key was stored locally in the key list
  k := c.keys[pk.ID()]
  require.Equal(t, k.gun, tkd.keyInfo.Gun)
  require.Equal(t, k.role, tkd.keyInfo.Role)
  require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
  require.NoError(t, err)

  // GenerateKey for gun 1
  tkd = testKeys["testtargetkeygun1"]
  pk, err = c.GenerateKey(tkd.keyInfo)
  require.NoError(t, err)
  // chect that all response fields from the GRPC server match
  require.Equal(t, pk.Public(), tkd.privateKey.Public())
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  // check that the generated key was stored locally in the key list
  k = c.keys[pk.ID()]
  require.Equal(t, k.gun, tkd.keyInfo.Gun)
  require.Equal(t, k.role, tkd.keyInfo.Role)
  require.Equal(t, k.remoteKeyID, tkd.remoteKeyID)
  require.NoError(t, err)

  // ListKeys - verifiy all new keys are listed
  km = c.ListKeys()
  require.Equal(t, 2, len(km))
  // walk through the test keys, make sure they are all correct
  for i := range testKeys {
     tkd = testKeys[i]
     require.Equal(t, tkd.keyInfo, km[tkd.privateKey.ID()])
  }

  // GetKey and sign for each key
  var role data.RoleName
  tkd = testKeys["testrootkey"]
  pk, role, err = c.GetKey(tkd.privateKey.ID())
  require.NoError(t, err)
  require.Equal(t, role, tkd.keyInfo.Role)
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  require.Equal(t, pk.Public(), tkd.privateKey.Public())

  // Test a Signing Operation with the RSA key type
  msg := []byte("Sign this with RSA Key")
  _, err = pk.Sign(rand.Reader, msg, nil)
  require.NoError(t, err)

  tkd = testKeys["testtargetkeygun1"]
  pk, role, err = c.GetKey(tkd.privateKey.ID())
  require.NoError(t, err)
  require.Equal(t, role, tkd.keyInfo.Role)
  require.Equal(t, pk.Algorithm(), tkd.privateKey.Algorithm())
  require.Equal(t, pk.SignatureAlgorithm(), tkd.privateKey.SignatureAlgorithm())
  require.Equal(t, pk.Public(), tkd.privateKey.Public())

  // Test a Signing Operation with the ECDSA key type
  msg = []byte("Sign this with they ECDSA Key")
  _, err = pk.Sign(rand.Reader, msg, nil)
  require.NoError(t, err)

  // RemoveKey for all three keys
  tkd = testKeys["testrootkey"]
  err = c.RemoveKey(string(tkd.privateKey.ID()))
  require.NoError(t, err)

  tkd = testKeys["testtargetkeygun1"]
  err = c.RemoveKey(string(tkd.privateKey.ID()))
  require.NoError(t, err)

  // ListKeys and Verify all keys deleted
  km = c.ListKeys()
  // verify zero keys returned
  require.Equal(t, 0, len(km))

  // close the client GRPC connection
  c.closeClient()
}

// Test TLS - Server Auth
// Client configures root ca
// Server configures cert, key
func TestTLSServerAuth(t *testing.T) {
  var err error
  testKeys := make(map[string]TestKeyData)

  // setting verifyServerCert to true and mutualAuth to false
  serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

  // start the GRPC test server
  t.Log("Starting GRPC Server")
  closer := setupTestServer(t, serverConfig, testServerData, testKeys)
  defer closer()

  // start the client for testing
  t.Log("Starting GRPC Client")
  c, err := NewGRPCKeyStore(clientConfig)
  require.NoError(t, err)

  // close the client GRPC connection
  c.closeClient()
}


// Test TLS - Server with TLS but without Server Verification
// Client configures nothing
// Server configures cert, key
func TestTLSNoServerVerification(t *testing.T) {
  var err error
  testKeys := make(map[string]TestKeyData)

  // setting verifyServerCert to false is the key difference for this test
  serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, false, false)

  // start the GRPC test server
  t.Log("Starting GRPC Server")
  closer := setupTestServer(t, serverConfig, testServerData, testKeys)
  defer closer()

  // start the client for testing
  t.Log("Starting GRPC Client")
  c, err := NewGRPCKeyStore(clientConfig)
  require.NoError(t, err)

  // close the client GRPC connection
  c.closeClient()
}

// Test TLS - mutual authentication (also called client authentication)
// Client configures cert, key, and ca cert files
// Server configures cert, key, and ca cert files
// As a simplification, the same keys/certs are used in
// both directions to avoid having to make new keys/certs
func TestTLSMutualAuth(t *testing.T) {
  var err error
  testKeys := make(map[string]TestKeyData)

  // setting mutualAuth to true is the key difference for this test
  serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, false, false)

  // start the GRPC test server
  t.Log("Starting GRPC Server")
  closer := setupTestServer(t, serverConfig, testServerData, testKeys)
  defer closer()

  // start the client for testing
  t.Log("Starting GRPC Client")
  c, err := NewGRPCKeyStore(clientConfig)
  require.NoError(t, err)

  // close the client GRPC connection
  c.closeClient()
}

// Test TLS - no TLS on server case.  An error is expected in this case since
// the client does not allow the server to not have TLS configured.
// Client configures nothing
// Server configures nothing
func TestTLSNoTLSConfiguredError(t *testing.T) {
  var err error
  testKeys := make(map[string]TestKeyData)

  // start with minimum permissable config
  serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, false, false)

  // then reset the server config to nothing...
  serverConfig.tlsKeyFile = ""
  serverConfig.tlsCertFile = ""

  // start the GRPC test server
  t.Log("Starting GRPC Server")
  closer := setupTestServer(t, serverConfig, testServerData, testKeys)
  defer closer()

  // start the client, expecting client startup to fail
  t.Log("Starting GRPC Client")
  _, err = NewGRPCKeyStore(clientConfig)
  // we expect an error from TLS here...client doesn't allow an insecure server
  require.Error(t, err)
}

// TestErrorsFromServer
// Server will inject an error into each grpc response
func TestErrorsFromServer(t *testing.T) {
  var tkd TestKeyData
  var err error
  testKeys := make(map[string]TestKeyData)

  // use an ecdsa Key for error testing
  err = setupTestKey(t, &testKeys, "testerrorkey", data.ECDSAKey,
               data.CanonicalTargetsRole, "myreg.com/myorg/gun1", true)

  serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

  // start the GRPC test server
  t.Log("Starting GRPC Server")
  testServerData.injectErrorGenerateKey = true
  testServerData.injectErrorAddKey = true
  testServerData.injectErrorGetKey = true
  testServerData.injectErrorRemoveKey = true

  closer := setupTestServer(t, serverConfig, testServerData, testKeys)
  defer closer()

  // start the client
  t.Log("Starting GRPC Client")
  c, err := NewGRPCKeyStore(clientConfig)

  tkd = testKeys["testerrorkey"]
  // GenerateKey Error Test
  pk, err := c.GenerateKey(tkd.keyInfo)
  require.Equal(t, nil, pk)
  require.Error(t, err)

  // AddKey Error Test
  err = c.AddKey(tkd.keyInfo, tkd.privateKey)
  require.Error(t, err)

  // GetKey Error Test
  pk, _, err = c.GetKey(tkd.privateKey.ID())
  require.Error(t, err)
  require.Equal(t, nil, pk)

  err = c.RemoveKey(string(tkd.privateKey.ID()))
  require.Error(t, err)

  // close the client GRPC connection
  c.closeClient()
}

// TestMetadata
// Non-empty metadata is sent from client to server
func TestMetadata(t *testing.T) {
  var err error
  testKeys := make(map[string]TestKeyData)

  // use an ecdsa Key for error testing
  err = setupTestKey(t, &testKeys, "testkey", data.ECDSAKey,
               data.CanonicalTargetsRole, "myreg.com/myorg/gun1", true)
  require.NoError(t, err)
  serverConfig, testServerData, clientConfig := setupClientandServerConfig(t, true, false)

  // start the GRPC test server
  t.Log("Starting GRPC Server")
  testServerData.metadata = metadata.Pairs(testMetadataKey, testMetadataValue)

  closer := setupTestServer(t, serverConfig, testServerData, testKeys)
  defer closer()

  clientConfig.Metadata = metadata.Pairs(testMetadataKey, testMetadataValue)

  // start the client
  t.Log("Starting GRPC Client")
  c, err := NewGRPCKeyStore(clientConfig)

  // ListKeys verifies the metadata - if we see a key returned it means
  // the metadata matches
  km := c.ListKeys()
  require.Equal(t, 1, len(km))


  // close the client GRPC connection
  c.closeClient()
}

//
// In order to test the GRPC keystore client, we need a GRPC keystore server.
// The functions below implement a GRPC server testing harness that
// allows the tests above to work.
//
type TestServerConfig struct{
    addr  string
    tlsCertFile string
    tlsKeyFile string
    tlsCAFile string
}

type TestServerData struct{
  injectErrorGenerateKey  bool
  injectErrorAssociateKey bool
  injectErrorAddKey       bool
  injectErrorListKeys     bool
  injectErrorGetKey       bool
  injectErrorRemoveKey    bool
  injectErrorSign         bool
  injectErrorStr          string
  metadata                metadata.MD

}

type GRPCKeyStoreSrvr struct{
  testKeys map[string]TestKeyData
  testServerData *TestServerData
  t *testing.T
}

// Constants for log message formatting
const logReceivedMsgStr =  "GRPC KeyStore Server Recieved %T"
const logReturningMsgStr = "GRPC KeyStore Server Returning %T"
const logReturningErrorMsgStr = "GRPC KeyStore Server Returning an Error"

//  Normally false, changing this to true turns on verbose debugging logs for
//  the test server.  This may help when debugging failing tests.
func verboseServerDebug() (bool) {
  return(true)
}

// NewGRPCServerKeyStore instantiates a new GRPC keystore server
func NewGRPCKeyStoreSrvr(t *testing.T, testServerData *TestServerData,
  testKeys map[string]TestKeyData) *GRPCKeyStoreSrvr {

  st := &GRPCKeyStoreSrvr{
    testServerData:      testServerData,
    testKeys:            testKeys,
    t:                   t,
  }
  return st
}

func getCertsDir(t *testing.T) string {
  _, file, _, ok := runtime.Caller(0)
  require.True(t, ok)
  dir := filepath.Dir(file)
  certsDir := filepath.Join(dir, "../../fixtures/")
  return certsDir
}

func getServerTLS(t *testing.T, config *TestServerConfig) *tls.Config {
  var pool *x509.CertPool
  var clientAuth = tls.NoClientCert
  var cert tls.Certificate
  var err error

  certDir := getCertsDir(t)
  if (config.tlsCertFile != "")  &&  (config.tlsKeyFile != "") {
    cert, err = tls.LoadX509KeyPair(
      filepath.Join(certDir, config.tlsCertFile),
      filepath.Join(certDir, config.tlsKeyFile),
    )
    require.NoError(t, err)
  } else {
    // this is not a normal case -- used only to drive negative testing
    return &tls.Config{}
  }

  // MUTUAL AUTH CASE
  if   (config.tlsCAFile != "") {
    clientAuth = tls.RequireAndVerifyClientCert
    pool = x509.NewCertPool()
    cacert, err := ioutil.ReadFile(filepath.Join(certDir, config.tlsCAFile))
    require.NoError(t, err)
    pool.AppendCertsFromPEM(
      cacert,
    )
  }
  return &tls.Config{
    Certificates: []tls.Certificate{cert},
    ClientCAs: pool,
    ClientAuth: clientAuth,
  }
}

func (st *GRPCKeyStoreSrvr) GenerateKey(ctx context.Context, msg *GenerateKeyReq) (*GenerateKeyRsp, error) {
  var t = st.t
  var tsd = st.testServerData
  var tkd TestKeyData
  var err error
  var keyFound = false
  var rsp = &GenerateKeyRsp{}

  t.Logf(logReceivedMsgStr, msg)
  if verboseServerDebug() {
    t.Logf("     Gun: %s", msg.Gun)
    t.Logf("     Role: %s", msg.Role)
  }

  for _,tkd = range st.testKeys {
     if (msg.Role == string(tkd.keyInfo.Role)) && (msg.Gun == string(tkd.keyInfo.Gun)) {
        keyFound = true
        break
      }
  }

  if !keyFound {
    err = fmt.Errorf("Unable to locate matching testkey for role:%s gun:%s", msg.Role, msg.Gun)
    return rsp, err
  }


  // if an error injection is reqeusted for testing, return it now.
  if (tsd.injectErrorGenerateKey) {
    t.Logf(logReturningErrorMsgStr)
    err = fmt.Errorf(tsd.injectErrorStr)
  }

  rsp = &GenerateKeyRsp{
    RemoteKeyId:             tkd.remoteKeyID,
    PublicKey:               tkd.privateKey.Public(),
    Algorithm:               string(tkd.privateKey.Algorithm()),
    SignatureAlgorithm:      string(tkd.privateKey.SignatureAlgorithm()),
  }

  t.Logf(logReturningMsgStr, rsp)
  if verboseServerDebug() {
    t.Logf("     RemoteKeyId: %s", rsp.RemoteKeyId)
    t.Logf("     Alogrithm: %s", rsp.Algorithm)
    t.Logf("     SignatureAlgorithm: %s", rsp.SignatureAlgorithm)
    t.Logf("     PublicKey: %x", rsp.PublicKey)
  }
  return rsp, err
}

func (st *GRPCKeyStoreSrvr) AssociateKey(ctx context.Context, msg *AssociateKeyReq) (*AssociateKeyRsp, error) {
  var t = st.t
  var tsd = st.testServerData
  var err error
  var tkd TestKeyData
  var i string
  var keyFound = false
  var rsp = &AssociateKeyRsp{}

  t.Logf(logReceivedMsgStr, msg)
  if verboseServerDebug() {
    t.Logf("     KeyId: %s", msg.KeyId)
    t.Logf("     RemoteKeyId: %s", msg.RemoteKeyId)
  }

  for i, tkd = range st.testKeys {
     if (msg.RemoteKeyId == tkd.remoteKeyID) {
        keyFound = true
        break
      }
  }

  if !keyFound {
    err = fmt.Errorf("Unable to locate matching testkey for remotekeyid:%s", msg.RemoteKeyId)
    return rsp, err
  }

  // if an error injection is reqeusted for testing, return it now.
  if (tsd.injectErrorAssociateKey) {
    t.Logf(logReturningErrorMsgStr)
    err = fmt.Errorf(tsd.injectErrorStr)
  }

  // mark the key associated (in use) and update the map
  tkd.associated = true
  st.testKeys[i] = tkd

  t.Logf(logReturningMsgStr, rsp)

  return rsp, err
}

func (st *GRPCKeyStoreSrvr) AddKey(ctx context.Context, msg *AddKeyReq) (*AddKeyRsp, error) {
  var t = st.t
  var tsd = st.testServerData
  var tkd TestKeyData
  var i string
  var err error
  var keyFound = false
  var rsp = &AddKeyRsp{}

  t.Logf(logReceivedMsgStr, msg)
  if verboseServerDebug() {
    t.Logf("     KeyID: %s", msg.KeyId)
    t.Logf("     Gun: %s", msg.Gun)
    t.Logf("     Role: %s", msg.Role)
    t.Logf("     Alogrithm: %s", msg.Algorithm)
    t.Logf("     SignatureAlgorithm: %s", msg.SignatureAlgorithm)
    t.Logf("     PublicKey: %x", msg.PublicKey)
    t.Logf("     PrivateKey: %x", msg.PrivateKey)
  }

  // search the test keys.  for addkey basically the only thing we are retrieving
  // is the remote key id.
  for i,tkd = range st.testKeys {
     if (msg.Role == string(tkd.keyInfo.Role)) && (msg.Gun == string(tkd.keyInfo.Gun)) {
        keyFound = true
        break
      }
  }

  if !keyFound {
    err = fmt.Errorf("Unable to locate matching testkey for role:%s gun:%s", msg.Role, msg.Gun)
    return rsp, err
  }

  // if an error injection is reqeusted for testing, return it now.
  if (tsd.injectErrorAddKey) {
    t.Logf(logReturningErrorMsgStr)
    err = fmt.Errorf(tsd.injectErrorStr)
  }

  // mark the key associated (in use) and update the map
  tkd.associated = true
  st.testKeys[i] = tkd

  rsp = &AddKeyRsp{
    RemoteKeyId:             tkd.remoteKeyID,
  }

  t.Logf(logReturningMsgStr, rsp)
  if verboseServerDebug() {
    t.Logf("     RemoteKeyId: %s", rsp.RemoteKeyId)
  }
  return rsp, err
}

func (st *GRPCKeyStoreSrvr) GetKey(ctx context.Context, msg *GetKeyReq) (*GetKeyRsp, error) {
  var t = st.t
  var tsd = st.testServerData
  var tkd TestKeyData
  var err error
  var keyFound = false
  var rsp = &GetKeyRsp{}

  t.Logf(logReceivedMsgStr, msg)

  if verboseServerDebug() {
    t.Logf("     KeyID: %s", msg.KeyId)
    t.Logf("     RemoteID: %s", msg.RemoteKeyId)
  }
  for _,tkd = range st.testKeys {
     if (msg.RemoteKeyId == tkd.remoteKeyID) && (tkd.associated) {
       keyFound = true
       break
      }
  }

  if !keyFound {
    err = fmt.Errorf("Unable to locate matching testkey for RemoteKeyID:%s", msg.RemoteKeyId)
    return rsp, err
  }

  // if an error injection is reqeusted for testing, return it now.
  if (tsd.injectErrorGetKey) {
    t.Logf(logReturningErrorMsgStr)
    err = fmt.Errorf(tsd.injectErrorStr)
  }

  rsp = &GetKeyRsp{
    Role:                  string(tkd.keyInfo.Role),
    Algorithm:             string(tkd.privateKey.Algorithm()),
    SignatureAlgorithm:    string(tkd.privateKey.SignatureAlgorithm()),
    PublicKey:             tkd.privateKey.Public(),
  }

  t.Logf(logReturningMsgStr, rsp)
  if verboseServerDebug() {
    t.Logf("     Role: %s", rsp.Role)
    t.Logf("     Alogrithm: %s", rsp.Algorithm)
    t.Logf("     SignatureAlgorithm: %s", rsp.SignatureAlgorithm)
    t.Logf("     PublicKey: %x", rsp.PublicKey)
  }

  return rsp, err
}

// ListKeys returns a list of unique PublicKeys present on the KeyFileStore
func (st *GRPCKeyStoreSrvr) ListKeys(ctx context.Context, msg *ListKeysReq) (*ListKeysRsp, error) {
  var t = st.t
  var tsd = st.testServerData
  var tkd TestKeyData
  var err error
  var keyDataList []*ListKeysRsp_KeyInfo
  var rsp = &ListKeysRsp{}

  t.Logf(logReceivedMsgStr, msg)

  // verify the metadata made it through
  md, _ := metadata.FromContext(ctx)

  // make sure all expected metadata made it through
  // if it doesn't match, return no keys so the
  // test will fail
  for expectedKey, expectedSlice := range tsd.metadata {
    receivedSlice := md[expectedKey]
    if len(expectedSlice) != len(receivedSlice) {
      err = fmt.Errorf("Number of values for expectedKey %s dont match", expectedKey)
    }
    if err == nil {
      for i := range expectedSlice {
        if expectedSlice[i] != receivedSlice[i] {
          err = fmt.Errorf("Metadata does not match for expectedKey %s", expectedKey)
        }
      }
    }
  }
  if err != nil {
    t.Logf("Expected metadata pairs not received on server")
    t.Logf("Received metadata: %v", md)
    t.Logf("Expected metadata: %v", tsd.metadata)
    return rsp, err
  }


  // return all the associated keys
  for _,tkd = range st.testKeys {
     if tkd.associated {
       keyData := ListKeysRsp_KeyInfo{
         KeyId:        string(tkd.privateKey.ID()),
         RemoteKeyId: tkd.remoteKeyID,
         Gun:          string(tkd.keyInfo.Gun),
         Role:         string(tkd.keyInfo.Role),
       }
       keyDataList = append(keyDataList, &keyData)
     }
   }

   // if an error injection is reqeusted for testing, return it now.
   if (tsd.injectErrorListKeys) {
     t.Logf(logReturningErrorMsgStr)
     err = fmt.Errorf(tsd.injectErrorStr)
   }

  rsp = &ListKeysRsp{
    KeyData : keyDataList,
  }

  t.Logf(logReturningMsgStr, rsp)
  if verboseServerDebug() {
    for i, key := range rsp.KeyData {
      t.Logf("     Key %d", i)
      t.Logf("        KeyId: %s", key.KeyId)
      t.Logf("        RemoteKeyId: %s", key.RemoteKeyId)
      t.Logf("        Gun: %s", key.Gun)
      t.Logf("        Role: %s", key.Role)
    }
  }

  return rsp, err
}

func (st *GRPCKeyStoreSrvr) RemoveKey(ctx context.Context, msg *RemoveKeyReq) (*RemoveKeyRsp, error) {
  var t = st.t
  var tsd = st.testServerData
  var tkd TestKeyData
  var i string
  var err error
  var keyFound = false
  var rsp = &RemoveKeyRsp{}

  t.Logf(logReceivedMsgStr, msg)
  if verboseServerDebug() {
    t.Logf("     KeyID: %s", msg.KeyId)
    t.Logf("     RemoteID: %s", msg.RemoteKeyId)
  }

  for i,tkd = range st.testKeys {
     if (msg.RemoteKeyId == tkd.remoteKeyID) && (tkd.associated) {
       keyFound = true
       tkd.associated = false
       // update the map as Associated
       st.testKeys[i] = tkd
       break
      }
  }

  if !keyFound {
    err = fmt.Errorf("Unable to locate matching testkey for RemoteKeyID:%s", msg.RemoteKeyId)
    return rsp, err
  }

  // if an error injection is reqeusted for testing, return it now.
  if (tsd.injectErrorRemoveKey) {
    t.Logf(logReturningErrorMsgStr)
    err = fmt.Errorf(tsd.injectErrorStr)
  }

  t.Logf(logReturningMsgStr, rsp)

  return rsp, err
}

func (st *GRPCKeyStoreSrvr) Sign(ctx context.Context, msg *SignReq) (*SignRsp, error) {
  var t = st.t
  var tsd = st.testServerData
  var err error
  var tkd TestKeyData
  var keyFound = false
  var rsp = &SignRsp{}

  t.Logf(logReceivedMsgStr, msg)

  if verboseServerDebug() {
    t.Logf("     KeyID: %s", msg.KeyId)
    t.Logf("     RemoteID: %s", msg.RemoteKeyId)
    t.Logf("     Message: %x", msg.Message)
  }

  for _, tkd = range st.testKeys {
     if (msg.RemoteKeyId == tkd.remoteKeyID) {
        keyFound = true
        break
      }
  }

  if !keyFound {
    err = fmt.Errorf("Unable to locate matching testkey for remoteID:%s", tkd.remoteKeyID)
    return rsp, err
  }

  // if an error injection is reqeusted for testing, return it now.
  if (tsd.injectErrorSign) {
    t.Logf(logReturningErrorMsgStr)
    err = fmt.Errorf(tsd.injectErrorStr)
  }

  signature, err := tkd.privateKey.Sign(rand.Reader, msg.Message, nil)

  rsp = &SignRsp{
    Signature:          signature,
  }

  t.Logf(logReturningMsgStr, rsp)
  if verboseServerDebug() {
    t.Logf("     Signature: %x", rsp.Signature)
  }

  return rsp, err
}
