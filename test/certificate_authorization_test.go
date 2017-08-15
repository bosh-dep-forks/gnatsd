package test

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"strings"
	"testing"

	"time"

	"regexp"

	"github.com/nats-io/go-nats"
)

func TestNonTLSConnectionsWithTLSServer(t *testing.T) {
	srv, opts := RunServerWithConfig("./configs/tls-generic.conf")
	defer srv.Shutdown()

	clientA := createClientConn(t, "localhost", opts.Port)
	defer clientA.Close()

	sendA, expectA := setupConnWithAuth(t, clientA, opts.Username, opts.Password)
	sendA("SUB foo 22\r\n")
	sendA("PING\r\n")
	expectA(pongRe)

	if err := checkExpectedSubs(1, srv); err != nil {
		t.Fatalf("%v", err)
	}

	clientB := createClientConn(t, "localhost", opts.Port)
	defer clientB.Close()

	sendB, expectB := setupConnWithAuth(t, clientB, opts.Username, opts.Password)
	sendB("PUB foo 2\r\nok\r\n")
	sendB("PING\r\n")
	expectB(pongRe)

	expectMsgs := expectMsgsCommand(t, expectA)

	matches := expectMsgs(1)
	checkMsg(t, matches[0], "foo", "22", "", "2", "ok")
}

func TestNonTLSConnectionsWithMutualTLSServer(t *testing.T) {
	srv, opts := RunServerWithConfig("./configs/tlsverify_cert_authorization.conf")
	defer srv.Shutdown()

	clientA := createClientConn(t, "localhost", opts.Port)
	defer clientA.Close()

	sendA, expectA := setupConnWithAuth(t, clientA, opts.Username, opts.Password)
	sendA("SUB foo 22\r\n")
	sendA("PING\r\n")
	expectA(pongRe)

	if err := checkExpectedSubs(1, srv); err != nil {
		t.Fatalf("%v", err)
	}

	clientB := createClientConn(t, "localhost", opts.Port)
	defer clientB.Close()

	sendB, expectB := setupConnWithAuth(t, clientB, opts.Username, opts.Password)
	sendB("PUB foo 2\r\nok\r\n")
	sendB("PING\r\n")
	expectB(pongRe)

	expectMsgs := expectMsgsCommand(t, expectA)

	matches := expectMsgs(1)
	checkMsg(t, matches[0], "foo", "22", "", "2", "ok")
}

func TestUnauthorizedNonTLSConnectionsWithMutualTLSServer(t *testing.T) {
	t.Skip("Update to use for legacy clients")

	srv, opts := RunServerWithConfig("./configs/tlsverify_cert_authorization_legacy_auth.conf")
	defer srv.Shutdown()

	clientA := createClientConn(t, "localhost", 4443)

	sendA, expectA := setupConnWithAuth(t, clientA, opts.Username, opts.Password)
	sendA("SUB foo 22\r\n")
	sendA("PING\r\n")
	expectA(pongRe)

	if err := checkExpectedSubs(1, srv); err != nil {
		t.Fatalf("%v", err)
	}

	clientB := createClientConn(t, "localhost", 4443)

	sendB, expectB := setupConnWithAuth(t, clientB, opts.Username, opts.Password)
	sendB("PUB foo 2\r\nok\r\n")
	sendB("PING\r\n")
	expectB(pongRe)

	expectMsgs := expectMsgsCommand(t, expectA)

	matches := expectMsgs(1)
	checkMsg(t, matches[0], "foo", "22", "", "2", "ok")
}

func TestUnauthenticatedNonTLSConnectionsWithMutualTLSServerEmptyAuthrizationBlock(t *testing.T) {
	srv, opts := RunServerWithConfig("./configs/tlsverify_cert_authorization.conf")
	defer srv.Shutdown()

	clientA := createClientConn(t, "localhost", opts.Port)
	defer clientA.Close()

	_, expectA := setupConnWithAuth(t, clientA, "unauthorized_user", "unauthorized_pass")
	expectA(regexp.MustCompile(`\A-ERR 'Authorization Violation'\r\n`))
}

func TestUnauthenticatedNonTLSConnectionsWithMutualTLSServer(t *testing.T) {
	t.Skip("Update to use for legacy clients")

	srv, _ := RunServerWithConfig("./configs/tlsverify_cert_authorization_legacy_auth.conf")
	defer srv.Shutdown()

	clientA := createClientConn(t, "localhost", 4443)

	_, expectA := setupConnWithAuth(t, clientA, "unauthorized_user", "unauthorized_pass")
	expectA(regexp.MustCompile(`\A-ERR 'Authorization Violation'\r\n`))
}

func TestTLSClientCertificatePermissionsUnauthorized(t *testing.T) {
	srv, opts := RunServerWithConfig("./configs/tlsverify_cert_authorization.conf")
	defer srv.Shutdown()

	endpoint := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	nurl := fmt.Sprintf("tls://%s:%s@%s/", opts.Username, opts.Password, endpoint)

	// Load client certificate to successfully connect.
	certFile := "./configs/certs/certificate_authorization/valid-client.pem"
	keyFile := "./configs/certs/certificate_authorization/valid-client.key"
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("error parsing X509 certificate/key pair: %v", err)
	}

	// Load in root CA for server verification
	rootPEM, err := ioutil.ReadFile("./configs/certs/certificate_authorization/ca.pem")
	if err != nil || rootPEM == nil {
		t.Fatalf("failed to read root certificate")
	}
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		t.Fatalf("failed to parse root certificate")
	}

	// Now do more advanced checking, verifying servername and using rootCA.
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   opts.Host,
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}

	nc, err := nats.Connect(nurl, nats.Secure(config))
	if err != nil {
		t.Fatalf("Got an error on Connect with Secure Options: %+v\n", err)
	}
	defer nc.Close()

	subj := "foo-tls"
	_, err = nc.SubscribeSync(subj)
	nc.Flush()

	err = nc.LastError()
	if err == nil {
		t.Fatalf("An error was expected when subscribing to channel: '%s'", subj)
	}

	expectedSuffix := fmt.Sprintf(`permissions violation for subscription to "%s"`, subj)
	if !strings.HasSuffix(err.Error(), expectedSuffix) {
		stackFatalf(t, "Response did not match expected: \n\tReceived:'%q'\n\tExpected to contain:'%s'\n", err.Error(), expectedSuffix)
	}
}

func TestTLSClientCertificatePermissions(t *testing.T) {
	srv, opts := RunServerWithConfig("./configs/tlsverify_cert_authorization.conf")
	defer srv.Shutdown()

	endpoint := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	nurl := fmt.Sprintf("tls://%s:%s@%s/", opts.Username, opts.Password, endpoint)

	// Load client certificate to successfully connect.
	certFile := "./configs/certs/certificate_authorization/valid-client.pem"
	keyFile := "./configs/certs/certificate_authorization/valid-client.key"
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("error parsing X509 certificate/key pair: %v", err)
	}

	// Load in root CA for server verification
	rootPEM, err := ioutil.ReadFile("./configs/certs/certificate_authorization/ca.pem")
	if err != nil || rootPEM == nil {
		t.Fatalf("failed to read root certificate")
	}
	pool := x509.NewCertPool()
	ok := pool.AppendCertsFromPEM([]byte(rootPEM))
	if !ok {
		t.Fatalf("failed to parse root certificate")
	}

	// Now do more advanced checking, verifying servername and using rootCA.
	config := &tls.Config{
		Certificates: []tls.Certificate{cert},
		ServerName:   opts.Host,
		RootCAs:      pool,
		MinVersion:   tls.VersionTLS12,
	}

	nc, err := nats.Connect(nurl, nats.Secure(config))
	if err != nil {
		t.Fatalf("Got an error on Connect with Secure Options: %+v\n", err)
	}
	defer nc.Close()

	subj := "smurf.happy"
	sub, _ := nc.SubscribeSync(subj)

	nc.Publish(subj, []byte("Message is Delivered!"))
	nc.Flush()

	msg, err := sub.NextMsg(2 * time.Second)

	if err != nil {
		t.Fatalf("Expected message to be sent.")
	}

	expectedMessage := "Message is Delivered!"
	if !strings.Contains(string(msg.Data), expectedMessage) {
		stackFatalf(t, "Response did not match expected: \n\tReceived:'%q'\n\tExpected to contain:'%s'\n", string(msg.Data), expectedMessage)
	}
}
