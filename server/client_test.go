// Copyright 2012-2016 Apcera Inc. All rights reserved.

package server

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"crypto/tls"

	"github.com/nats-io/go-nats"
	"crypto/x509"
	"encoding/pem"
)

type serverInfo struct {
	Id           string `json:"server_id"`
	Host         string `json:"host"`
	Port         uint   `json:"port"`
	Version      string `json:"version"`
	AuthRequired bool   `json:"auth_required"`
	TLSRequired  bool   `json:"ssl_required"`
	MaxPayload   int64  `json:"max_payload"`
}

type mockAuth struct{}

func (m *mockAuth) Check(c ClientAuth) bool {
	return true
}

func createClientAsync(ch chan *client, s *Server, cli net.Conn) {
	go func() {
		c := s.createClient(cli)
		// Must be here to suppress +OK
		c.opts.Verbose = false
		ch <- c
	}()
}

var defaultServerOptions = Options{
	Trace:  false,
	Debug:  false,
	NoLog:  true,
	NoSigs: true,
}

func rawSetup(serverOptions Options) (*Server, *client, *bufio.Reader, string) {
	cli, srv := net.Pipe()
	cr := bufio.NewReaderSize(cli, maxBufSize)
	s := New(&serverOptions)
	if serverOptions.Authorization != "" {
		s.SetClientAuthMethod(&mockAuth{})
	}

	ch := make(chan *client)
	createClientAsync(ch, s, srv)

	l, _ := cr.ReadString('\n')

	// Grab client
	c := <-ch
	return s, c, cr, l
}

func setUpClientWithResponse() (*client, string) {
	_, c, _, l := rawSetup(defaultServerOptions)
	return c, l
}

func setupClient() (*Server, *client, *bufio.Reader) {
	s, c, cr, _ := rawSetup(defaultServerOptions)
	return s, c, cr
}

func TestClientCreateAndInfo(t *testing.T) {
	c, l := setUpClientWithResponse()

	if c.cid != 1 {
		t.Fatalf("Expected cid of 1 vs %d\n", c.cid)
	}
	if c.state != OP_START {
		t.Fatal("Expected state to be OP_START")
	}

	if !strings.HasPrefix(l, "INFO ") {
		t.Fatalf("INFO response incorrect: %s\n", l)
	}
	// Make sure payload is proper json
	var info serverInfo
	err := json.Unmarshal([]byte(l[5:]), &info)
	if err != nil {
		t.Fatalf("Could not parse INFO json: %v\n", err)
	}
	// Sanity checks
	if info.MaxPayload != MAX_PAYLOAD_SIZE ||
		info.AuthRequired || info.TLSRequired ||
		info.Port != DEFAULT_PORT {
		t.Fatalf("INFO inconsistent: %+v\n", info)
	}
}

func TestClientConnect(t *testing.T) {
	_, c, _ := setupClient()

	// Basic Connect setting flags
	connectOp := []byte("CONNECT {\"verbose\":true,\"pedantic\":true,\"ssl_required\":false}\r\n")
	err := c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected state of OP_START vs %d\n", c.state)
	}
	if !reflect.DeepEqual(c.opts, clientOpts{Verbose: true, Pedantic: true}) {
		t.Fatalf("Did not parse connect options correctly: %+v\n", c.opts)
	}

	// Test that we can capture user/pass
	connectOp = []byte("CONNECT {\"user\":\"derek\",\"pass\":\"foo\"}\r\n")
	c.opts = defaultOpts
	err = c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected state of OP_START vs %d\n", c.state)
	}
	if !reflect.DeepEqual(c.opts, clientOpts{Verbose: true, Pedantic: true, Username: "derek", Password: "foo"}) {
		t.Fatalf("Did not parse connect options correctly: %+v\n", c.opts)
	}

	// Test that we can capture client name
	connectOp = []byte("CONNECT {\"user\":\"derek\",\"pass\":\"foo\",\"name\":\"router\"}\r\n")
	c.opts = defaultOpts
	err = c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected state of OP_START vs %d\n", c.state)
	}

	if !reflect.DeepEqual(c.opts, clientOpts{Verbose: true, Pedantic: true, Username: "derek", Password: "foo", Name: "router"}) {
		t.Fatalf("Did not parse connect options correctly: %+v\n", c.opts)
	}

	// Test that we correctly capture auth tokens
	connectOp = []byte("CONNECT {\"auth_token\":\"YZZ222\",\"name\":\"router\"}\r\n")
	c.opts = defaultOpts
	err = c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected state of OP_START vs %d\n", c.state)
	}

	if !reflect.DeepEqual(c.opts, clientOpts{Verbose: true, Pedantic: true, Authorization: "YZZ222", Name: "router"}) {
		t.Fatalf("Did not parse connect options correctly: %+v\n", c.opts)
	}
}

func TestClientConnectProto(t *testing.T) {
	_, c, _ := setupClient()

	// Basic Connect setting flags, proto should be zero (original proto)
	connectOp := []byte("CONNECT {\"verbose\":true,\"pedantic\":true,\"ssl_required\":false}\r\n")
	err := c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected state of OP_START vs %d\n", c.state)
	}
	if !reflect.DeepEqual(c.opts, clientOpts{Verbose: true, Pedantic: true, Protocol: ClientProtoZero}) {
		t.Fatalf("Did not parse connect options correctly: %+v\n", c.opts)
	}

	// ProtoInfo
	connectOp = []byte(fmt.Sprintf("CONNECT {\"verbose\":true,\"pedantic\":true,\"ssl_required\":false,\"protocol\":%d}\r\n", ClientProtoInfo))
	err = c.parse(connectOp)
	if err != nil {
		t.Fatalf("Received error: %v\n", err)
	}
	if c.state != OP_START {
		t.Fatalf("Expected state of OP_START vs %d\n", c.state)
	}
	if !reflect.DeepEqual(c.opts, clientOpts{Verbose: true, Pedantic: true, Protocol: ClientProtoInfo}) {
		t.Fatalf("Did not parse connect options correctly: %+v\n", c.opts)
	}
	if c.opts.Protocol != ClientProtoInfo {
		t.Fatalf("Protocol should have been set to %v, but is set to %v", ClientProtoInfo, c.opts.Protocol)
	}

	// Illegal Option
	connectOp = []byte("CONNECT {\"protocol\":22}\r\n")
	err = c.parse(connectOp)
	if err == nil {
		t.Fatalf("Expected to receive an error\n")
	}
	if err != ErrBadClientProtocol {
		t.Fatalf("Expected err of %q, got  %q\n", ErrBadClientProtocol, err)
	}
}

func TestClientPing(t *testing.T) {
	_, c, cr := setupClient()

	// PING
	pingOp := []byte("PING\r\n")
	go c.parse(pingOp)
	l, err := cr.ReadString('\n')
	if err != nil {
		t.Fatalf("Error receiving info from server: %v\n", err)
	}
	if !strings.HasPrefix(l, "PONG\r\n") {
		t.Fatalf("PONG response incorrect: %s\n", l)
	}
}

var msgPat = regexp.MustCompile(`\AMSG\s+([^\s]+)\s+([^\s]+)\s+(([^\s]+)[^\S\r\n]+)?(\d+)\r\n`)

const (
	SUB_INDEX   = 1
	SID_INDEX   = 2
	REPLY_INDEX = 4
	LEN_INDEX   = 5
)

func checkPayload(cr *bufio.Reader, expected []byte, t *testing.T) {
	// Read in payload
	d := make([]byte, len(expected))
	n, err := cr.Read(d)
	if err != nil {
		t.Fatalf("Error receiving msg payload from server: %v\n", err)
	}
	if n != len(expected) {
		t.Fatalf("Did not read correct amount of bytes: %d vs %d\n", n, len(expected))
	}
	if !bytes.Equal(d, expected) {
		t.Fatalf("Did not read correct payload:: <%s>\n", d)
	}
}

func TestClientSimplePubSub(t *testing.T) {
	_, c, cr := setupClient()
	// SUB/PUB
	go c.parse([]byte("SUB foo 1\r\nPUB foo 5\r\nhello\r\nPING\r\n"))
	l, err := cr.ReadString('\n')
	if err != nil {
		t.Fatalf("Error receiving msg from server: %v\n", err)
	}
	matches := msgPat.FindAllStringSubmatch(l, -1)[0]
	if len(matches) != 6 {
		t.Fatalf("Did not get correct # matches: %d vs %d\n", len(matches), 6)
	}
	if matches[SUB_INDEX] != "foo" {
		t.Fatalf("Did not get correct subject: '%s'\n", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'\n", matches[SID_INDEX])
	}
	if matches[LEN_INDEX] != "5" {
		t.Fatalf("Did not get correct msg length: '%s'\n", matches[LEN_INDEX])
	}
	checkPayload(cr, []byte("hello\r\n"), t)
}

func TestClientSimplePubSubWithReply(t *testing.T) {
	_, c, cr := setupClient()

	// SUB/PUB
	go c.parse([]byte("SUB foo 1\r\nPUB foo bar 5\r\nhello\r\nPING\r\n"))
	l, err := cr.ReadString('\n')
	if err != nil {
		t.Fatalf("Error receiving msg from server: %v\n", err)
	}
	matches := msgPat.FindAllStringSubmatch(l, -1)[0]
	if len(matches) != 6 {
		t.Fatalf("Did not get correct # matches: %d vs %d\n", len(matches), 6)
	}
	if matches[SUB_INDEX] != "foo" {
		t.Fatalf("Did not get correct subject: '%s'\n", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'\n", matches[SID_INDEX])
	}
	if matches[REPLY_INDEX] != "bar" {
		t.Fatalf("Did not get correct reply subject: '%s'\n", matches[REPLY_INDEX])
	}
	if matches[LEN_INDEX] != "5" {
		t.Fatalf("Did not get correct msg length: '%s'\n", matches[LEN_INDEX])
	}
}

func TestClientNoBodyPubSubWithReply(t *testing.T) {
	_, c, cr := setupClient()

	// SUB/PUB
	go c.parse([]byte("SUB foo 1\r\nPUB foo bar 0\r\n\r\nPING\r\n"))
	l, err := cr.ReadString('\n')
	if err != nil {
		t.Fatalf("Error receiving msg from server: %v\n", err)
	}
	matches := msgPat.FindAllStringSubmatch(l, -1)[0]
	if len(matches) != 6 {
		t.Fatalf("Did not get correct # matches: %d vs %d\n", len(matches), 6)
	}
	if matches[SUB_INDEX] != "foo" {
		t.Fatalf("Did not get correct subject: '%s'\n", matches[SUB_INDEX])
	}
	if matches[SID_INDEX] != "1" {
		t.Fatalf("Did not get correct sid: '%s'\n", matches[SID_INDEX])
	}
	if matches[REPLY_INDEX] != "bar" {
		t.Fatalf("Did not get correct reply subject: '%s'\n", matches[REPLY_INDEX])
	}
	if matches[LEN_INDEX] != "0" {
		t.Fatalf("Did not get correct msg length: '%s'\n", matches[LEN_INDEX])
	}
}

func TestClientPubWithQueueSub(t *testing.T) {
	_, c, cr := setupClient()

	num := 100

	// Queue SUB/PUB
	subs := []byte("SUB foo g1 1\r\nSUB foo g1 2\r\n")
	pubs := []byte("PUB foo bar 5\r\nhello\r\n")
	op := []byte{}
	op = append(op, subs...)
	for i := 0; i < num; i++ {
		op = append(op, pubs...)
	}

	go func() {
		c.parse(op)
		for cp := range c.pcd {
			cp.bw.Flush()
		}
		c.nc.Close()
	}()

	var n1, n2, received int
	for ; ; received++ {
		l, err := cr.ReadString('\n')
		if err != nil {
			break
		}
		matches := msgPat.FindAllStringSubmatch(l, -1)[0]

		// Count which sub
		switch matches[SID_INDEX] {
		case "1":
			n1++
		case "2":
			n2++
		}
		checkPayload(cr, []byte("hello\r\n"), t)
	}
	if received != num {
		t.Fatalf("Received wrong # of msgs: %d vs %d\n", received, num)
	}
	// Threshold for randomness for now
	if n1 < 20 || n2 < 20 {
		t.Fatalf("Received wrong # of msgs per subscriber: %d - %d\n", n1, n2)
	}
}

func TestClientUnSub(t *testing.T) {
	_, c, cr := setupClient()

	num := 1

	// SUB/PUB
	subs := []byte("SUB foo 1\r\nSUB foo 2\r\n")
	unsub := []byte("UNSUB 1\r\n")
	pub := []byte("PUB foo bar 5\r\nhello\r\n")

	op := []byte{}
	op = append(op, subs...)
	op = append(op, unsub...)
	op = append(op, pub...)

	go func() {
		c.parse(op)
		for cp := range c.pcd {
			cp.bw.Flush()
		}
		c.nc.Close()
	}()

	var received int
	for ; ; received++ {
		l, err := cr.ReadString('\n')
		if err != nil {
			break
		}
		matches := msgPat.FindAllStringSubmatch(l, -1)[0]
		if matches[SID_INDEX] != "2" {
			t.Fatalf("Received msg on unsubscribed subscription!\n")
		}
		checkPayload(cr, []byte("hello\r\n"), t)
	}
	if received != num {
		t.Fatalf("Received wrong # of msgs: %d vs %d\n", received, num)
	}
}

func TestClientUnSubMax(t *testing.T) {
	_, c, cr := setupClient()

	num := 10
	exp := 5

	// SUB/PUB
	subs := []byte("SUB foo 1\r\n")
	unsub := []byte("UNSUB 1 5\r\n")
	pub := []byte("PUB foo bar 5\r\nhello\r\n")

	op := []byte{}
	op = append(op, subs...)
	op = append(op, unsub...)
	for i := 0; i < num; i++ {
		op = append(op, pub...)
	}

	go func() {
		c.parse(op)
		for cp := range c.pcd {
			cp.bw.Flush()
		}
		c.nc.Close()
	}()

	var received int
	for ; ; received++ {
		l, err := cr.ReadString('\n')
		if err != nil {
			break
		}
		matches := msgPat.FindAllStringSubmatch(l, -1)[0]
		if matches[SID_INDEX] != "1" {
			t.Fatalf("Received msg on unsubscribed subscription!\n")
		}
		checkPayload(cr, []byte("hello\r\n"), t)
	}
	if received != exp {
		t.Fatalf("Received wrong # of msgs: %d vs %d\n", received, exp)
	}
}

func TestClientAutoUnsubExactReceived(t *testing.T) {
	_, c, _ := setupClient()
	defer c.nc.Close()

	// SUB/PUB
	subs := []byte("SUB foo 1\r\n")
	unsub := []byte("UNSUB 1 1\r\n")
	pub := []byte("PUB foo bar 2\r\nok\r\n")

	op := []byte{}
	op = append(op, subs...)
	op = append(op, unsub...)
	op = append(op, pub...)

	ch := make(chan bool)
	go func() {
		c.parse(op)
		ch <- true
	}()

	// Wait for processing
	<-ch

	// We should not have any subscriptions in place here.
	if len(c.subs) != 0 {
		t.Fatalf("Wrong number of subscriptions: expected 0, got %d\n", len(c.subs))
	}
}

func TestClientUnsubAfterAutoUnsub(t *testing.T) {
	_, c, _ := setupClient()
	defer c.nc.Close()

	// SUB/UNSUB/UNSUB
	subs := []byte("SUB foo 1\r\n")
	asub := []byte("UNSUB 1 1\r\n")
	unsub := []byte("UNSUB 1\r\n")

	op := []byte{}
	op = append(op, subs...)
	op = append(op, asub...)
	op = append(op, unsub...)

	ch := make(chan bool)
	go func() {
		c.parse(op)
		ch <- true
	}()

	// Wait for processing
	<-ch

	// We should not have any subscriptions in place here.
	if len(c.subs) != 0 {
		t.Fatalf("Wrong number of subscriptions: expected 0, got %d\n", len(c.subs))
	}
}

func TestClientRemoveSubsOnDisconnect(t *testing.T) {
	s, c, _ := setupClient()
	subs := []byte("SUB foo 1\r\nSUB bar 2\r\n")

	ch := make(chan bool)
	go func() {
		c.parse(subs)
		ch <- true
	}()
	<-ch

	if s.sl.Count() != 2 {
		t.Fatalf("Should have 2 subscriptions, got %d\n", s.sl.Count())
	}
	c.closeConnection()
	if s.sl.Count() != 0 {
		t.Fatalf("Should have no subscriptions after close, got %d\n", s.sl.Count())
	}
}

func TestClientDoesNotAddSubscriptionsWhenConnectionClosed(t *testing.T) {
	s, c, _ := setupClient()
	c.closeConnection()
	subs := []byte("SUB foo 1\r\nSUB bar 2\r\n")

	ch := make(chan bool)
	go func() {
		c.parse(subs)
		ch <- true
	}()
	<-ch

	if s.sl.Count() != 0 {
		t.Fatalf("Should have no subscriptions after close, got %d\n", s.sl.Count())
	}
}

func TestClientMapRemoval(t *testing.T) {
	s, c, _ := setupClient()
	c.nc.Close()
	end := time.Now().Add(1 * time.Second)

	for time.Now().Before(end) {
		s.mu.Lock()
		lsc := len(s.clients)
		s.mu.Unlock()
		if lsc > 0 {
			time.Sleep(5 * time.Millisecond)
		}
	}
	s.mu.Lock()
	lsc := len(s.clients)
	s.mu.Unlock()
	if lsc > 0 {
		t.Fatal("Client still in server map")
	}
}

// TODO: This test timesout for unknown reasons.
//func TestAuthorizationTimeout(t *testing.T) {
//	serverOptions := defaultServerOptions
//	serverOptions.Authorization = "my_token"
//	serverOptions.AuthTimeout = 1
//	s := RunServer(&serverOptions)
//	defer s.Shutdown()
//
//	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", serverOptions.Host, serverOptions.Port))
//	if err != nil {
//		t.Fatalf("Error dialing server: %v\n", err)
//	}
//	defer conn.Close()
//	client := bufio.NewReaderSize(conn, maxBufSize)
//	if _, err := client.ReadString('\n'); err != nil {
//		t.Fatalf("Error receiving info from server: %v\n", err)
//	}
//	l, err := client.ReadString('\n')
//	if err != nil {
//		t.Fatalf("Error receiving info from server: %v\n", err)
//	}
//	if !strings.Contains(l, "Authorization Timeout") {
//		t.Fatalf("Authorization Timeout response incorrect: %q\n", l)
//	}
//}

// This is from bug report #18
func TestTwoTokenPubMatchSingleTokenSub(t *testing.T) {
	_, c, cr := setupClient()
	test := []byte("PUB foo.bar 5\r\nhello\r\nSUB foo 1\r\nPING\r\nPUB foo.bar 5\r\nhello\r\nPING\r\n")
	go c.parse(test)
	l, err := cr.ReadString('\n')
	if err != nil {
		t.Fatalf("Error receiving info from server: %v\n", err)
	}
	if !strings.HasPrefix(l, "PONG\r\n") {
		t.Fatalf("PONG response incorrect: %q\n", l)
	}
	// Expect just a pong, no match should exist here..
	l, _ = cr.ReadString('\n')
	if !strings.HasPrefix(l, "PONG\r\n") {
		t.Fatalf("PONG response was expected, got: %q\n", l)
	}
}

func TestUnsubRace(t *testing.T) {
	s := RunServer(nil)
	defer s.Shutdown()

	nc, err := nats.Connect(fmt.Sprintf("nats://%s:%d",
		DefaultOptions.Host,
		DefaultOptions.Port))
	if err != nil {
		t.Fatalf("Error creating client: %v\n", err)
	}
	defer nc.Close()

	ncp, err := nats.Connect(fmt.Sprintf("nats://%s:%d",
		DefaultOptions.Host,
		DefaultOptions.Port))
	if err != nil {
		t.Fatalf("Error creating client: %v\n", err)
	}
	defer ncp.Close()

	sub, _ := nc.Subscribe("foo", func(m *nats.Msg) {
		// Just eat it..
	})

	nc.Flush()

	var wg sync.WaitGroup

	wg.Add(1)

	go func() {
		for i := 0; i < 10000; i++ {
			ncp.Publish("foo", []byte("hello"))
		}
		wg.Done()
	}()

	time.Sleep(5 * time.Millisecond)

	sub.Unsubscribe()

	wg.Wait()
}

func TestTLSCloseClientConnection(t *testing.T) {
	opts, err := ProcessConfigFile("./configs/tls.conf")
	if err != nil {
		t.Fatalf("Error processing config file: %v", err)
	}
	opts.Authorization = ""
	opts.TLSTimeout = 100
	s := RunServer(opts)
	defer s.Shutdown()

	endpoint := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	conn, err := net.DialTimeout("tcp", endpoint, 2*time.Second)
	if err != nil {
		t.Fatalf("Unexpected error on dial: %v", err)
	}
	defer conn.Close()
	br := bufio.NewReaderSize(conn, 100)
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("Unexpected error reading INFO: %v", err)
	}

	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true})
	defer tlsConn.Close()
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("Unexpected error during handshake: %v", err)
	}
	br = bufio.NewReaderSize(tlsConn, 100)
	connectOp := []byte("CONNECT {\"verbose\":false,\"pedantic\":false,\"tls_required\":true}\r\n")
	if _, err := tlsConn.Write(connectOp); err != nil {
		t.Fatalf("Unexpected error writing CONNECT: %v", err)
	}
	if _, err := tlsConn.Write([]byte("PING\r\n")); err != nil {
		t.Fatalf("Unexpected error writing PING: %v", err)
	}
	if _, err := br.ReadString('\n'); err != nil {
		t.Fatalf("Unexpected error reading PONG: %v", err)
	}

	getClient := func() *client {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, c := range s.clients {
			return c
		}
		return nil
	}
	// Wait for client to be registered.
	timeout := time.Now().Add(5 * time.Second)
	var cli *client
	for time.Now().Before(timeout) {
		cli = getClient()
		if cli != nil {
			break
		}
	}
	if cli == nil {
		t.Fatal("Did not register client on time")
	}
	// Fill the buffer. Need to send 1 byte at a time so that we timeout here
	// the nc.Close() would block due to a write that can not complete.
	done := false
	for !done {
		cli.nc.SetWriteDeadline(time.Now().Add(time.Second))
		if _, err := cli.nc.Write([]byte("a")); err != nil {
			done = true
		}
		cli.nc.SetWriteDeadline(time.Time{})
	}
	ch := make(chan bool)
	go func() {
		select {
		case <-ch:
			return
		case <-time.After(3 * time.Second):
			fmt.Println("!!!! closeConnection is blocked, test will hang !!!")
			return
		}
	}()
	// Close the client
	cli.closeConnection()
	ch <- true
}

func TestGetCertificateClientName(t *testing.T) {
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIDQTCCAimgAwIBAgIRAN2xb3ZM2thFxHdh4sCYbncwDQYJKoZIhvcNAQELBQAw
JjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQKEw1DbG91ZCBGb3VuZHJ5MB4XDTE3MDgx
NDIwMTcwMloXDTE4MDgxNDIwMTcwMlowWzEMMAoGA1UEBhMDVVNBMRYwFAYDVQQK
Ew1DbG91ZCBGb3VuZHJ5MTMwMQYDVQQDEyphZ2VudC44Mzc3OEZCMC0zOTcyLTQ2
QjYtODQwMC0zNEYxOTIwMzVENTAwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
AoIBAQClPlAJvyowA79FjD2nc/AvZj4EzKyBUY+1QBIblOSxr9lS5ZVoPUHtUgBt
IKRXQshkJ4XEgqzsUm7Smh0r2czgc0z78GRjolTuuZ4f9veDxTA7ulOUc6z+u0Hb
YKuh7bgsQfrXzIdWK6LbkCzK1KV0nUnH5hzMug+ES4n3iZi+LbWd95bbPK1kI9RI
H4dJaoL9Uu0R6v5EFHPKfx64JPMC0rpE4Wzug5omi4frduJPlRue4obyELYfqL98
FUACxlxRwFkn7FfxWvJiLOYNkspebbrGOnm57J7OZ1Jff+wtkrfmnc6FmnOhxaj6
9ntCEq0pRCKUPomKZPV1A94bD+RpAgMBAAGjNTAzMA4GA1UdDwEB/wQEAwIFoDAT
BgNVHSUEDDAKBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUA
A4IBAQBnkJRsIKYhWSUrJNqLN4IgBR7txNiutGhIOLzzdDbYJ+U6dsg6tnmCNx/s
IKe81LgpAZXJM+jD0FYOA68CQMq47gcqWHI0yaONauoSI9YKT+mjzyNwlI4fknCp
0YQDVFLT1t8KEOhCoiw0qo34IaZRGlDomsgG6OArhPGjkBAykh1UYNngOMLmdMeP
CcPgjrlOaTKAhuC7XegkSroR/RvN7GqHxRrdEHcnHlWtDPDtneYREAvTfNF5mri5
374oCbF6ZFHtgQiOYnWQ9dArPbZgk9gSyOX7pYmuaPgzgzU52SaCShrYETlHzU8j
hXOiF9qEq+q+y3mYtXm5ZDlBibca
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)


	client := client{clientCertificate: crt}

	expectedCertificateClientName := "agent"
	expectedCertificateClientID := "83778FB0-3972-46B6-8400-34F192035D50"

	actualCertificateClientName, actualCertificateClientID, _ := client.GetCertificateClientNameAndID()

	if actualCertificateClientName != expectedCertificateClientName {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientName, expectedCertificateClientName)
	}

	if actualCertificateClientID != expectedCertificateClientID {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientID, expectedCertificateClientID)
	}
}

func TestGetCertificateClientNameNoCertificate(t *testing.T) {
	client := client{clientCertificate: nil}

	_, _, err := client.GetCertificateClientNameAndID()
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}

	expectedErrorMessage := "Client does not have a certificate"
	if err.Error() != expectedErrorMessage {
		stackFatalf(t, "Expected %s to equal %s", err.Error(), expectedErrorMessage)
	}
}

func TestGetCertificateClientNameNoCommonName(t *testing.T) {
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIDDDCCAfSgAwIBAgIRANNAvhLbz8ppp1dhqUXPufkwDQYJKoZIhvcNAQELBQAw
JjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQKEw1DbG91ZCBGb3VuZHJ5MB4XDTE3MDgx
NDIwMzM1N1oXDTE4MDgxNDIwMzM1N1owJjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQK
Ew1DbG91ZCBGb3VuZHJ5MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA
689hB+0cxRlio3ZcaUxAkNSjmBKwfjI379FSyux30GaF9feV+ZgWSNOqKoY534DP
VmMAuoHl/12BwUi5O3RtztQLHLBNtXsAgrn21kkgjvZo29/I24LrB/Xw0lSm2V+O
klZz6LhVIpjAKWh6z4bE3QCW95Bipj9aos6BU3YDmducOSN23JrY9pyl0epoDahl
4JKB8npQZ0MOcXYxAjIAX7ea8jphPuem65fpvlBzkjfmryXpclsvg2lxc/SfHCks
R8dO0ttoswv7YgChqUvGxyZ6NOz3EWmHOVojGr6Mu1vF0egb+S96ro7icAVxDJhV
9xj5G/l+PLd9IYWMflNsGwIDAQABozUwMzAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0l
BAwwCgYIKwYBBQUHAwIwDAYDVR0TAQH/BAIwADANBgkqhkiG9w0BAQsFAAOCAQEA
fCFABI++voIBTQSfdELchXm6FiIBsTIFbFFsiqfRN5di0i9pMq6L/ekYlqXSoe7Z
5uHMmf7jcNdYxgLuS6A4xEWGpVsbMSt80B6/UTIi7UtTxSRv5toqCB6WN3Rh4iRd
4m/sKwXnuChjz6GTdB30YoKUQX/b+rDKCbLQ7zJWPI+3UJSmrgnTp0r1jO1io4pn
05mmDisyNv7jTlqSo143QEqWSeb8FTTqA9zV+84m+1pkbkQDE4pN41eUdedrprTq
ndmdXI8j8ycbjIqrsCnO1m0D4BAhYOPQVry1OR13LpyZZIf8jkfSSSVrzRpxUQab
IwKkI6wszdjZ9f6pPUbI9w==
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	expectedCertificateClientName := ""
	expectedCertificateClientID := ""

	actualCertificateClientName, actualCertificateClientID, _ := client.GetCertificateClientNameAndID()

	if actualCertificateClientName != expectedCertificateClientName {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientName, expectedCertificateClientName)
	}

	if actualCertificateClientID != expectedCertificateClientID {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientID, expectedCertificateClientID)
	}
}

func TestGetCertificateClientNameCommonNameNoDots(t *testing.T) {
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIDHDCCAgSgAwIBAgIRANPxF8tpqqkMW49Mxnr48cowDQYJKoZIhvcNAQELBQAw
JjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQKEw1DbG91ZCBGb3VuZHJ5MB4XDTE3MDgx
NDIxMzEzM1oXDTE4MDgxNDIxMzEzM1owNjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQK
Ew1DbG91ZCBGb3VuZHJ5MQ4wDAYDVQQDEwVhZ2VudDCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALKrb7Q9OkFWzQoeG2Yep+nHfLFhYiWi5d6UkM959EW6
pmoBqymq8mbpkPtxd0tX30VeMFfUQEDGjH1JS6sGna+3H+LMyIMMOXlhb4VTRino
lBnagt0ax4hWPuJq1SoQIzQLFjkN0kQEKu00f+cQ8EZ0DpG9uikhABbJDatC0voo
/TWdpT7wHCxodajBPb3KK+CvPMbIANbgk3VBHbGrDvXsFr7ge1IQ7diAZy0ArbbN
NX24D6Ae9Dnn2ZFT2zD9bqPkIsZ6Yor5NnyUtGHaut+DYjZ2M+fvBRRrkGCrUjfk
aX3M5LaO1aFjULtVDE//957Q8xHm1yo9bjMnETYGdg8CAwEAAaM1MDMwDgYDVR0P
AQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwDQYJ
KoZIhvcNAQELBQADggEBAEo/ojFO3rfa6s7XfdUTJ/7s7mNJk7mFHHDUz7gL9jfM
XuJBQeHAAJbscARODhyS2LzwKkIsr0bjekfcMry+4AGQb7XcO699gRalh4oLFe96
VBThPJIYOo3G2+hbrSrLwlLCRnVh6Mh2mI0TshsfUt6xiSlm54K5ygUqIOrOrN/0
Dkf7DcuavAMk0rzfNptoIRgLFhAp94p2P/UdQYnje8M2PRZgrHpdlDQCAL6IiPN1
sudBs+h5VEmSNWH9DhyySFNFn474jEgfZLEoMiymr/KvopilZHF/6jciSN0+ijYQ
ZPj54+7ig2TFKbIDhXfnqUYhDNTDD1LbleW4b6+Ohc0=
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	expectedCertificateClientName := "agent"
	expectedCertificateClientID := ""

	actualCertificateClientName, actualCertificateClientID, _ := client.GetCertificateClientNameAndID()

	if actualCertificateClientName != expectedCertificateClientName {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientName, expectedCertificateClientName)
	}

	if actualCertificateClientID != expectedCertificateClientID {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientID, expectedCertificateClientID)
	}
}

func TestGetCertificateClientNameCommonNameOneDot(t *testing.T) {
	// common_name : agent.
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIDHDCCAgSgAwIBAgIQEz0zK5wijp7FaayGsrTMJTANBgkqhkiG9w0BAQsFADAm
MQwwCgYDVQQGEwNVU0ExFjAUBgNVBAoTDUNsb3VkIEZvdW5kcnkwHhcNMTcwODE0
MjEzMTM0WhcNMTgwODE0MjEzMTM0WjA3MQwwCgYDVQQGEwNVU0ExFjAUBgNVBAoT
DUNsb3VkIEZvdW5kcnkxDzANBgNVBAMTBmFnZW50LjCCASIwDQYJKoZIhvcNAQEB
BQADggEPADCCAQoCggEBALy5UzV1XrDOKLh/vsytQwp1PwY+2NmipfT/RM0SeZnS
Q7yEJVCj+IueH8ZcjMxdO3sWdWXLBRP/pVS6Hm1uTiy72r7uMiuNvlrVGDTB/9zk
hyhoXpreIP/BLZtozfEr2unEXFbz7xqb4Fa4uWvdOCgSwdWMel0IXqmQ0GsRk9wE
Uta33LUnUhaM0DnKUGTEg12cboUPR2f+KT7dHcOLIS/WpLJ41SaJ1LXkshP7K/gr
UVGWr524ST29/QexbI53Mlua17jE7HpBPqL0YNeIjF3kTSLaJjqBZ5SrJmP7UjdZ
YQPVFd0v9Lm0h4osr090RKs5HWpJzHXTDx7vR9q+wrMCAwEAAaM1MDMwDgYDVR0P
AQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAwDQYJ
KoZIhvcNAQELBQADggEBADeN7KWwzVe2Nz3Gg/uilA3Q7oBl0cbB2swcfeqKr+nc
WsqNnAlUtyzSBHu5+Fc5Pkf9Ie/6M76sWHS8cAubtMGG3aYxhyA37Q71tj9Zk6Qx
IItJY6NAIJnPB4WGY8hwsQos0KOF/f1yy0biwYqXL3Xd2cbvZV90C5iP7JKCyDrr
WRc7vBZ+xEnaUP7uvJXT6zUj3eg4ZpfxaCCxpSjWjQOTSGn96vR7H2c4IXJWw4Vg
zuVx86B+lWBpzx9pjXJODTW9elTmn9uBubQLkFtTuHuzzy2W92RsT5ukqDBzkbqz
DJ5c/ccblLatvbxBQ3EHv9sS/LyLyjlftsd4Q8oJg3w=
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	expectedCertificateClientName := "agent"
	expectedCertificateClientID := ""

	actualCertificateClientName, actualCertificateClientID, _ := client.GetCertificateClientNameAndID()

	if actualCertificateClientName != expectedCertificateClientName {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientName, expectedCertificateClientName)
	}

	if actualCertificateClientID != expectedCertificateClientID {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientID, expectedCertificateClientID)
	}
}

func TestGetCertificateClientNameCommonNameMultiDots(t *testing.T) {
	// common_name : agent.hello.bye
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIDJjCCAg6gAwIBAgIRAOQ81VCCUOJ7ijVZdHAW6SYwDQYJKoZIhvcNAQELBQAw
JjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQKEw1DbG91ZCBGb3VuZHJ5MB4XDTE3MDgx
NDIxMzEzM1oXDTE4MDgxNDIxMzEzM1owQDEMMAoGA1UEBhMDVVNBMRYwFAYDVQQK
Ew1DbG91ZCBGb3VuZHJ5MRgwFgYDVQQDEw9hZ2VudC5oZWxsby5ieWUwggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDTMYokqie2t/9cIMc//33eQ9lGCYRg
zeHwDXS24dIt5iKqXfazJ3fNpSOChuGAmYkI0ATqVn9pn3aVB3/P4s2NPpMakqxC
xROespZ6oqAw4cCAjr3C5RPM6/Gc11YvSXi4F8aeijEclP2PkBU6W9Pdq3axW9pB
EFy6k/xXC5ZaE1S6fAYQ2G1oTLEwdmJ/8U0ypwcy1aKSSm2/sq8LfqHDR6lzAEhv
93zQlMMExBesT8/c9ZEcEBhEYZ8d6mRA3lEEBHp3ku/RK04Hr7GOhvlWBiekd8NO
Mlkk3328zonpgJWgBVaTbQCHhpepGKA1kksKndrFqHasnMI+oELppX4PAgMBAAGj
NTAzMA4GA1UdDwEB/wQEAwIFoDATBgNVHSUEDDAKBggrBgEFBQcDAjAMBgNVHRMB
Af8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQAEes+hIkX9WuQo+WcnkneGZ69HF+gv
VhjJIu4AM5JZD8dAjpmLSwYPXxWBlqPmGi6mYGAftGqL1vX/huc7HbVDT+u+0h9Q
SovFFApz70gUtWQilfaWcggbiVUD8bjJqVZWZ8xSUzZ6zq/ENu5/Dm2OdOkCodhS
RRC3xQ5vmrN+kF5BBW5c0RYkllBfJ+fcAmvuzf0G9muSlihxbonZFfPzOriz1zPB
P+qJ8ZtGjqulB25ibSvbnHQ8Urszj5nfwfSJ8leI9DKlrUoF9C4CjNLAXmhrsqUg
xB1OnbVy1YO9SuUsexRU1gTj2US7zz7CBHiicZQFQy5fR/ROLNGO636z
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	expectedCertificateClientName := "agent"
	expectedCertificateClientID := "hello.bye"

	actualCertificateClientName, actualCertificateClientID, _ := client.GetCertificateClientNameAndID()

	if actualCertificateClientName != expectedCertificateClientName {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientName, expectedCertificateClientName)
	}

	if actualCertificateClientID != expectedCertificateClientID {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientID, expectedCertificateClientID)
	}
}

func TestGetCertificateClientNameCommonNameMultiConsecutiveDots(t *testing.T) {
	// common_name : agent...
	clientCertificate := `-----BEGIN CERTIFICATE-----
MIIDHzCCAgegAwIBAgIRAK/CbS1ioM24r422hqKf6ZUwDQYJKoZIhvcNAQELBQAw
JjEMMAoGA1UEBhMDVVNBMRYwFAYDVQQKEw1DbG91ZCBGb3VuZHJ5MB4XDTE3MDgx
NDIxMzEzM1oXDTE4MDgxNDIxMzEzM1owOTEMMAoGA1UEBhMDVVNBMRYwFAYDVQQK
Ew1DbG91ZCBGb3VuZHJ5MREwDwYDVQQDEwhhZ2VudC4uLjCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAL51FQEsMIOMj8g5S4on/ZNdb80Oysg028tRYwIF
myYLssA4yIWeKfB1et+y0UFb6+JFaOEa9Ly72bzqIeh9182ccQrWK6AitFd8hhk/
Cs+Mc65niASSs83RJwA33+FujbJWeF5b7YpDOuRQ2cWUFrOQTBUXf0uf2zpsIItD
mCAgmuaeeSStv9V52kB5vLidFhB+U01OvG3QaKwu2mXG18ejww0w9i46WJfQgS60
V77C08HCy2xs9KXpJ/1wb5H5zks0UAfrR+2wkmRCpoibtpRV0fBsfQqaeaXxTllV
j8f/VqXbHqSBp4HWy88y5oDfgMI5Re2ERs6cBpkgeK+WpgcCAwEAAaM1MDMwDgYD
VR0PAQH/BAQDAgWgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAw
DQYJKoZIhvcNAQELBQADggEBAAXo+uMechGfmzpUPFj4YPIexdgXjD/7LD5FQl7k
dt0gzZ8qDFqbtbybV0T+5twsT17TLhwTGkk5hwi+kA4n5Y40QlzZ4LTder8b8gVd
HxbVu7burGu9rxwfVtdeE8jZ6dLQFY4BEKf7z8h4v1hVCQsgCKncAuf7MLUhPre3
9nOQQvl9cPmJWmB2G/2lP2w1bACUJupbSPcaqMYlieFrFPsoV1Dl29E2G88pPLuy
zm4H3OvWEAndOeeXQp/RjKUFYCcQGzvNBhs65IuGfuDUzoTQW4+b7NqJ4NGTYehq
Qr6kwPBR4nh2c0nI7+fwwDVhEKk/oTvcQr1q+4kcy+MYytg=
-----END CERTIFICATE-----`

	cpb, _ := pem.Decode([]byte(clientCertificate))
	crt, _ := x509.ParseCertificate(cpb.Bytes)

	client := client{clientCertificate: crt}

	expectedCertificateClientName := "agent"
	expectedCertificateClientID := ".."

	actualCertificateClientName, actualCertificateClientID, _ := client.GetCertificateClientNameAndID()

	if actualCertificateClientName != expectedCertificateClientName {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientName, expectedCertificateClientName)
	}

	if actualCertificateClientID != expectedCertificateClientID {
		stackFatalf(t, "Expected %s to equal %s", actualCertificateClientID, expectedCertificateClientID)
	}
}