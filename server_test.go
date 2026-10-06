package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"net"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

// The command channel is the part that can hang rather than fail, so it is
// exercised over a real handshake. `open` is refused by the local/remote split
// before it runs, which keeps the test off the machine's real config.
func TestCommandChannelReportsErrorAndExitStatus(t *testing.T) {
	client := commandSession(t)

	channel, requests, err := client.OpenChannel(commandChannel, ssh.Marshal(commandRequest{Command: "open"}))
	if err != nil {
		t.Fatalf("could not open command channel: %v", err)
	}
	defer channel.Close()

	status := make(chan uint32, 1)
	go func() {
		defer close(status)
		for request := range requests {
			var payload exitStatus
			if request.Type == "exit-status" && ssh.Unmarshal(request.Payload, &payload) == nil {
				status <- payload.Status
			}
		}
	}()

	stderr, err := io.ReadAll(channel.Stderr())
	if err != nil {
		t.Fatalf("could not read stderr: %v", err)
	}

	if !strings.Contains(string(stderr), "only takes `out`") {
		t.Errorf("unexpected server message: %q", stderr)
	}

	code, ok := <-status
	if !ok {
		t.Fatal("server never reported an exit status")
	}
	if code != 1 {
		t.Errorf("exit status is %d, want 1", code)
	}
}

func TestCommandChannelRejectsUnknownChannelType(t *testing.T) {
	client := commandSession(t)

	if _, _, err := client.OpenChannel("session", nil); err == nil {
		t.Error("a session channel was accepted")
	}
}

// commandSession wires a client to serveCommands over a loopback connection.
func commandSession(t *testing.T) *ssh.Client {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("could not listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	serverConfig := &ssh.ServerConfig{NoClientAuth: true}
	serverConfig.AddHostKey(testHostKey(t))

	go func() {
		accepted, err := listener.Accept()
		if err != nil {
			return
		}
		defer accepted.Close()

		serverConn, chans, reqs, err := ssh.NewServerConn(accepted, serverConfig)
		if err != nil {
			return
		}
		defer serverConn.Close()

		go ssh.DiscardRequests(reqs)
		serveCommands(chans, "1.2.3.4")
	}()

	clientSide, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("could not dial: %v", err)
	}

	clientConfig := &ssh.ClientConfig{
		User:            commandUser,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	conn, chans, reqs, err := ssh.NewClientConn(clientSide, listener.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("handshake failed: %v", err)
	}

	client := ssh.NewClient(conn, chans, reqs)
	t.Cleanup(func() { client.Close() })

	return client
}

func testHostKey(t *testing.T) ssh.Signer {
	t.Helper()

	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("could not generate a host key: %v", err)
	}

	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatalf("could not build a signer: %v", err)
	}

	return signer
}

func TestSourceKeyGroupsIPv6ByPrefix(t *testing.T) {
	if sourceKey("1.2.3.4") != "1.2.3.4" {
		t.Error("an IPv4 address is its own source")
	}
	if sourceKey("2001:db8:1:2::1") != sourceKey("2001:db8:1:2:ffff::9") {
		t.Error("two addresses in one /64 must be one source")
	}
	if sourceKey("2001:db8:1:2::1") == sourceKey("2001:db8:1:3::1") {
		t.Error("different /64s must be different sources")
	}
}

func TestSourceLimiterCapsEachSource(t *testing.T) {
	limiter := newSourceLimiter(2)
	if !limiter.acquire("a") || !limiter.acquire("a") {
		t.Fatal("a source must get up to the limit")
	}
	if limiter.acquire("a") {
		t.Error("a source must not get past the limit")
	}
	if !limiter.acquire("b") {
		t.Error("one source at its limit must not block another")
	}
	limiter.release("a")
	if !limiter.acquire("a") {
		t.Error("a released slot must be reusable")
	}
}
