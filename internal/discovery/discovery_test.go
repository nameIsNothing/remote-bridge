package discovery

import (
	"context"
	"encoding/json"
	"net"
	"strings"
	"testing"
	"time"
)

func testAnnouncement(nonce string) Announcement {
	return Announcement{
		V: Version, Type: AnnouncementType, InstanceID: "instance-1",
		Hostname: "WIN-TEST", Addresses: []string{"192.168.100.27"},
		Port: 5985, Transport: "http", Username: `WIN-TEST\RemoteBridge`,
		ExpiresAt: time.Now().Add(time.Minute), RequestNonce: nonce,
	}
}

func TestQueryAndAnnouncementRoundTrip(t *testing.T) {
	q, err := NewQuery()
	if err != nil {
		t.Fatal(err)
	}
	data, err := MarshalQuery(q)
	if err != nil {
		t.Fatal(err)
	}
	gotQ, err := UnmarshalQuery(data)
	if err != nil || gotQ != q {
		t.Fatalf("query round trip: %#v %v", gotQ, err)
	}
	a := testAnnouncement(q.RequestNonce)
	data, err = MarshalAnnouncement(a)
	if err != nil {
		t.Fatal(err)
	}
	gotA, err := UnmarshalAnnouncement(data)
	if err != nil {
		t.Fatal(err)
	}
	if gotA.InstanceID != a.InstanceID || gotA.RequestNonce != a.RequestNonce || !gotA.ExpiresAt.Equal(a.ExpiresAt) {
		t.Fatalf("announcement round trip: %#v", gotA)
	}
	if strings.Contains(string(data), "password") || strings.Contains(string(data), "state") {
		t.Fatalf("announcement contains prohibited field: %s", data)
	}
}

func TestUnknownFieldsAndInvalidValuesRejected(t *testing.T) {
	if _, err := UnmarshalQuery([]byte(`{"v":1,"type":"discover","request_nonce":"00000000000000000000000000000000","password":"x"}`)); err == nil {
		t.Fatal("secret field should be rejected")
	}
	bad := testAnnouncement("")
	bad.Addresses = []string{"127.0.0.1"}
	if err := bad.Validate(); err == nil {
		t.Fatal("loopback announcement address should be rejected")
	}
	if _, err := ParseBroadcastAddress("::1", DefaultPort); err == nil {
		t.Fatal("IPv6 broadcast address should be rejected")
	}
}

func TestResponderRepliesToQuery(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = ServeResponder(ctx, server, testAnnouncement("")) }()
	q, err := NewQuery()
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := MarshalQuery(q)
	if _, err := client.WriteToUDP(payload, server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	if err := client.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, MaxPacketSize)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	a, err := UnmarshalAnnouncement(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if a.RequestNonce != q.RequestNonce {
		t.Fatalf("nonce mismatch: %q != %q", a.RequestNonce, q.RequestNonce)
	}
}

func TestDiscoverCollectsAndDeduplicates(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	manager, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	go func() {
		buf := make([]byte, MaxPacketSize)
		n, from, err := server.ReadFromUDP(buf)
		if err != nil {
			return
		}
		q, err := UnmarshalQuery(buf[:n])
		if err != nil {
			return
		}
		a := testAnnouncement(q.RequestNonce)
		wrong := a
		wrong.InstanceID = "wrong-nonce"
		wrong.RequestNonce = strings.Repeat("f", 32)
		wrongPayload, _ := MarshalAnnouncement(wrong)
		_, _ = server.WriteToUDP(wrongPayload, from)
		payload, _ := MarshalAnnouncement(a)
		_, _ = server.WriteToUDP(payload, from)
		_, _ = server.WriteToUDP(payload, from)
	}()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	results, err := Discover(ctx, manager, "127.0.0.1", server.LocalAddr().(*net.UDPAddr).Port)
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || results[0].InstanceID != "instance-1" {
		t.Fatalf("unexpected discoveries: %#v", results)
	}
}

func TestAnnouncementJSONHasNoCredentialFields(t *testing.T) {
	a := testAnnouncement("")
	b, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"password", "token", "state_path", "script"} {
		if strings.Contains(string(b), field) {
			t.Fatalf("forbidden field %q in %s", field, b)
		}
	}
}

func TestPairRequestAndResponseRoundTrip(t *testing.T) {
	request := PairRequest{
		V:               Version,
		Type:            PairRequestType,
		InstanceID:      "instance-1",
		RequestNonce:    "0123456789abcdef0123456789abcdef",
		ManagerID:       "manager-1",
		ManagerHostname: "MANAGER",
		PublicKey:       "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm",
	}
	payload, err := MarshalPairRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	got, err := UnmarshalPairRequest(payload)
	if err != nil || got.PublicKey != request.PublicKey || got.RequestNonce != request.RequestNonce {
		t.Fatalf("request round trip: %#v %v", got, err)
	}
	response := PairResponse{
		V:            Version,
		Type:         PairResponseType,
		InstanceID:   request.InstanceID,
		RequestNonce: request.RequestNonce,
		Accepted:     true,
		Hostname:     "WIN-TEST",
		Port:         22022,
		Username:     "RemoteBridge",
		ExpiresAt:    time.Now().Add(time.Minute),
		HostKey:      request.PublicKey,
	}
	data, err := MarshalPairResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	gotResponse, err := UnmarshalPairResponse(data)
	if err != nil || !gotResponse.Accepted || gotResponse.Port != response.Port {
		t.Fatalf("response round trip: %#v %v", gotResponse, err)
	}
}

func TestPairResponseRejectsSecretLikeFields(t *testing.T) {
	request := PairRequest{
		V: Version, Type: PairRequestType, InstanceID: "instance-1",
		RequestNonce: "0123456789abcdef0123456789abcdef", ManagerID: "manager-1",
		ManagerHostname: "MANAGER", PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm",
	}
	data, err := json.Marshal(struct {
		PairRequest
		Password string `json:"password"`
	}{PairRequest: request, Password: "secret"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := UnmarshalPairRequest(data); err == nil {
		t.Fatal("pair request accepted unknown password field")
	}
}

func TestDiscoveryRemainsResponsiveDuringConsent(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pending := make(chan struct{})
	go ServeResponderWithPairing(ctx, server, testAnnouncement(""), func(ctx context.Context, r PairRequest, source *net.UDPAddr) PairResponse {
		close(pending)
		<-ctx.Done()
		return PairResponse{}
	})
	manager, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer manager.Close()
	request := PairRequest{V: Version, Type: PairRequestType, InstanceID: "instance-1", RequestNonce: strings.Repeat("a", 32), ManagerID: "manager-1", ManagerHostname: "MANAGER", PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm"}
	payload, err := MarshalPairRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.WriteToUDP(payload, server.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-pending:
	case <-time.After(time.Second):
		t.Fatal("pair handler did not run")
	}
	query, err := NewQuery()
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = MarshalQuery(query)
	_, _ = manager.WriteToUDP(payload, server.LocalAddr().(*net.UDPAddr))
	_ = manager.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, MaxPacketSize)
	n, _, err := manager.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("discovery blocked on consent: %v", err)
	}
	announcement, err := UnmarshalAnnouncement(buf[:n])
	if err != nil || announcement.RequestNonce != query.RequestNonce {
		t.Fatalf("unexpected discovery response: %v", err)
	}
	request.RequestNonce = strings.Repeat("b", 32)
	payload, _ = MarshalPairRequest(request)
	_, _ = manager.WriteToUDP(payload, server.LocalAddr().(*net.UDPAddr))
	n, _, err = manager.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	response, err := UnmarshalPairResponse(buf[:n])
	if err != nil || response.Accepted || response.RequestNonce != request.RequestNonce {
		t.Fatal("second pending confirmation was not safely rejected")
	}
}
