package device_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	device "github.com/faustbrian/go-oauth-server/device"
)

func TestRFC8628DeviceRequestAndDiscriminatedPoll(t *testing.T) {
	r, err := device.ParseDeviceRequest("client_id=screen&scope=identity%3Aread&future=ignored", nil)
	if err != nil || r.ClientID != "screen" || len(r.Scopes) != 1 || r.Scopes[0] != "identity:read" || r.Network != "" {
		t.Fatal("bounded RFC8628 request/unknown-field handling failed", err)
	}
	code := strings.Repeat("A", 43)
	p, err := device.ParseTokenExchange("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Adevice_code&device_code="+code+"&client_id=screen", nil)
	if err != nil || p.DeviceCode != code || p.ClientID != "screen" {
		t.Fatal("RFC8628 extension grant not preserved", err)
	}
	for _, raw := range []string{
		"client_id=screen&client_id=other",
		"client_id=screen&client_secret=forbidden",
		"client_id=screen&scope=identity%3Aread+identity%3Aread",
		strings.Repeat("x", 16385),
	} {
		if _, err := device.ParseDeviceRequest(raw, nil); err == nil {
			t.Fatal("conflicting/unbounded device issuance admitted")
		}
	}
	for _, raw := range []string{
		"grant_type=refresh_token&device_code=" + code + "&client_id=screen",
		"grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=" + code + "&client_id=screen&scope=identity%3Aread",
		"grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=" + code + "&client_id=screen&device_code=" + code,
		"grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code=" + strings.Repeat("A", 42) + "B&client_id=screen",
	} {
		if _, err := device.ParseTokenExchange(raw, nil); err == nil {
			t.Fatal("foreign/conflicting/noncanonical device token grant admitted")
		}
	}
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("device bearer implicitly serialized")
	}
}

func TestUserCodeCanonicalizationRejectsConfusables(t *testing.T) {
	for _, raw := range []string{"bcdfghjk", "BCDF-GHJK", "bcdf-ghjk"} {
		if code, err := device.ParseUserCode(raw); err != nil || string(code) != "BCDF-GHJK" {
			t.Fatal("bounded explicit canonicalization failed", err)
		}
	}
	for _, raw := range []string{"ABCD-EFGH", "BCDF-OHJK", "BCDF GHJK", "BCDF-GHJK-", "ＢＣＤＦ-GHJK", strings.Repeat("X", 1025)} {
		if _, err := device.ParseUserCode(raw); !errors.Is(err, device.ErrAccessDenied) {
			t.Fatal("confusable/foreign user code widened enumeration surface", err)
		}
	}
}

func FuzzDeviceProtocolBounds(f *testing.F) {
	f.Add("client_id=screen&scope=identity%3Aread", "BCDF-GHJK")
	f.Add("client_id=%zz", "0000-OOOO")
	f.Add("grant_type=urn:ietf:params:oauth:grant-type:device_code&device_code="+strings.Repeat("A", 43)+"&client_id=screen", "bcdfghjk")
	f.Fuzz(func(t *testing.T, form, user string) {
		if r, err := device.ParseDeviceRequest(form, nil); err == nil && (len(form) > 16384 || len(r.ClientID) > 128 || r.Network != "") {
			t.Fatal("device request bounds lost")
		}
		if p, err := device.ParseTokenExchange(form, nil); err == nil && (len(form) > 16384 || len(p.DeviceCode) != 43 || p.Network != "") {
			t.Fatal("device poll bounds lost")
		}
		if code, err := device.ParseUserCode(user); err == nil && (len(code) != 9 || code[4] != '-') {
			t.Fatal("user-code canonical form lost")
		}
	})
}
