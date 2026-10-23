package device

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestConfiguredDeviceEndpointsRejectEmptyQueryAndFragmentMarkers(t *testing.T) {
	issuer := "https://issuer.example"
	for _, uri := range []string{issuer + "/device?", issuer + "/device#", issuer + "/device?x=1", issuer + "/device#fragment"} {
		if validURI(uri, issuer) {
			t.Fatal("non-exact endpoint with query or fragment marker admitted")
		}
	}
}

func TestEnabledDeviceConfigMustFitCompleteVerificationURIBeforeSelection(t *testing.T) {
	issuer := "https://issuer.example"
	c := Config{Enabled: true, TenantID: "tenant", VerificationURI: issuer + "/" + strings.Repeat("v", 120), TokenEndpoint: issuer + "/token", AuthorizationEndpoint: issuer + "/device_authorization", TTL: time.Minute, PollInterval: 5 * time.Second, VerificationURICompleteBytes: 128, LookupLimit: 32}
	if validConfig(c, issuer) {
		t.Fatal("selected unusable complete-URI policy instead of rejecting configuration")
	}
	c.VerificationURICompleteBytes = 512
	if !validConfig(c, issuer) {
		t.Fatal("bounded complete-URI policy rejected")
	}
}

func TestDisabledDeviceServiceNeedsNoOwnersAndAdvertisesNothing(t *testing.T) {
	s, err := NewService(nil, Config{}, nil)
	if err != nil || s.Enabled() || s.Metadata() != (Metadata{}) || s.PollPolicy() != (PollPolicy{}) {
		t.Fatal("unselected optional device capability became mandatory or advertised", err)
	}
	if _, err := s.Authorize(context.Background(), DeviceRequest{}); !errors.Is(err, ErrAccessDenied) {
		t.Fatal("disabled device service issued authority", err)
	}
}
