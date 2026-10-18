package rfc8176_test

import (
	"testing"

	"github.com/davfer/gorfc/rfc8176"
)

func TestAMRConstants(t *testing.T) {
	tests := []struct {
		constant string
		expected string
	}{
		{rfc8176.AMRFace, "face"},
		{rfc8176.AMRFpt, "fpt"},
		{rfc8176.AMRGeo, "geo"},
		{rfc8176.AMRHwk, "hwk"},
		{rfc8176.AMRIris, "iris"},
		{rfc8176.AMRKba, "kba"},
		{rfc8176.AMRMca, "mca"},
		{rfc8176.AMRMfa, "mfa"},
		{rfc8176.AMROtp, "otp"},
		{rfc8176.AMRPin, "pin"},
		{rfc8176.AMRPwd, "pwd"},
		{rfc8176.AMRRba, "rba"},
		{rfc8176.AMRRetina, "retina"},
		{rfc8176.AMRSc, "sc"},
		{rfc8176.AMRSms, "sms"},
		{rfc8176.AMRSwk, "swk"},
		{rfc8176.AMRTel, "tel"},
		{rfc8176.AMRUser, "user"},
		{rfc8176.AMRVbm, "vbm"},
		{rfc8176.AMRWia, "wia"},
	}

	for _, tt := range tests {
		if tt.constant != tt.expected {
			t.Errorf("expected constant %q, got %q", tt.expected, tt.constant)
		}
	}
}
