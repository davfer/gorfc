package rfc8176

// Authentication Method Reference (AMR) values registered in the IANA "Authentication Method Reference Values" Registry.
// Reference: RFC 8176, Section 2
const (
	// AMRFace indicates Facial recognition.
	// Reference: RFC 8176, Section 2
	AMRFace = "face"

	// AMRFpt indicates Fingerprint biometric.
	// Reference: RFC 8176, Section 2
	AMRFpt = "fpt"

	// AMRGeo indicates Geolocation.
	// Reference: RFC 8176, Section 2
	AMRGeo = "geo"

	// AMRHwk indicates Proof-of-possession of a hardware-secured key.
	// Reference: RFC 8176, Section 2
	AMRHwk = "hwk"

	// AMRIris indicates Iris scan biometric.
	// Reference: RFC 8176, Section 2
	AMRIris = "iris"

	// AMRKba indicates Knowledge-based authentication.
	// Reference: RFC 8176, Section 2
	AMRKba = "kba"

	// AMRMca indicates Multiple-channel authentication.
	// Reference: RFC 8176, Section 2
	AMRMca = "mca"

	// AMRMfa indicates Multiple-factor authentication.
	// Reference: RFC 8176, Section 2
	AMRMfa = "mfa"

	// AMROtp indicates One-time password.
	// Reference: RFC 8176, Section 2
	AMROtp = "otp"

	// AMRPin indicates Personal Identification Number.
	// Reference: RFC 8176, Section 2
	AMRPin = "pin"

	// AMRPwd indicates Password.
	// Reference: RFC 8176, Section 2
	AMRPwd = "pwd"

	// AMRRba indicates Risk-based authentication.
	// Reference: RFC 8176, Section 2
	AMRRba = "rba"

	// AMRRetina indicates Retina scan biometric.
	// Reference: RFC 8176, Section 2
	AMRRetina = "retina"

	// AMRSc indicates Smart card.
	// Reference: RFC 8176, Section 2
	AMRSc = "sc"

	// AMRSms indicates Confirmation using SMS.
	// Reference: RFC 8176, Section 2
	AMRSms = "sms"

	// AMRSwk indicates Proof-of-possession of a software-secured key.
	// Reference: RFC 8176, Section 2
	AMRSwk = "swk"

	// AMRTel indicates Confirmation via telephone call.
	// Reference: RFC 8176, Section 2
	AMRTel = "tel"

	// AMRUser indicates User presence test.
	// Reference: RFC 8176, Section 2
	AMRUser = "user"

	// AMRVbm indicates Voice biometrics.
	// Reference: RFC 8176, Section 2
	AMRVbm = "vbm"

	// AMRWia indicates Windows Integrated Authentication.
	// Reference: RFC 8176, Section 2
	AMRWia = "wia"
)
