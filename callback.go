package jambo

type RequestType int

const (
	RequestTypeInvalid      RequestType = iota
	RequestTypeUserPassword             // regular authentication: user and password
	RequestTypeSendOTP                  // client is requesting OTP to be sent to their devices
	RequestTypeOTP                      // client has just sent the OTP to be checked
)

type Request struct {
	Type     RequestType
	Client   string
	User     string
	Password string
	MFAType  string
	OTPValue string
}

type ResponseType int

const (
	ResponseTypeInvalid     ResponseType = iota
	ResponseTypeOK                       // No errors
	ResponseTypeLoginOK                  // login is successful
	ResponseTypeLoginFailed              // login failed
	ResponseType2FANeeded                // login is successful so far, but we need 2FA
)

type Response struct {
	Type ResponseType // the following fields depend on this type:

	// If Type == ResponseTypeLoginOK:
	User   string // login for the user. Usually the same sent in the request.
	Name   string // user name and surname.
	Mail   string
	Groups []string
}
