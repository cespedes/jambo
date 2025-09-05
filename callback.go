package jambo

// A Request is a message sent from the OIDC server to the authenticator,
// asking if a given credentials are valid
type Request struct {
	ID       string // unique ID for this user.
	Type     RequestType
	Client   string
	User     string
	Password string
	Token    string // if there is a token, send it here
	MFAType  string // valid for Type==RequestTypeSendOTP or Type==RequestTypeOTP
	OTPValue string // valid for Type==RequestTypeOTP
	Scopes   []string
}

type RequestType int

const (
	RequestTypeInvalid      RequestType = iota
	RequestTypeUserPassword             // regular authentication: user and password
	RequestTypeSendOTP                  // client is requesting OTP to be sent to their devices
	RequestTypeOTP                      // client has just sent the OTP to be checked
)

// A Response is sent from the authenticator to the OIDC server, answering a Request.
type Response struct {
	Type ResponseType // the following fields depend on this type:

	// Standard claims:

	// login for the user. It is usually the same sent in the request.
	// Used in claims "sub" and "preferred_username".
	User string

	// User name and surname.  Used in claim "name".
	Name string

	// e-mail address.  Used in claim "email".
	Mail string

	// List of groups
	Groups []string

	// Other claims:
	Claims map[string]any

	// If Type == ResponseType2FANeeded:
	MFAMethods []string // list of MFA methods this user accepts (e.g., "sms", "totp")
}

type ResponseType int

const (
	ResponseTypeInvalid     ResponseType = iota
	ResponseTypeOK                       // No errors
	ResponseTypeLoginOK                  // login is successful
	ResponseTypeLoginFailed              // login failed
	ResponseType2FANeeded                // login is successful so far, but we need 2FA
)
