package jambo

type ResultType int

const (
	ResultTypeOK     ResultType = iota // login is successful
	ResultTypeFailed                   // login failed
	ResultTypeAsk                      // login is successful so far, but we need more info
	ResultTypeChoose                   // login is successful so far, but we need more info
)

type Result struct {
	Type     ResultType
	Claims   map[string]string
	question string
	values   []string
	callback func(string) Result
}

var ResultLoginOK = Result{
	Type: ResultTypeOK,
}

var ResultLoginFailed = Result{
	Type: ResultTypeFailed,
}

func ResultLoginChoose(question string, values []string, callback func(string) Result) Result {
	return Result{
		Type:     ResultTypeChoose,
		question: question,
		values:   values,
		callback: callback,
	}
}

func ResultLoginAsk(question string, callback func(string) Result) Result {
	return Result{
		Type:     ResultTypeAsk,
		question: question,
		callback: callback,
	}
}
