package output

const (
	ExitCodeOK          = 0
	ExitCodeInputError  = 1
	ExitCodeEnvError    = 2
	ExitCodeInternalErr = 3
)

type AppError struct {
	Code    int
	Message string
	Hint    string
}

func (e *AppError) Error() string {
	if e == nil {
		return ""
	}
	return e.Message
}
