package lxc

import (
	"fmt"
	"io"
	"text/template"
	"time"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/stacktrace"
)

var errorTemplate = template.Must(template.New("error").Parse(`Timestamp: {{.Timestamp}}
Code: {{.ECode}}
{{if .Message }}
Message: {{.Message}}
{{end}}
Frames:{{range $i, $frame := .Stack.Frames}}
---
{{$i}}: {{$frame.Function}}
Package: {{$frame.Package}}
File: {{$frame.File}}@{{$frame.Line}}{{end}}
`))

func newGenericError(err error, c libcontainer.ErrorCode) libcontainer.Error {
	if le, ok := err.(libcontainer.Error); ok {
		return le
	}
	gerr := &genericError{
		Timestamp: time.Now(),
		Err:       err,
		ECode:     c,
		Stack:     stacktrace.Capture(1),
	}
	if err != nil {
		gerr.Message = err.Error()
	}
	return gerr
}

func newSystemError(err error) libcontainer.Error {
	if le, ok := err.(libcontainer.Error); ok {
		return le
	}
	gerr := &genericError{
		Timestamp: time.Now(),
		Err:       err,
		ECode:     libcontainer.SystemError,
		Stack:     stacktrace.Capture(1),
	}
	if err != nil {
		gerr.Message = err.Error()
	}
	return gerr
}

type genericError struct {
	Timestamp time.Time
	ECode     libcontainer.ErrorCode
	Err       error `json:"-"`
	Message   string
	Stack     stacktrace.Stacktrace
}

func (e *genericError) Error() string {
	return fmt.Sprintf("[%d] %s: %s", e.ECode, e.ECode, e.Message)
}

func (e *genericError) Code() libcontainer.ErrorCode {
	return e.ECode
}

func (e *genericError) Detail(w io.Writer) error {
	return errorTemplate.Execute(w, e)
}
