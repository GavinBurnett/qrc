package main

import (
	"runtime"
)

// GetFunctionName: Gets the name of the currently running function
func GetFunctionName() string {

	data := make([]uintptr, 1)

	var functionName string
	functionName = ""

	callers := runtime.Callers(2, data)
	if callers != 0 {
		caller := runtime.FuncForPC(data[0] - 1)
		if caller != nil {
			functionName = caller.Name()
		}
	}
	return functionName
}
