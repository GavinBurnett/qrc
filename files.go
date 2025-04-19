package main

import (
	"fmt"
	"math"
	"os"
)

// FileExists: Check the given file exists
func FileExists(_file string) bool {

	var fileExists bool = false

	if len(_file) > 0 {

		// Try to get file info
		_, err := os.Stat(_file)

		// If any errors occur on getting file info, file does not exist
		if os.IsNotExist(err) || err != nil {
			if DEBUG == true {
				fmt.Println(fmt.Sprintf(UI_FileNotFound, _file))
			}
			fileExists = false
		} else {
			// File info found - file exists
			if DEBUG == true {
				fmt.Println(fmt.Sprintf(UI_FileFound, _file))
			}
			fileExists = true
		}
	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_file: "+_file))
	}

	return fileExists
}

// GetFileSize: Gets the size of the given file in bytes
func GetFileSize(_file string) int64 {

	var fileSize int64 = -1

	if len(_file) > 0 {

		// Get file info
		fileInfo, err := os.Stat(_file)
		if err == nil {

			// Get file size
			fileSize = fileInfo.Size()

			if fileSize == 0 {
				fmt.Println(UI_EmptyFile)
				fileSize = -1
			}

			if fileSize < 0 {
				fmt.Println(fmt.Sprintf(UI_InvalidFileSize, _file))
				fileSize = -1
			}

			if fileSize > math.MaxInt64 {
				fmt.Println(UI_FileTooBig)
				fileSize = -1
			}

		} else {
			fmt.Println(fmt.Sprintf(UI_NoFileSize, _file, err))
		}

	} else {
		fmt.Println(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_file:"+_file))
	}

	return fileSize
}

// DeleteFile: Delete the given file
func DeleteFile(_file string) bool {

	var deleteError bool = false
	var err error

	if len(_file) > 0 {
		err = os.Remove(_file)
		if err != nil {
			fmt.Println(fmt.Sprintf(UI_FileDeleteError, _file, err))
			deleteError = true
		} else {
			// File deleted
			if DEBUG == true {
				fmt.Println(fmt.Sprintf(UI_FileDeleted, _file))
			}
		}
	} else {
		fmt.Println(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()), "_file:", _file)
		deleteError = true
	}

	return deleteError
}
