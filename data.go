package main

import (
	"bufio"
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"syscall"

	"golang.org/x/term"
)

// IsByteArrayZeros: Returns true if given byte array contains all zeros, false otherwise
func IsByteArrayZeros(_byteArray []byte) bool {

	var counter int
	var allZeros bool = true

	for counter = 0; counter != len(_byteArray); counter++ {

		if _byteArray[counter] != 0 {
			allZeros = false
			break
		}

	} // end for

	return allZeros
}

// GetUserInput: Gets user input from command line
func GetUserInput(_prompt string) string {

	var reader *bufio.Reader
	var inputStr string
	var userInput string

	var err error

	if len(_prompt) > 0 {

		// Display prompt stating type of data for user input
		fmt.Print(_prompt)

		// Read user input from command line
		reader = bufio.NewReader(os.Stdin)
		inputStr, err = reader.ReadString('\n')

		if err == nil && len(inputStr) > 0 {

			// Remove any linux carrige returns
			if strings.Contains(inputStr, "\n") {
				userInput = strings.Replace(inputStr, "\n", "", -1)
			}

			// Remove any windows carrige returns
			if strings.Contains(inputStr, "\r\n") {
				userInput = strings.Replace(inputStr, "\r\n", "", -1)
			}

		} else {
			fmt.Println(UI_FailedToReadCmdData)
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_prompt: "+_prompt))
	}

	return userInput
}

// GetUserYesOrNo: Gets a yes or no user response from the command line. Returns: true = yes, false = no
func GetUserYesOrNo(_defaultYes bool) bool {

	var reader *bufio.Reader
	var char rune
	var bytesRead int
	var yesOrNo bool

	var err error

	// Set return to given default
	yesOrNo = _defaultYes

	// Read a character from the command line
	reader = bufio.NewReader(os.Stdin)
	char, bytesRead, err = reader.ReadRune()

	if bytesRead == 1 && err == nil {

		if DEBUG == true {
			fmt.Println(fmt.Sprintf(UI_ReadChar, char))
		}

		if string(char) == "Y" || string(char) == "y" {
			yesOrNo = true
		}

		if string(char) == "N" || string(char) == "n" {
			yesOrNo = false
		}

		// If return pressed use given default
		if string(char) == "\n" || string(char) == "\r\n" || string(char) == "\r" {

			if _defaultYes == true {
				yesOrNo = true
			} else {
				yesOrNo = false
			}
		}

	} else {
		fmt.Println(UI_FailedToReadCmdData)
	}

	return yesOrNo
}

// GetPassword: Gets user password from command line
func GetUserPassword(_confirm bool) string {

	var passwordString string
	var confirmPasswordString string
	var returnPasswordString string

	if _confirm == false {

		// Read password once
		returnPasswordString = GetPassword(fmt.Sprintf(UI_EnterPassword))

	} else {

		// Read password twice
		passwordString = GetPassword(fmt.Sprintf(UI_EnterPassword))

		if len(passwordString) > 0 {

			confirmPasswordString = GetPassword(fmt.Sprintf(UI_ConfirmPassword))

			if len(confirmPasswordString) > 0 {

				if passwordString == confirmPasswordString {

					// Both passwords match
					returnPasswordString = confirmPasswordString

				} else {
					fmt.Println(UI_InvalidPassword)
				}

			} else {
				fmt.Println(UI_InvalidPassword)
			}

		} else {
			fmt.Println(UI_InvalidPassword)
		}

	}

	return returnPasswordString
}

// GetPassword: Gets user password from command line
func GetPassword(_passwordPrompt string) string {

	var reader *bufio.Reader
	var password []byte
	var passwordString string

	var err error

	if len(_passwordPrompt) > 0 {

		fmt.Print(_passwordPrompt)

		if DEBUG == true {

			// Echo password to terminal

			// Read user input from command line
			reader = bufio.NewReader(os.Stdin)
			passwordString, err = reader.ReadString('\n')

			if err == nil && len(passwordString) > 0 {

				// Remove any linux carrige returns
				passwordString = strings.Replace(passwordString, "\n", "", -1)

			} else {
				fmt.Println(UI_FailedToReadCmdData)
			}

		} else {

			// Do not echo password to terminal

			// Read user input from command line
			password, err = term.ReadPassword(int(syscall.Stdin))

			if err == nil && len(password) > 0 {

				// Convert password to string
				passwordString = string(password)

			} else {
				fmt.Println(UI_FailedToReadCmdData)
			}

			// Move onto next line in command line
			fmt.Println()
		}
	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_passwordPrompt: "+_passwordPrompt))
	}

	return passwordString
}

// GetPasswordMD5Hash: Gets the MD5 Hash for the given password
func GetPasswordMD5Hash(_password string) string {

	var passwordBytes []byte
	var MD5Hash [MD5_HASH_LENGTH]byte
	var passwordHash string

	if len(_password) > 0 {

		// Convert password string to password byte array
		passwordBytes = []byte(_password)

		if len(passwordBytes) == len(_password) {

			// Get MD5 Hash of password byte array
			MD5Hash = md5.Sum(passwordBytes)

			if len(MD5Hash) == MD5_HASH_LENGTH {

				// Convert MD5 Hash to string
				passwordHash = hex.EncodeToString(MD5Hash[:])

				if len(passwordHash) == PASSWORD_HASH_LENGTH {

					if DEBUG == true {
						fmt.Println(passwordHash)
					}

				} else {
					fmt.Println(UI_FailedToGeneratePasswordHash)
				}

			} else {
				fmt.Println(UI_FailedToGenerateMD5Hash)
			}

		} else {
			fmt.Println(UI_NoBufferMemory)
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_password: "+_password))
	}

	return passwordHash
}
