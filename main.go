// qrc project main.go
package main

import (
	"fmt"
	"os"
	"strings"
)

// Main: program entry point
func main() {

	var key string
	var keyParsed bool = false
	var plainText string
	var plainTextParsed bool = false
	var cipherText string
	var cipherTextParsed bool = false
	var publicKey string
	var publicKeyParsed bool = false
	var secretKey string
	var secretKeyParsed bool = false

	var keysGenerated bool = false
	var encrypted bool = false
	var decrypted bool = false
	var validated bool = false

	exitCode := 0

	if os.Args != nil {

		if DEBUG == true {
			fmt.Println(len(os.Args), UI_Arguments, os.Args)
		}

		if len(os.Args) == 1 {
			// No user arguments given - display help
			fmt.Println(UI_Help)
		}
		if len(os.Args) == 2 {
			if IsStringHelpArgument(os.Args[1]) {
				// User has given help argument - display help
				fmt.Println(UI_Help)
			} else if os.Args[1] == CMD_GENERATE_KEYS {
				// Generate keys
				if DEBUG == true {
					fmt.Println(CMD_GENERATE_KEYS)
				}
				keysGenerated = GenerateKeyPair()
				if keysGenerated == false {
					exitCode = 1
				}
			} else if strings.HasPrefix(os.Args[1], CMD_SHOW_KEY) {
				// Show key
				if DEBUG == true {
					fmt.Println(CMD_SHOW_KEY)
				}
				key, keyParsed = ParseCMDArgument(os.Args[1])
				if keyParsed == true {
					DisplayKey(key)
				} else {
					exitCode = 1
					fmt.Println(UI_InvalidArgs)
				}
			} else {
				// User has given only one argument that is not a help argument - display error
				exitCode = 1
				fmt.Println(UI_InvalidArgs)
				//File
			}
		}
		if len(os.Args) == 3 {
			// Wrong number of arguments - display error
			exitCode = 1
			fmt.Println(UI_InvalidArgs)
		}
		if len(os.Args) == 4 {
			if os.Args[1] == CMD_VALIDATE_KEYS {
				// Validate keys
				if DEBUG == true {
					fmt.Println(CMD_VALIDATE_KEYS)
				}
				if strings.HasPrefix(os.Args[2], CMD_SECRET) && strings.HasPrefix(os.Args[3], CMD_PUBLIC) {

					secretKey, publicKeyParsed = ParseCMDArgument(os.Args[2])
					publicKey, secretKeyParsed = ParseCMDArgument(os.Args[3])

					if secretKeyParsed == true && publicKeyParsed == true {
						if DEBUG == true {
							fmt.Println(fmt.Sprintf(UI_ValidateArgs, secretKey, publicKey))
						}
						validated = ValidateKeys(secretKey, publicKey)
						if validated == false {
							exitCode = 1
						}
					} else {
						exitCode = 1
						fmt.Println(UI_InvalidArgs)
					}

				} else {
					exitCode = 1
					fmt.Println(UI_InvalidArgs)
				}
			}
		}
		if len(os.Args) == 5 {
			if os.Args[1] == CMD_ENCRYPT {
				// Encrypt file
				if DEBUG == true {
					fmt.Println(CMD_ENCRYPT)
				}
				if strings.HasPrefix(os.Args[2], CMD_KEY) && strings.HasPrefix(os.Args[3], CMD_PLAINTEXT) && strings.HasPrefix(os.Args[4], CMD_CIPHERTEXT) {

					key, keyParsed = ParseCMDArgument(os.Args[2])
					plainText, plainTextParsed = ParseCMDArgument(os.Args[3])
					cipherText, cipherTextParsed = ParseCMDArgument(os.Args[4])

					if keyParsed == true && plainTextParsed == true && cipherTextParsed == true {
						if DEBUG == true {
							fmt.Println(fmt.Sprintf(UI_EncryptArgs, key, plainText, cipherText))
						}
						encrypted = Encrypt(key, plainText, cipherText)
						if encrypted == false {
							exitCode = 1
						}
					} else {
						exitCode = 1
						fmt.Println(UI_InvalidArgs)
					}

				} else {
					exitCode = 1
					fmt.Println(UI_InvalidArgs)
				}
			} else if os.Args[1] == CMD_DECRYPT {
				// Decrypt file
				if DEBUG == true {
					fmt.Println(CMD_DECRYPT)
				}
				if strings.HasPrefix(os.Args[2], CMD_KEY) && strings.HasPrefix(os.Args[3], CMD_CIPHERTEXT) && strings.HasPrefix(os.Args[4], CMD_PLAINTEXT) {

					key, keyParsed = ParseCMDArgument(os.Args[2])
					cipherText, cipherTextParsed = ParseCMDArgument(os.Args[3])
					plainText, plainTextParsed = ParseCMDArgument(os.Args[4])

					if keyParsed == true && plainTextParsed == true && cipherTextParsed == true {
						if DEBUG == true {
							fmt.Println(fmt.Sprintf(UI_DecryptArgs, key, cipherText, plainText))
						}
						decrypted = Decrypt(key, cipherText, plainText)
						if decrypted == false {
							exitCode = 1
						}
					} else {
						exitCode = 1
						fmt.Println(UI_InvalidArgs)
					}

				} else {
					exitCode = 1
					fmt.Println(UI_InvalidArgs)
				}

			} else {
				exitCode = 1
				fmt.Println(UI_InvalidArgs)
			}
		}
		if len(os.Args) > 5 {
			// Too many arguments - display error
			exitCode = 1
			fmt.Println(UI_InvalidArgs)
		}
	} else {
		// No arguments
		exitCode = 1
		fmt.Println(UI_NoParametersGiven)
	}

	os.Exit(exitCode)
}

// ParseCMDArgument: Parses given command line argument
func ParseCMDArgument(_argument string) (string, bool) {

	var splitKey []string
	var parsed bool = false
	var parsedArgument string

	if len(_argument) > 0 {

		splitKey = strings.Split(_argument, `=`)
		if len(splitKey) == 2 {
			if splitKey[1] != "" {
				parsedArgument = splitKey[1]
				parsed = true
				if DEBUG == true {
					fmt.Println(parsedArgument)
				}
			} else {
				fmt.Println(UI_InvalidArgs)
			}
		} else {
			fmt.Println(UI_InvalidArgs)
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_argument:"+_argument))
	}

	return parsedArgument, parsed

}

// IsStringHelpArgument: Returns true if given string is a help argument, false if it is not
func IsStringHelpArgument(_theString string) bool {

	isHelpArgument := false

	if len(_theString) > 0 {

		switch _theString {
		case "?":
			isHelpArgument = true
		case "/?":
			isHelpArgument = true
		case "-?":
			isHelpArgument = true
		case "--?":
			isHelpArgument = true
		case "h":
			isHelpArgument = true
		case "/h":
			isHelpArgument = true
		case "-h":
			isHelpArgument = true
		case "--h":
			isHelpArgument = true
		case "help":
			isHelpArgument = true
		case "/help":
			isHelpArgument = true
		case "-help":
			isHelpArgument = true
		case "--help":
			isHelpArgument = true
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_theString:"+_theString))
	}

	return isHelpArgument
}
