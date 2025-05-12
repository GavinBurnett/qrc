package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"time"
)

// Key: Data structure that defines private and public keys
type Key struct {
	magicNumber         int64                          // Magic number - secret or public
	ownerName           [OWNER_NAME_LENGTH]byte        // Name of key owner
	ownerEmail          [OWNER_EMAIL_LENGTH]byte       // E-Mail address of key owner
	keyType             [KEY_TYPE_LENGTH]byte          // Key type
	keyLength           int32                          // Key length
	keyRevoked          bool                           // Key revoked flag
	dateCreated         [DATE_CREATED_LENGTH]byte      // Key creation date
	secretKeyData       [SECRET_KEY_LENGTH]byte        // Decrypted secret key - held in memory only
	secretKeyCipherData [SECRET_KEY_CIPHER_LENGTH]byte // Encrypted secret key - stored on disk
	publicKeyData       [PUBLIC_KEY_LENGTH]byte        // Public key
	keySHA256Sum        [SHA256_HASH_LENGTH]byte       // SHA256 Sum of key
}

// GenerateKeyPair: Generate secret/public key pair
func GenerateKeyPair() bool {

	var secretKeyData *mlkem.DecapsulationKey1024
	var publicKeyData *mlkem.EncapsulationKey1024

	var ownerName string
	var ownerNameBytes [OWNER_NAME_LENGTH]byte

	var ownerEmail string
	var ownerEmailBytes [OWNER_EMAIL_LENGTH]byte

	var keyTypeBytes [KEY_TYPE_LENGTH]byte

	var currentDate time.Time
	var currentDateString string
	var currentDateBytes [DATE_CREATED_LENGTH]byte

	var publicKeyFileName string
	var secretKeyFileName string

	var encryptSecretKey bool = false
	var secretKeyCipherDataBytes [SECRET_KEY_CIPHER_LENGTH]byte
	var publicKeyDataBytes [PUBLIC_KEY_LENGTH]byte
	var emptySecretKeyBytes [SECRET_KEY_LENGTH]byte
	var emptySecretKeyCipherBytes [SECRET_KEY_CIPHER_LENGTH]byte
	var emptyPublicKeyBytes [PUBLIC_KEY_LENGTH]byte
	var emptySHA256SumBytes [SHA256_HASH_LENGTH]byte

	var savedSecretKey bool = false
	var savedPublicKey bool = false

	var secretKey Key
	var publicKey Key

	var keysGenerated bool = false

	var err error

	// Get key owner name
	ownerName = GetUserInput(fmt.Sprintf(UI_EnterKeyOwnerName))
	if len(ownerName) > 0 && len(ownerName) < OWNER_NAME_LENGTH {
		copy(ownerNameBytes[:], ownerName)
		if len(ownerNameBytes) == OWNER_NAME_LENGTH {

			// Get key owner e-mail
			ownerEmail = GetUserInput(fmt.Sprintf(UI_EnterKeyOwnerEMail))
			if len(ownerEmail) > 0 && len(ownerEmail) < OWNER_EMAIL_LENGTH {
				copy(ownerEmailBytes[:], ownerEmail)
				if len(ownerEmailBytes) == OWNER_EMAIL_LENGTH {

					// Set key type
					copy(keyTypeBytes[:], KEY_TYPE)
					if len(keyTypeBytes) == KEY_TYPE_LENGTH {

						// Set key creation date
						currentDate = time.Now().Local()
						currentDateString = currentDate.Format("02-01-2006")
						copy(currentDateBytes[:], currentDateString)
						if len(currentDateBytes) == DATE_CREATED_LENGTH {

							// Get public key file name
							publicKeyFileName = GetUserInput(fmt.Sprintf(UI_EnterPublicKeyFileName))
							if len(publicKeyFileName) > 0 {

								// Get secret key file name
								secretKeyFileName = GetUserInput(fmt.Sprintf(UI_EnterSecretKeyFileName))
								if len(secretKeyFileName) > 0 {

									// Generate decapsulation/secret key
									secretKeyData, err = mlkem.GenerateKey1024()

									if DEBUG == true {
										fmt.Println(fmt.Sprintf(UI_SecretKeyData, secretKeyData.Bytes()))
									}

									if err == nil {

										// Encrypt secret key
										encryptSecretKey, secretKeyCipherDataBytes = EncryptSecretKey(secretKeyData.Bytes())

										if encryptSecretKey == true && len(secretKeyCipherDataBytes) == SECRET_KEY_CIPHER_LENGTH {

											// Create secret key structure
											secretKey = Key{SECRET_KEY_MAGIC_NUMBER, ownerNameBytes, ownerEmailBytes, keyTypeBytes, KEY_LENGTH, false, currentDateBytes, emptySecretKeyBytes, secretKeyCipherDataBytes, emptyPublicKeyBytes, emptySHA256SumBytes}

											// Get SHA256 hash of secret key structure
											secretKey.keySHA256Sum = GetKeySHA256Sum(secretKey)

											// Save secret key structure to disk
											savedSecretKey = SaveKey(secretKey, secretKeyFileName, false)

											if savedSecretKey == true {

												// Extract the encapsulation/public key from the decapsulation/secret key
												publicKeyData = secretKeyData.EncapsulationKey()

												// Copy public key to fixed sized byte array
												copy(publicKeyDataBytes[:], publicKeyData.Bytes())

												if DEBUG == true {
													fmt.Println(fmt.Sprintf(UI_PublicKeyData, publicKeyData.Bytes()))
												}

												if len(publicKeyDataBytes) == PUBLIC_KEY_LENGTH {

													// Create public key structure
													publicKey = Key{PUBLIC_KEY_MAGIC_NUMBER, ownerNameBytes, ownerEmailBytes, keyTypeBytes, KEY_LENGTH, false, currentDateBytes, emptySecretKeyBytes, emptySecretKeyCipherBytes, publicKeyDataBytes, emptySHA256SumBytes}

													// Get SHA256 hash of public key structure
													publicKey.keySHA256Sum = GetKeySHA256Sum(publicKey)

													// Save public key structure to disk
													savedPublicKey = SaveKey(publicKey, publicKeyFileName, false)

													if savedPublicKey == true {
														fmt.Println(UI_KeysGeneratedOK)
														keysGenerated = true

													} else {
														fmt.Println(UI_FailedToSavePublicKey)
													}

												} else {
													fmt.Println(UI_FailedToCreatePublicKey)
												}

											} else {
												fmt.Println(UI_FailedToSaveSecretKey)
											}

										} else {
											fmt.Println(UI_FailedToEncryptSecretKey)
										}

									} else {
										fmt.Println(UI_FailedToGenerateSecretKey)
									}

								} else {
									fmt.Println(UI_FailedToGetSecretKeyName)
								}

							} else {
								fmt.Println(UI_FailedToGetPublicKeyName)
							}

						} else {
							fmt.Println(UI_FailedToSetDate)
						}

					} else {
						fmt.Println(UI_FailedToSetKeyType)
					}

				} else {
					fmt.Println(UI_FailedToGetOwnerEMail)
				}

			} else {
				fmt.Println(UI_FailedToGetOwnerEMail)
			}

		} else {
			fmt.Println(UI_FailedToGetOwnerName)
		}

	} else {
		fmt.Println(UI_FailedToGetOwnerName)
	}

	return keysGenerated
}

// EncryptSecretKey: Encrypt secret key
func EncryptSecretKey(_secretKeyDataBytes []byte) (bool, [SECRET_KEY_CIPHER_LENGTH]byte) {

	var password string
	var passwordHash string
	var cipherBlock cipher.Block
	var gcm cipher.AEAD
	var nonce []byte
	var bytesRead int
	var secretKeyGetCipherDataBytes []byte
	var secretKeyCipherDataBytes [SECRET_KEY_CIPHER_LENGTH]byte
	var encrypted bool = false

	var err error

	if len(_secretKeyDataBytes) == SECRET_KEY_LENGTH {

		// Get password to encrypt with
		password = GetUserPassword(true)

		if len(password) > 0 {

			// Get MD5 hash of password
			passwordHash = GetPasswordMD5Hash(password)

			if len(passwordHash) == PASSWORD_HASH_LENGTH {

				// Use 32 bit MD5 password hash to create AES-256 block cipher
				cipherBlock, err = aes.NewCipher([]byte(passwordHash))

				if cipherBlock.BlockSize() == CIPHER_BLOCK_LENGTH && err == nil {

					// Create a GCM cipher
					gcm, err = cipher.NewGCM(cipherBlock)
					if err == nil {

						// Create nonce
						nonce = make([]byte, gcm.NonceSize())

						if len(nonce) == gcm.NonceSize() {

							bytesRead, err = io.ReadFull(rand.Reader, nonce)

							if bytesRead == len(nonce) && err == nil {

								// Encrypt secret key
								secretKeyGetCipherDataBytes = gcm.Seal(nonce, nonce, _secretKeyDataBytes, nil)

								if len(secretKeyGetCipherDataBytes) > 0 {

									// Copy encrypted secret key to fixed sized byte array
									copy(secretKeyCipherDataBytes[:], secretKeyGetCipherDataBytes)

									if len(secretKeyCipherDataBytes) == SECRET_KEY_CIPHER_LENGTH {

										encrypted = true

										if DEBUG == true {
											fmt.Println(UI_PasswordEncrypted)
										}

									} else {
										fmt.Println(UI_FailedToEncrypt)
									}

								} else {
									fmt.Println(UI_FailedToEncryptSecretKey)
								}

							} else {
								fmt.Println(UI_FailedToGenerateNonce)
							}

						} else {
							fmt.Println(UI_FailedToGenerateNonce)
						}

					} else {
						fmt.Println(UI_FailedToCreateGCM)
					}

				} else {
					fmt.Println(UI_FailedToCreateCipherBlock)
				}

			} else {
				fmt.Println(UI_InvalidHashPhrase)
			}

		} else {
			fmt.Println(UI_InvalidPassword)
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
	}

	return encrypted, secretKeyCipherDataBytes
}

// DecryptSecretKey: Decrypt secret key
func DecryptSecretKey(_secretKeyCipherDataBytes [SECRET_KEY_CIPHER_LENGTH]byte) (bool, [SECRET_KEY_LENGTH]byte) {

	var secretKeySetCipherDataBytes []byte
	var password string
	var passwordHash string
	var cipherBlock cipher.Block
	var gcm cipher.AEAD
	var nonceSize int
	var nonce []byte
	var secretKeyGetCipherDataBytes []byte
	var secretKeyGetDataBytes []byte
	var secretKeyDataBytes [SECRET_KEY_LENGTH]byte
	var decrypted bool = false

	var err error

	if len(_secretKeyCipherDataBytes) == SECRET_KEY_CIPHER_LENGTH {

		// Copy secret key to non fixed sized byte array
		secretKeySetCipherDataBytes = _secretKeyCipherDataBytes[:]

		if len(secretKeySetCipherDataBytes) == SECRET_KEY_CIPHER_LENGTH {

			// Get password to encrypt with
			password = GetUserPassword(false)

			if len(password) > 0 {

				// Get MD5 hash of password
				passwordHash = GetPasswordMD5Hash(password)

				if len(passwordHash) == PASSWORD_HASH_LENGTH {

					// Use 32 bit MD5 password hash to create AES-256 block cipher
					cipherBlock, err = aes.NewCipher([]byte(passwordHash))

					if cipherBlock.BlockSize() == CIPHER_BLOCK_LENGTH && err == nil {

						// Create a GCM cipher
						gcm, err = cipher.NewGCM(cipherBlock)

						if err == nil {

							// Get nonce size
							nonceSize = gcm.NonceSize()

							// Get nonce and encrypted secret key
							nonce, secretKeyGetCipherDataBytes = secretKeySetCipherDataBytes[:nonceSize], secretKeySetCipherDataBytes[nonceSize:]

							// Decrypt encrypted secret key
							secretKeyGetDataBytes, err = gcm.Open(nil, nonce, secretKeyGetCipherDataBytes, nil)

							if len(secretKeyGetDataBytes) == SECRET_KEY_LENGTH {

								// Copy decrypted secret key to fixed sized byte array
								copy(secretKeyDataBytes[:], secretKeyGetDataBytes)

								if len(secretKeyDataBytes) == SECRET_KEY_LENGTH {

									decrypted = true

									if DEBUG == true {
										fmt.Println(UI_KeyDecrypted)
									}

								} else {
									fmt.Println(UI_NoBufferMemory)
								}

							} else {
								fmt.Println(UI_FailedToDecrypt)
							}

						} else {
							fmt.Println(UI_FailedToCreateGCM)
						}

					} else {
						fmt.Println(UI_FailedToCreateCipherBlock)
					}

				} else {
					fmt.Println(UI_InvalidPassword)
				}

			} else {
				fmt.Println(UI_InvalidPassword)
			}

		} else {
			fmt.Println(UI_DataCopyError)
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
	}

	return decrypted, secretKeyDataBytes
}

// GetKeySHA256Sum: Gets the SHA256 Sum for the given key
func GetKeySHA256Sum(_key Key) [SHA256_HASH_LENGTH]byte {

	var tempKey Key
	var emptySHA256Sum [SHA256_HASH_LENGTH]byte
	var keyBuffer bytes.Buffer
	var SHA256Sum [SHA256_HASH_LENGTH]byte

	var err error

	if _key.magicNumber == SECRET_KEY_MAGIC_NUMBER || _key.magicNumber == PUBLIC_KEY_MAGIC_NUMBER {

		// Create temp key
		tempKey = _key

		if tempKey.magicNumber == _key.magicNumber {

			// Clear temp key SHA256 Sum
			tempKey.keySHA256Sum = emptySHA256Sum

			// Copy temp key to binary key buffer
			err = binary.Write(&keyBuffer, binary.LittleEndian, tempKey)

			if err == nil {

				// Get SHA256 Sum of data in binary key buffer
				SHA256Sum = sha256.Sum256(keyBuffer.Bytes())

				if len(SHA256Sum) == SHA256_HASH_LENGTH {

					if DEBUG == true {
						fmt.Print(fmt.Sprintf(UI_PublicKeyData, _key))
						fmt.Print(fmt.Sprintf(UI_SHA256Sum, fmt.Sprintf("%x", SHA256Sum)))
					}

				} else {
					fmt.Println(UI_FailedToGenerateSHA256Sum)
				}

			} else {
				fmt.Println(UI_NoBufferMemory)
			}

		} else {
			fmt.Println(UI_FailedToCreateTempKey)
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
	}

	return SHA256Sum
}

// GetKeyDataSHA256Sum: Gets the SHA256 Sum for the given key data
func GetKeyDataSHA256Sum(_keyData []byte) (bool, [SHA256_HASH_LENGTH]byte) {

	var SHA256Sum [SHA256_HASH_LENGTH]byte
	var gotSHA256Sum bool = false

	if len(_keyData) > 0 {

		// Get SHA256 Sum of given key data
		SHA256Sum = sha256.Sum256(_keyData)

		// Check SHA256 Sum is valid
		if len(SHA256Sum) == SHA256_HASH_LENGTH {

			if IsByteArrayZeros(SHA256Sum[:]) == false {

				if DEBUG == true {
					fmt.Print(fmt.Sprintf(UI_PublicKeyData, _keyData))
					fmt.Print(fmt.Sprintf(UI_SHA256Sum, fmt.Sprintf("%x", SHA256Sum)))
				}

				gotSHA256Sum = true

			} else {
				fmt.Println(UI_FailedToGenerateSHA256Sum)
			}

		} else {
			fmt.Println(UI_FailedToGenerateSHA256Sum)
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
	}

	return gotSHA256Sum, SHA256Sum
}

// CheckKeySHA256Sum: Checks that SHA256 Sum stored in given key matches sum calculated from given key
func CheckKeySHA256Sum(_key Key) bool {

	var keySHA256Sum [SHA256_HASH_LENGTH]byte
	var sumValid bool = false

	// Check given key has valid public or secret key magic number
	if _key.magicNumber == SECRET_KEY_MAGIC_NUMBER || _key.magicNumber == PUBLIC_KEY_MAGIC_NUMBER {

		// Get SHA256 Sum of given key
		keySHA256Sum = GetKeySHA256Sum(_key)

		if _key.keySHA256Sum == keySHA256Sum {

			if DEBUG == true {
				fmt.Print(fmt.Sprintf(UI_SHA256Matches, _key.keySHA256Sum, keySHA256Sum))
			}

			sumValid = true

		} else {

			if DEBUG == true {
				fmt.Print(fmt.Sprintf(UI_SHA256DoesNotMatch, _key.keySHA256Sum, keySHA256Sum))
			}
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
	}

	return sumValid
}

// DisplayKey: Loads and displays the details of the given key file
func DisplayKey(_fileName string) {

	var displayKey Key
	var keyLoaded bool = false

	if len(_fileName) > 0 {

		if FileExists(_fileName) == true {

			// Load the key
			displayKey, keyLoaded = LoadKeyFile(_fileName)

			if keyLoaded == true {

				// Display key details

				if displayKey.magicNumber == PUBLIC_KEY_MAGIC_NUMBER {
					fmt.Println(UI_PublicKey)
				}
				if displayKey.magicNumber == SECRET_KEY_MAGIC_NUMBER {
					fmt.Println(UI_SecretKey)
				}

				fmt.Println(fmt.Sprintf(UI_KeyOwnerName, string(bytes.Trim(displayKey.ownerName[:], "\x00"))))
				fmt.Println(fmt.Sprintf(UI_KeyOwnerEMail, string(bytes.Trim(displayKey.ownerEmail[:], "\x00"))))
				fmt.Println(fmt.Sprintf(UI_KeyType, string(bytes.Trim(displayKey.keyType[:], "\x00"))))
				fmt.Println(fmt.Sprintf(UI_DateCreated, string(bytes.Trim(displayKey.dateCreated[:], "\x00"))))
				fmt.Println(fmt.Sprintf(UI_SHA256Sum, fmt.Sprintf("%x", displayKey.keySHA256Sum)))

				if displayKey.keyRevoked == true {
					fmt.Println(UI_KeyRevoked)
				}

			} else {
				fmt.Println(UI_FailedToLoadKey)
			}

		} else {
			fmt.Println(fmt.Sprintf(UI_FileNotFound, _fileName))
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_fileName: "+_fileName))
	}
}

// LoadKey: Loads the given key file
func LoadKey(_fileName string) (Key, bool) {

	var loadKey Key
	var fileLoaded bool = false
	var secretKeyDataDecrypted bool = false
	var secretKeyData [SECRET_KEY_LENGTH]byte
	var loaded bool = false

	if len(_fileName) > 0 {

		// Load key from disk
		loadKey, fileLoaded = LoadKeyFile(_fileName)

		if fileLoaded == true {

			if loadKey.magicNumber == SECRET_KEY_MAGIC_NUMBER {

				if loadKey.keyRevoked == false {

					if CheckKeySHA256Sum(loadKey) == true {

						// Decrypt secret key data
						secretKeyDataDecrypted, secretKeyData = DecryptSecretKey(loadKey.secretKeyCipherData)

						if secretKeyDataDecrypted == true && len(secretKeyData) == SECRET_KEY_LENGTH {

							// Add decrypted secret key data to key structure
							loadKey.secretKeyData = secretKeyData

							if DEBUG == true {
								fmt.Println(fmt.Sprintf(UI_LoadedSecretKey, loadKey))
							}

							loaded = true

						} else {
							fmt.Println(UI_FailedToDecryptSecretKey)
						}

					} else {
						fmt.Println(UI_InvalidSHA256Sum)
					}

				} else {
					fmt.Println(UI_KeyRevoked)
				}
			}

			if loadKey.magicNumber == PUBLIC_KEY_MAGIC_NUMBER {

				if loadKey.keyRevoked == false {

					if CheckKeySHA256Sum(loadKey) == true {

						if DEBUG == true {
							fmt.Println(fmt.Sprintf(UI_LoadedPublicKey, loadKey))
						}

						loaded = true

					} else {
						fmt.Println(UI_InvalidSHA256Sum)
					}

				} else {
					fmt.Println(UI_KeyRevoked)
				}
			}

		} else {
			fmt.Println(UI_FailedToLoadKey)
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_fileName: "+_fileName))
	}

	return loadKey, loaded
}

// LoadKeyFile: Loads the given key file from disk
func LoadKeyFile(_fileName string) (Key, bool) {

	var keyFile *os.File

	var magicNumber int64
	var ownerName [OWNER_NAME_LENGTH]byte
	var ownerEmail [OWNER_EMAIL_LENGTH]byte
	var keyType [KEY_TYPE_LENGTH]byte
	var keyLength int32
	var keyRevoked bool
	var dateCreated [DATE_CREATED_LENGTH]byte
	var secretKeyData [SECRET_KEY_LENGTH]byte
	var secretKeyCipherData [SECRET_KEY_CIPHER_LENGTH]byte
	var publicKeyData [PUBLIC_KEY_LENGTH]byte
	var keySHA256Sum [SHA256_HASH_LENGTH]byte

	var loadKey Key
	var fileLoaded bool = false

	var err error

	if len(_fileName) > 0 {

		if FileExists(_fileName) == true {

			// Load key data from key file
			keyFile, err = os.OpenFile(_fileName, os.O_RDONLY, 0)

			if err == nil {
				err = binary.Read(keyFile, binary.LittleEndian, &magicNumber)
				if err == nil {
					err = binary.Read(keyFile, binary.LittleEndian, &ownerName)
					if err == nil {
						err = binary.Read(keyFile, binary.LittleEndian, &ownerEmail)
						if err == nil {
							err = binary.Read(keyFile, binary.LittleEndian, &keyType)
							if err == nil {
								err = binary.Read(keyFile, binary.LittleEndian, &keyLength)
								if err == nil {
									err = binary.Read(keyFile, binary.LittleEndian, &keyRevoked)
									if err == nil {
										err = binary.Read(keyFile, binary.LittleEndian, &dateCreated)
										if err == nil {
											err = binary.Read(keyFile, binary.LittleEndian, &secretKeyData)
											if err == nil {
												err = binary.Read(keyFile, binary.LittleEndian, &secretKeyCipherData)
												if err == nil {
													err = binary.Read(keyFile, binary.LittleEndian, &publicKeyData)
													if err == nil {
														err = binary.Read(keyFile, binary.LittleEndian, &keySHA256Sum)
														if err == nil {

															// Load key data into key structure
															loadKey = Key{magicNumber, ownerName, ownerEmail, keyType, keyLength, keyRevoked, dateCreated, secretKeyData, secretKeyCipherData, publicKeyData, keySHA256Sum}
															fileLoaded = true

														} else {
															fmt.Println(fmt.Sprintf(UI_FileReadError, _fileName, err))
														}

													} else {
														fmt.Println(fmt.Sprintf(UI_FileReadError, _fileName, err))
													}

												} else {
													fmt.Println(fmt.Sprintf(UI_FileReadError, _fileName, err))
												}

											} else {
												fmt.Println(fmt.Sprintf(UI_FileReadError, _fileName, err))
											}

										} else {
											fmt.Println(fmt.Sprintf(UI_FileReadError, _fileName, err))
										}

									} else {
										fmt.Println(fmt.Sprintf(UI_FileReadError, _fileName, err))
									}

								} else {
									fmt.Println(fmt.Sprintf(UI_FileReadError, _fileName, err))
								}

							} else {
								fmt.Println(fmt.Sprintf(UI_FileReadError, _fileName, err))
							}

						} else {
							fmt.Println(fmt.Sprintf(UI_FileReadError, _fileName, err))
						}

					} else {
						fmt.Println(fmt.Sprintf(UI_FileReadError, _fileName, err))
					}

				} else {
					fmt.Println(fmt.Sprintf(UI_FileReadError, _fileName, err))
				}

			} else {
				fmt.Println(UI_FailedToLoadKey)
			}

			keyFile.Close()

		} else {
			fmt.Println(fmt.Sprintf(UI_FileNotFound, _fileName))
		}
	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_fileName: "+_fileName))
	}

	return loadKey, fileLoaded
}

// SaveKey: Save given key to given key filename
func SaveKey(_key Key, _fileName string, _overwrite bool) bool {

	var secretKeyFile *os.File
	var savedOk = false

	var err error

	if _key.magicNumber == SECRET_KEY_MAGIC_NUMBER || _key.magicNumber == PUBLIC_KEY_MAGIC_NUMBER {

		if FileExists(_fileName) == false || _overwrite == true {

			// Create file for key
			secretKeyFile, err = os.Create(_fileName)

			if err == nil {

				// Write key data to key file
				err = binary.Write(secretKeyFile, binary.LittleEndian, _key)

				if err == nil {

					if DEBUG == true {
						fmt.Println(UI_KeySaved)
					}

					savedOk = true

				} else {
					fmt.Println(fmt.Sprintf(UI_FileWriteError, _fileName, err))
				}

			} else {
				fmt.Println(fmt.Sprintf(UI_FileCreateError, _fileName))
			}

			secretKeyFile.Sync()
			secretKeyFile.Close()

		} else {
			fmt.Println(fmt.Sprintf(UI_FileAlreadyExists, _fileName))
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
	}

	return savedOk
}

// ValidateKeys: Validates given keys - checks given public key is the correct pair for the given secret key
func ValidateKeys(_secretKeyFileName string, _publicKeyFileName string) bool {

	var secretKeyLoaded bool
	var secretKey Key
	var publicKeyLoaded bool
	var publicKey Key

	var decapsulationKey *mlkem.DecapsulationKey1024
	var encapsulationKey *mlkem.EncapsulationKey1024

	var derivedKeySHA256Sum [SHA256_HASH_LENGTH]byte
	var gotDerivedKeySHA256Sum bool
	var givenKeySHA256Sum [SHA256_HASH_LENGTH]byte
	var gotGivenKeySHA256Sum bool

	var keysValid bool

	var err error

	secretKeyLoaded = false
	publicKeyLoaded = false
	gotDerivedKeySHA256Sum = false
	gotGivenKeySHA256Sum = false
	keysValid = false

	if len(_secretKeyFileName) > 0 && len(_publicKeyFileName) > 0 {

		// Check secret and public key files exist
		if FileExists(_secretKeyFileName) == true {

			if FileExists(_publicKeyFileName) == true {

				// Load the secret key
				secretKey, secretKeyLoaded = LoadKey(_secretKeyFileName)

				if secretKeyLoaded == true {

					// Load the public key
					publicKey, publicKeyLoaded = LoadKey(_publicKeyFileName)

					if publicKeyLoaded == true {

						// Check secret key is valid
						if secretKey.magicNumber == SECRET_KEY_MAGIC_NUMBER {

							// Check public key is valid
							if publicKey.magicNumber == PUBLIC_KEY_MAGIC_NUMBER {

								// Get secret key from secret key data
								decapsulationKey, err = mlkem.NewDecapsulationKey1024(secretKey.secretKeyData[:])

								if len(decapsulationKey.Bytes()) == SECRET_KEY_LENGTH && err == nil {

									// Extract the encapsulation/public key from the decapsulation/secret key
									encapsulationKey = decapsulationKey.EncapsulationKey()

									if DEBUG == true {
										fmt.Println(fmt.Sprintf(UI_PublicKeyData, encapsulationKey.Bytes()))
										fmt.Println(fmt.Sprintf(UI_PublicKeyData, publicKey.publicKeyData[:]))
									}

									if len(encapsulationKey.Bytes()) == PUBLIC_KEY_LENGTH {

										// Check extracted encapsulation/public key data has the same SHA256 Sum as the given public key data
										gotDerivedKeySHA256Sum, derivedKeySHA256Sum = GetKeyDataSHA256Sum(encapsulationKey.Bytes())
										gotGivenKeySHA256Sum, givenKeySHA256Sum = GetKeyDataSHA256Sum(publicKey.publicKeyData[:])

										if DEBUG == true {
											fmt.Print(fmt.Sprintf(UI_SHA256Sum, fmt.Sprintf("%x", derivedKeySHA256Sum)))
											fmt.Print(fmt.Sprintf(UI_SHA256Sum, fmt.Sprintf("%x", givenKeySHA256Sum)))
										}

										if gotDerivedKeySHA256Sum == true && gotGivenKeySHA256Sum == true {

											if derivedKeySHA256Sum == givenKeySHA256Sum {

												fmt.Println(fmt.Sprintf(UI_PublicKeyFromSecretKey, _publicKeyFileName, _secretKeyFileName))
												keysValid = true

											} else {
												fmt.Println(fmt.Sprintf(UI_PublicKeyNotFromSecretKey, _publicKeyFileName, _secretKeyFileName))
											}

										} else {
											fmt.Println(UI_FailedToGenerateSHA256Sum)
										}

									} else {
										fmt.Println(UI_FailedToCreatePublicKey)
									}

								} else {
									fmt.Println(UI_KeyNotValid)
								}

							} else {
								fmt.Println(UI_KeyNotValid)
							}

						} else {
							fmt.Println(UI_KeyNotValid)
						}

					} else {
						fmt.Println(UI_FailedToLoadKey)
					}

				} else {
					fmt.Println(UI_FailedToLoadKey)
				}

			} else {
				fmt.Println(fmt.Sprintf(UI_FileNotFound, _publicKeyFileName))
			}

		} else {
			fmt.Println(fmt.Sprintf(UI_FileNotFound, _secretKeyFileName))
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_secretKeyFileName: "+_secretKeyFileName+"_publicKeyFileName: "+_publicKeyFileName))
	}

	return keysValid

}

// RevokeKeys: Revokes the given secret and public keys
func RevokeKeys(_secretKeyFileName string, _publicKeyFileName string) bool {

	var confirmRevoke bool
	var validated bool
	var secretKeyLoaded bool
	var secretKey Key
	var publicKeyLoaded bool
	var publicKey Key
	var emptySecretKeyCipherBytes [SECRET_KEY_CIPHER_LENGTH]byte
	var emptyPublicKeyBytes [PUBLIC_KEY_LENGTH]byte
	var secretKeySaved bool
	var publicKeySaved bool
	var revoked bool

	confirmRevoke = false
	validated = false
	secretKeyLoaded = false
	publicKeyLoaded = false
	secretKeySaved = false
	revoked = false

	if len(_secretKeyFileName) > 0 && len(_publicKeyFileName) > 0 {

		// Confirm key revoke
		fmt.Println(fmt.Sprintf(UI_RevokeWarning, _secretKeyFileName, _publicKeyFileName))
		fmt.Print(UI_ConfirmNoDefault)
		confirmRevoke = GetUserYesOrNo(false)

		if confirmRevoke == true {

			// Prompt for secret key password
			fmt.Println(UI_RevokePassword)

			// Check given secret and public keys match (are a key pair)
			validated = ValidateKeys(_secretKeyFileName, _publicKeyFileName)
			if validated == true {

				// Prompt again for secret key password
				fmt.Println(UI_ConfirmRevokePassword)

				// Load the secret key
				secretKey, secretKeyLoaded = LoadKey(_secretKeyFileName)

				if secretKeyLoaded == true {

					// Load the public key
					publicKey, publicKeyLoaded = LoadKey(_publicKeyFileName)

					if publicKeyLoaded == true {

						// Revoke secret and public key pair
						secretKey.keyRevoked = true
						secretKey.secretKeyCipherData = emptySecretKeyCipherBytes

						secretKeySaved = SaveKey(secretKey, _secretKeyFileName, true)

						if secretKeySaved == true {

							publicKey.keyRevoked = true
							publicKey.publicKeyData = emptyPublicKeyBytes

							publicKeySaved = SaveKey(publicKey, _publicKeyFileName, true)

							if publicKeySaved == true {
								fmt.Println(fmt.Sprintf(UI_Revoked, _secretKeyFileName, _publicKeyFileName))
							} else {
								fmt.Println(fmt.Sprintf(UI_FailedToRevoke, _secretKeyFileName, _publicKeyFileName))
							}

						} else {
							fmt.Println(fmt.Sprintf(UI_FailedToRevoke, _secretKeyFileName, _publicKeyFileName))
						}

					} else {
						fmt.Println(UI_FailedToLoadKey)
					}

				} else {
					fmt.Println(UI_FailedToLoadKey)
				}

			} else {
				fmt.Println(fmt.Sprintf(UI_PublicKeyNotFromSecretKey, _publicKeyFileName, _secretKeyFileName))
			}

		} else {
			fmt.Println(UI_RevokeCancelled)
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_secretKeyFileName: "+_secretKeyFileName+"_publicKeyFileName: "+_publicKeyFileName))
	}

	return revoked
}
