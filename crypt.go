package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/mlkem"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// CipherTextHeader: Data structure that defines location of data blocks in cipher text
type CipherTextHeader struct {
	magicNumber              int64
	sharedKeyCipherTextStart int64
	cipherTextStart          int64
}

// Encrypt: Encrypt the plain text file into a cipher text file using the public key
func Encrypt(_publicKeyFile string, _plainTextFile string, _cipherTextFile string) bool {

	var publicKeyData Key
	var publicKey *mlkem.EncapsulationKey1024
	var keyLoaded bool = false

	var sharedKey []byte
	var sharedKeyCipherText []byte
	var cipherBlock cipher.Block
	var gcm cipher.AEAD
	var nonce []byte

	var plainTextFile *os.File
	var plainTextSize int64 = 0
	var plainTextBytesRead int = 0
	var plainText []byte

	var cipherTextFile *os.File
	var cipherTextFileBytesWritten int = 0
	var cipherTextTotalBytesWritten int64 = 0
	var cipherTextHeaderWritten bool = false
	var cipherText []byte

	var encrypted bool = false

	var err error

	// Check passed in parameters are valid
	if len(_publicKeyFile) > 0 && len(_plainTextFile) > 0 && len(_cipherTextFile) > 0 {

		// Load public key data
		publicKeyData, keyLoaded = LoadKey(_publicKeyFile)

		if publicKeyData.magicNumber == PUBLIC_KEY_MAGIC_NUMBER && keyLoaded == true {

			// Get public key from public key data
			publicKey, err = mlkem.NewEncapsulationKey1024(publicKeyData.publicKeyData[:])

			if len(publicKey.Bytes()) == PUBLIC_KEY_LENGTH && err == nil {

				// Check plain text file exists
				if FileExists(_plainTextFile) == true {

					// Get size of plain text file
					plainTextSize = GetFileSize(_plainTextFile)

					// If size of plain text file is valid
					if plainTextSize != -1 && plainTextSize > 0 {

						if DEBUG == true {
							fmt.Println(fmt.Sprintf(UI_FileSize, _plainTextFile, plainTextSize))
						}

						// Open plain text file
						plainTextFile, err = os.OpenFile(_plainTextFile, os.O_RDONLY, 0)

						if err == nil {

							// If cipher text file does not exist (do not overwrite file if it does exist)
							if FileExists(_cipherTextFile) == false {

								// Create cipher text file
								cipherTextFile, err = os.Create(_cipherTextFile)

								if err == nil {

									// Update UI with encrypting message
									fmt.Println(fmt.Sprintf(UI_Encrypting, _plainTextFile, _cipherTextFile))

									// Create shared key and shared cipher text from public key
									sharedKey, sharedKeyCipherText = publicKey.Encapsulate()

									if len(sharedKey) == SHARED_KEY_LENGTH && len(sharedKeyCipherText) == SHARED_CIPHERTEXT_LENGTH {

										if DEBUG == true {
											fmt.Println(fmt.Sprintf(UI_SharedKey, sharedKey, len(sharedKey)))
											fmt.Println(fmt.Sprintf(UI_SharedKeyCipherText, sharedKeyCipherText, len(sharedKeyCipherText)))
										}

										// Write the header to the cipher text file
										cipherTextHeaderWritten, cipherTextTotalBytesWritten = WriteCipherTextHeader(cipherTextFile)

										if cipherTextHeaderWritten == true {

											// Write the shared key cipher text to the cipher text file
											cipherTextFileBytesWritten, err = cipherTextFile.Write(sharedKeyCipherText)

											if err == nil {

												// Increment total bytes written counter
												cipherTextTotalBytesWritten += int64(cipherTextFileBytesWritten)

												// Use 32 bit shared key to create AES-256 block cipher
												cipherBlock, err = aes.NewCipher(sharedKey)

												if cipherBlock.BlockSize() == CIPHER_BLOCK_LENGTH && err == nil {

													// Create a GCM cipher
													gcm, err = cipher.NewGCM(cipherBlock)

													if err == nil {

														// Generate a random nonce for each encryption
														nonce = make([]byte, gcm.NonceSize())

														if len(nonce) == gcm.NonceSize() {

															_, err = io.ReadFull(rand.Reader, nonce)

															if err == nil {

																// Create memory buffer for plain text file
																plainText = make([]byte, plainTextSize)

																if int64(len(plainText)) == plainTextSize {

																	// Read the plain text file data into the buffer
																	plainTextBytesRead, err = plainTextFile.Read(plainText)

																	if DEBUG == true {
																		fmt.Println(fmt.Sprintf(UI_BytesRead, _plainTextFile, plainTextBytesRead))
																	}

																	if err == nil {

																		if int64(plainTextBytesRead) == plainTextSize {

																			// Encrypt the plain text data buffer into cipher text buffer
																			cipherText = gcm.Seal(nonce, nonce, plainText, nil)

																			if len(cipherText) > 0 {

																				cipherTextFileBytesWritten, err = cipherTextFile.Write(cipherText)

																				if err == nil {

																					if cipherTextFileBytesWritten > 0 {
																						encrypted = true
																						fmt.Println(fmt.Sprintf(UI_Encrypted, _plainTextFile, _cipherTextFile))
																					} else {
																						fmt.Println(fmt.Sprintf(UI_CipherCreateFail, err))
																					}

																				} else {
																					fmt.Println(fmt.Sprintf(UI_FileWriteError, _cipherTextFile, err))
																				}

																			} else {
																				fmt.Println(UI_FailedToEncrypt)
																			}

																		} else {
																			fmt.Println(fmt.Sprintf(UI_FileReadError, _plainTextFile, err))
																		}

																	} else {
																		fmt.Println(fmt.Sprintf(UI_FileReadError, _plainTextFile, err))
																	}

																} else {
																	fmt.Println(UI_NoBufferMemory)
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
												fmt.Println(fmt.Sprintf(UI_FailedToWriteSharedKeyToFile, _cipherTextFile))
											}

										} else {
											fmt.Println(fmt.Sprintf(UI_FailedToWriteCipherTextHeader, _cipherTextFile))
										}

									} else {
										fmt.Println(UI_FailedToCreateSharedKeyAndCipherText)
									}

								} else {
									fmt.Println(fmt.Sprintf(UI_FileCreateError, _cipherTextFile))
								}

								// Close cipher text file down
								if encrypted == true {
									cipherTextFile.Sync()
									cipherTextFile.Close()
								} else {
									cipherTextFile.Close()
									DeleteFile(_cipherTextFile)
								}

							} else {
								fmt.Println(fmt.Sprintf(UI_FileAlreadyExists, _cipherTextFile))
							}
						} else {
							fmt.Println(fmt.Sprintf(UI_FileOpenError, _plainTextFile))
						}

						plainTextFile.Close()

					} else {
						fmt.Println(fmt.Sprintf(UI_InvalidFileSize, _plainTextFile))
					}

				} else {
					fmt.Println(fmt.Sprintf(UI_FileNotFound, _plainTextFile))
				}

			} else {
				fmt.Println(UI_KeyNotValid)
			}

		} else {
			fmt.Println(UI_KeyNotValid)
		}

		publicKey = nil
		sharedKey = nil
		sharedKeyCipherText = nil
		cipherBlock = nil
		gcm = nil
		nonce = nil
		plainTextFile = nil
		plainText = nil
		cipherTextFile = nil
		cipherText = nil

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_publicKeyFile: "+_publicKeyFile+"_plainTextFile: "+_plainTextFile+"_cipherTextFile: "+_cipherTextFile))
	}

	return encrypted
}

// Decrypt: Decrypt the cipher text file into a plain text file using the secret key
func Decrypt(_secretKeyFile string, _cipherTextFile string, _plainTextFile string) bool {

	var secretKeyData Key
	var secretKey *mlkem.DecapsulationKey1024
	var keyLoaded bool = false

	var sharedKey []byte
	var sharedKeyCipherText [SHARED_CIPHERTEXT_LENGTH]byte
	var cipherBlock cipher.Block
	var gcm cipher.AEAD
	var nonce []byte
	var nonceSize int

	var plainTextFile *os.File
	var plainTextBytesWritten int = 0
	var plainText []byte

	var cipherTextFile *os.File
	var cipherTextSize int64 = 0
	var cipherTextBytesRead int = 0
	var cipherTextBytesLeftToRead int64 = 0
	var cipherText []byte
	var cipherTextHeader CipherTextHeader
	var readCipherTextHeaderOk bool = false
	var cipherFileOffset int64

	var decrypted bool = false

	var err error

	// Check passed in parameters are valid
	if len(_secretKeyFile) > 0 && len(_cipherTextFile) > 0 && len(_plainTextFile) > 0 {

		// Load secret key data
		secretKeyData, keyLoaded = LoadKey(_secretKeyFile)

		if secretKeyData.magicNumber == SECRET_KEY_MAGIC_NUMBER && keyLoaded == true {

			// Get secret key from secret key data
			secretKey, err = mlkem.NewDecapsulationKey1024(secretKeyData.secretKeyData[:])

			if len(secretKey.Bytes()) == SECRET_KEY_LENGTH && err == nil {

				// Check cipher text file exists
				if FileExists(_cipherTextFile) == true {

					// Get size of cipher text file
					cipherTextSize = GetFileSize(_cipherTextFile)

					// If size of cipher text file is valid
					if cipherTextSize != -1 && cipherTextSize > 0 {

						if DEBUG == true {
							fmt.Println(fmt.Sprintf(UI_FileSize, _cipherTextFile, cipherTextSize))
						}

						// Open cipher text file
						cipherTextFile, err = os.OpenFile(_cipherTextFile, os.O_RDONLY, 0)

						if err == nil {

							// If plain text file does not exist (do not overwrite file if it does exist)
							if FileExists(_plainTextFile) == false {

								// Create plain text file
								plainTextFile, err = os.Create(_plainTextFile)

								if err == nil {

									// Update UI with decrypting message
									fmt.Println(fmt.Sprintf(UI_Decrypting, _cipherTextFile, _plainTextFile))

									// Read header from cipher text file
									readCipherTextHeaderOk, cipherTextHeader = ReadCipherTextHeader(cipherTextFile)

									if readCipherTextHeaderOk == true {

										if DEBUG == true {
											fmt.Println(fmt.Sprintf(UI_CipherTextHeader, cipherTextHeader))
										}

										if cipherTextHeader.magicNumber == CIPHER_TEXT_HEADER_MAGIC_NUMBER {

											// Read shared key cipher from cipher text file
											cipherFileOffset, err = cipherTextFile.Seek(cipherTextHeader.sharedKeyCipherTextStart, 0)

											if err == nil {

												if cipherFileOffset == cipherTextHeader.sharedKeyCipherTextStart {

													err = binary.Read(cipherTextFile, binary.LittleEndian, &sharedKeyCipherText)

													if err == nil {

														if DEBUG == true {
															fmt.Println(fmt.Sprintf(UI_SharedKeyCipherText, sharedKeyCipherText, len(sharedKeyCipherText)))
														}

														// Get shared key from secret key and shared key cipher
														sharedKey, err = secretKey.Decapsulate(sharedKeyCipherText[:])

														if len(sharedKey) == SHARED_KEY_LENGTH && err == nil {

															if DEBUG == true {
																fmt.Println(fmt.Sprintf(UI_SharedKey, sharedKey, len(sharedKey)))
															}

															// Use 32 bit shared key to create AES-256 block cipher
															cipherBlock, err = aes.NewCipher(sharedKey)

															if cipherBlock.BlockSize() == CIPHER_BLOCK_LENGTH && err == nil {

																// Create a GCM cipher
																gcm, err = cipher.NewGCM(cipherBlock)

																if err == nil {

																	// Get the nonce size from the shared key
																	nonceSize = gcm.NonceSize()

																	// Get size of cipher text data to read in
																	cipherTextBytesLeftToRead = cipherTextSize - cipherTextHeader.cipherTextStart

																	if DEBUG == true {
																		fmt.Println(fmt.Sprintf(UI_CipherTextBytesLeftToRead, cipherTextBytesLeftToRead))
																	}

																	// Create buffer to hold cipher text data
																	cipherText = make([]byte, cipherTextBytesLeftToRead)

																	if int64(len(cipherText)) == cipherTextBytesLeftToRead {

																		// Read cipher text file data into buffer
																		cipherTextBytesRead, err = cipherTextFile.Read(cipherText)

																		if err == nil {

																			if int64(cipherTextBytesRead) == cipherTextBytesLeftToRead {

																				// Get the nonce from the ciphertext
																				nonce = cipherText[:nonceSize]

																				if len(nonce) == nonceSize {

																					// Decrypt - Get plain text data from cipher text data
																					plainText, err = gcm.Open(nil, nonce, cipherText[nonceSize:], nil)

																					if len(plainText) > 0 && err == nil {

																						// Write plain text data to plain text file
																						plainTextBytesWritten, err = plainTextFile.Write(plainText)

																						if err == nil {

																							if plainTextBytesWritten > 0 {
																								decrypted = true
																								fmt.Println(fmt.Sprintf(UI_Decrypted, _cipherTextFile, _plainTextFile))
																							} else {
																								fmt.Println(fmt.Sprintf(UI_PlainCreateFail, _plainTextFile))
																							}

																						} else {
																							fmt.Println(fmt.Sprintf(UI_FileWriteError, _plainTextFile, err))
																						}

																					} else {
																						fmt.Println(UI_FailedToDecrypt)
																					}

																				} else {
																					fmt.Println(UI_InvalidNonceSize)
																				}

																			} else {
																				fmt.Println(fmt.Sprintf(UI_FileReadError, _cipherTextFile, err))
																			}

																		} else {
																			fmt.Println(fmt.Sprintf(UI_FileReadError, _cipherTextFile, err))
																		}

																	} else {
																		fmt.Println(UI_NoBufferMemory)
																	}

																} else {
																	fmt.Println(UI_FailedToCreateGCM)
																}

															} else {
																fmt.Println(UI_FailedToCreateCipherBlock)
															}

														} else {
															fmt.Println(UI_FailedToDecapsualteKey)
														}
													} else {
														fmt.Println(UI_FailedToGetSharedKeyCipherText)
													}

												} else {
													fmt.Println(fmt.Sprintf(UI_SeekFail, _cipherTextFile, cipherTextHeader.sharedKeyCipherTextStart, err))
												}

											} else {
												fmt.Println(fmt.Sprintf(UI_SeekFail, _cipherTextFile, cipherTextHeader.sharedKeyCipherTextStart, err))
											}

										} else {
											fmt.Println(UI_InvalidCipherTextHeader)
										}

									} else {
										fmt.Println(UI_FailedToReadCipherTextHeader)
									}

								} else {
									fmt.Println(fmt.Sprintf(UI_FileCreateError, _plainTextFile))
								}

								// Close plain text file down
								if decrypted == true {
									plainTextFile.Sync()
									plainTextFile.Close()
								} else {
									plainTextFile.Close()
									DeleteFile(_plainTextFile)
								}

							} else {
								fmt.Println(fmt.Sprintf(UI_FileAlreadyExists, _plainTextFile))
							}

							cipherTextFile.Close()

						} else {
							fmt.Println(fmt.Sprintf(UI_FileOpenError, _cipherTextFile))
						}

					} else {
						fmt.Println(fmt.Sprintf(UI_InvalidFileSize, _cipherTextFile))
					}

				} else {
					fmt.Println(fmt.Sprintf(UI_FileNotFound, _cipherTextFile))
				}

			} else {
				fmt.Println(UI_KeyNotValid)
			}

		} else {
			fmt.Println(UI_KeyNotValid)
		}

		sharedKey = nil
		cipherBlock = nil
		gcm = nil
		nonce = nil
		plainTextFile = nil
		plainText = nil
		cipherTextFile = nil
		cipherText = nil

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_secretKeyFile: "+_secretKeyFile+"_cipherTextFile: "+_cipherTextFile+"_plainTextFile: "+_plainTextFile))
	}

	return decrypted
}

// WriteCipherTextHeader: Writes the cipher text header into the cipher text file
func WriteCipherTextHeader(_cipherFile *os.File) (bool, int64) {

	var cipherTextHeader CipherTextHeader
	var fileOffset int64
	var dataWritten = false

	var err error

	if _cipherFile != nil {

		// Create and populate header
		cipherTextHeader = CipherTextHeader{}

		cipherTextHeader.magicNumber = CIPHER_TEXT_HEADER_MAGIC_NUMBER
		cipherTextHeader.sharedKeyCipherTextStart = int64(CIPHER_TEXT_HEADER_SIZE)
		cipherTextHeader.cipherTextStart = cipherTextHeader.sharedKeyCipherTextStart + int64(SHARED_CIPHERTEXT_LENGTH)

		if DEBUG == true {
			fmt.Println(fmt.Sprintf(UI_CipherTextHeader, cipherTextHeader))
		}

		// Write cipher text header to cipher text file
		err = binary.Write(_cipherFile, binary.LittleEndian, cipherTextHeader)
		if err == nil {

			if DEBUG == true {
				fmt.Println(fmt.Sprintf(UI_HeaderDataWrittenOK, cipherTextHeader, _cipherFile.Name()))
			}

			// Get number of bytes written to cipher text file
			fileOffset, err = _cipherFile.Seek(0, io.SeekCurrent)
			if err == nil {

				if fileOffset == int64(CIPHER_TEXT_HEADER_SIZE) {
					dataWritten = true
				} else {
					fmt.Println(fmt.Sprintf(UI_FileWriteError, _cipherFile.Name(), err))
				}

			} else {
				fmt.Println(fmt.Sprintf(UI_FileWriteError, _cipherFile.Name(), err))
			}

		} else {
			fmt.Println(fmt.Sprintf(UI_FileWriteError, _cipherFile.Name(), err))
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_cipherFile: "+_cipherFile.Name()))
	}

	return dataWritten, fileOffset

}

// ReadCipherTextHeader: Reads the cipher text header from the cipher text file
func ReadCipherTextHeader(_cipherFile *os.File) (bool, CipherTextHeader) {

	var cipherTextHeader CipherTextHeader
	var readCipherTextHeader []byte
	var readCipherTextHeaderOk = false

	var err error

	if _cipherFile != nil {

		cipherTextHeader = CipherTextHeader{}

		// Create byte array to read cipher text header into
		readCipherTextHeader = make([]byte, CIPHER_TEXT_HEADER_SIZE)

		if len(readCipherTextHeader) == CIPHER_TEXT_HEADER_SIZE {

			// Read cipher text header into byte array
			err = binary.Read(_cipherFile, binary.LittleEndian, &cipherTextHeader.magicNumber)

			if err == nil {

				err = binary.Read(_cipherFile, binary.LittleEndian, &cipherTextHeader.sharedKeyCipherTextStart)

				if err == nil {

					err = binary.Read(_cipherFile, binary.LittleEndian, &cipherTextHeader.cipherTextStart)

					if err == nil {

						if cipherTextHeader.magicNumber == CIPHER_TEXT_HEADER_MAGIC_NUMBER {

							if DEBUG == true {
								fmt.Println(fmt.Sprintf(UI_HeaderDataReadOK, cipherTextHeader, _cipherFile.Name()))
							}

							readCipherTextHeaderOk = true

						} else {
							fmt.Println(UI_InvalidCipherTextHeader)
						}

					} else {
						fmt.Println(UI_FailedToReadCipherTextHeader)
					}

				} else {
					fmt.Println(UI_FailedToReadCipherTextHeader)
				}

			} else {
				fmt.Println(UI_InvalidCipherTextHeader)
			}

		} else {
			fmt.Println(UI_NoBufferMemory)
		}

	} else {
		fmt.Print(fmt.Sprintf(UI_ParameterInvalid, GetFunctionName()))
		fmt.Println(fmt.Sprintf(UI_Parameter, "_cipherFile: "+_cipherFile.Name()))
	}

	return readCipherTextHeaderOk, cipherTextHeader

}
