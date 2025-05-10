package main

const (
	UI_InvalidArgs                          = `ERROR: Invalid arguments`
	UI_CipherCreateFail                     = `ERROR: Failed to generate cipher text: %s`
	UI_PlainCreateFail                      = `ERROR: Failed to generate plain text: %s`
	UI_NoParametersGiven                    = `ERROR: No parameters specified`
	UI_ParameterInvalid                     = `ERROR: Invalid parameter: %s`
	UI_EmptyFile                            = `ERROR: Empty file`
	UI_InvalidFileSize                      = `ERROR: Invalid file size: %s`
	UI_FileTooBig                           = `ERROR: File too big`
	UI_NoFileSize                           = `ERROR: Can't get file size: %s %s`
	UI_FileReadError                        = `ERROR: File read error: %s %s`
	UI_FileWriteError                       = `ERROR: File write error: %s %s`
	UI_NoBufferMemory                       = `ERROR: Failed to allocate buffer memory`
	UI_DataCopyError                        = `ERROR: Data copy error`
	UI_FileOpenError                        = `ERROR: File open error: %s`
	UI_FileAlreadyExists                    = `ERROR: %s File already exists`
	UI_FileDeleteError                      = `ERROR: %s File delete error: %s`
	UI_FileNameTooLong                      = `ERROR: File name %s too long. Maximum %v characters`
	UI_SeekFail                             = `ERROR: File: %s seek to: %v failed. %s`
	UI_FileCreateError                      = `ERROR: Failed to create file: %s`
	UI_FailedToEncrypt                      = `ERROR: Failed to encrypt data`
	UI_FailedToDecrypt                      = `ERROR: Failed to decrypt data`
	UI_FailedToGenerateNonce                = `ERROR: Failed to generate nonce`
	UI_InvalidNonceSize                     = `ERROR: Invalid nonce size`
	UI_FailedToCreateGCM                    = `ERROR: Failed to create GCM cipher`
	UI_FailedToCreateCipherBlock            = `ERROR: Failed to create cipher block`
	UI_FailedToWriteSharedKeyToFile         = `ERROR: Failed to write shared key to file: %s`
	UI_FailedToWriteCipherTextHeader        = `ERROR: Failed to write cipher text header to file: %s`
	UI_InvalidCipherTextHeader              = `ERROR: Invalid cipher text header`
	UI_FailedToReadCipherTextHeader         = `ERROR: Failed to read cipher text header`
	UI_FailedToCreateSharedKeyAndCipherText = `ERROR: Failed to create shared key and shared cipher text`
	UI_FailedToGetSharedKeyCipherText       = `ERROR: Failed to get shared key cipher text`
	UI_FileNotFound                         = `ERROR: File not found: %s`
	UI_KeyNotValid                          = `ERROR: Key not valid`
	UI_FailedToDecapsualteKey               = `ERROR: Failed to decapsulate key`
	UI_FailedToSavePublicKey                = `ERROR: Failed to save public key`
	UI_FailedToSaveSecretKey                = `ERROR: Failed to save secret key`
	UI_FailedToCreatePublicKey              = `ERROR: Failed to create public key`
	UI_FailedToEncryptSecretKey             = `ERROR: Failed to encrypt secret key`
	UI_FailedToDecryptSecretKey             = `ERROR: Failed to decrypt secret key`
	UI_FailedToGenerateSecretKey            = `ERROR: Failed to generate decapsulation/secret key`
	UI_FailedToGetSecretKeyName             = `ERROR: Failed to get secret key name`
	UI_FailedToGetPublicKeyName             = `ERROR: Failed to get public key name`
	UI_FailedToSetDate                      = `ERROR: Failed to set current date`
	UI_FailedToSetKeyType                   = `ERROR: Failed to set key type`
	UI_FailedToGetOwnerEMail                = `ERROR: Failed to get owner E-Mail`
	UI_FailedToGetOwnerName                 = `ERROR: Failed to get owner name`
	UI_InvalidHashPhrase                    = `ERROR: Invalid hash phrase`
	UI_InvalidPassword                      = `ERROR: Invalid password`
	UI_FailedToGeneratePasswordHash         = `ERROR: Failed to generate password hash`
	UI_FailedToGenerateMD5Hash              = `ERROR: Failed to generate MD5 hash`
	UI_FailedToGenerateSHA256Sum            = `ERROR: Failed to generate SHA256 sum`
	UI_InvalidSHA256Sum                     = `ERROR: Invalid SHA256 sum`
	UI_FailedToCreateTempKey                = `ERROR: Failed to create temporary key`
	UI_FailedToReadCmdData                  = `ERROR: Failed to read data from command line`
	UI_FailedToLoadKey                      = `ERROR: Failed to load key`
	UI_FailedToRevoke                       = `ERROR: Failed to revoke secret key: %s and public key: %s`
	UI_PublicKeyNotFromSecretKey            = `Public key: %s not a match with Secret key: %s`
	UI_PublicKeyFromSecretKey               = `Public key: %s matches with Secret key: %s`
	UI_FileSize                             = `%s File size: %v`
	UI_SeekOffset                           = `Seeked to offset: %v`
	UI_Encrypting                           = `Attempting to encrypt plain text file: %s into cipher text file: %s`
	UI_Decrypting                           = `Attempting to decrypt cipher text file: %s into plain text file: %s`
	UI_Encrypted                            = `Successfully encrypted plain text file: %s into cipher text file: %s`
	UI_Decrypted                            = `Successfully decrypted cipher text file: %s into plain text file: %s`
	UI_SHA256Sum                            = `SHA256 Sum: %s`
	UI_SharedKey                            = `Shared key: %v
Shared key length: %v`
	UI_SharedKeyCipherText = `Shared cipher text: %v
Shared key cipher text length: %v`
	UI_BytesRead                 = `%s bytes read: %v`
	UI_CipherTextBytesLeftToRead = `Cipher text bytes left to read: %v`
	UI_BytesWritten              = `Bytes written: %v`
	UI_Arguments                 = `Arguments: `
	UI_FileFound                 = `File found: %s`
	UI_CreatingFile              = `Creating file: `
	UI_Parameter                 = `Parameters: %s`
	UI_HeaderDataWrittenOK       = `Header data: %v written into file: %s successfully`
	UI_HeaderDataReadOK          = `Header data: %v read from file: %s successfully`
	UI_FileDeleted               = `File deleted: %s`
	UI_BufferSize                = `Buffer size: %v`
	UI_EnterKeyOwnerName         = `Enter name of key owner:`
	UI_EnterKeyOwnerEMail        = `Enter e-mail address of key owner:`
	UI_EnterPublicKeyFileName    = `Enter file name of public key:`
	UI_EnterSecretKeyFileName    = `Enter file name of secret key:`
	UI_KeyOwnerName              = `Name of key owner: %s`
	UI_KeyOwnerEMail             = `E-mail address of key owner: %s`
	UI_KeyType                   = `Key type: %s`
	UI_KeyLength                 = `Key length: %v`
	UI_DateCreated               = `Date created: %s`
	UI_KeysGeneratedOK           = `Public and secret keys generated successfully`
	UI_EnterPassword             = `Enter secret key password:`
	UI_ConfirmPassword           = `Confirm secret key password:`
	UI_SHA256Matches             = `SHA256Sums Match. Key value: %x Calculated value: %x`
	UI_SHA256DoesNotMatch        = `SHA256Sums Do not match. Key value: %x Calculated value: %x`
	UI_SecretKeyData             = `Secret key data: %v`
	UI_PublicKeyData             = `Public key data: %v`
	UI_SecretKey                 = `Secret key`
	UI_PublicKey                 = `Public key`
	UI_LoadedSecretKey           = `Loaded secret key: %v`
	UI_LoadedPublicKey           = `Loaded public key: %v`
	UI_KeyRevoked                = `***** KEY REVOKED *****`
	UI_KeySaved                  = `Key saved successfully`
	UI_CipherTextHeader          = `Cipher Text Header: %v`
	UI_PasswordEncrypted         = `Password encrypted`
	UI_KeyDecrypted              = `Key decrypted`
	UI_EncryptArgs               = `Encrypt arguments: %s %s %s`
	UI_DecryptArgs               = `Decrypt arguments: %s %s %s`
	UI_ValidateArgs              = `Validate arguments: %s %s`
	UI_RevokeArgs                = `Revoke arguments: %s %s`
	UI_RevokeWarning             = `WARNING: Revoking secret key: %s and public key: %s will stop key pair from being used for encryption and decryption. This cannot be reversed.`
	UI_ConfirmNoDefault          = `Are you sure? [N/y]:`
	UI_ConfirmYesDefault         = `Are you sure? [n/Y]:`
	UI_RevokePassword            = `Secret key password must be given to revoke key pair`
	UI_ConfirmRevokePassword     = `Confirm secret key password to revoke key pair`
	UI_Revoked                   = `Revoked secret key: %s and public key: %s`
	UI_RevokeCancelled           = `Key revoke cancelled`
	UI_ReadChar                  = `Read char: %c`
	UI_Help                      = `qrc v1.2 by gburnett@outlook.com

Arguments: 

qrc --generate-keys
qrc --show-key=<keyfile>
qrc --encrypt key=<public keyfile> plaintext=<plaintextfile> ciphertext=<ciphertextfile>
qrc --decrypt key=<secret keyfile> ciphertext=<ciphertextfile> plaintext=<plaintextfile>
qrc --validate-keys secret=<secret keyfile> public=<public keyfile>
qrc --revoke-keys secret=<secret keyfile> public=<public keyfile>

Examples:

qrc --show-key=public.key
qrc --encrypt key=public.key plaintext=plaintextfile.txt ciphertext=ciphertextfile.qrc
qrc --decrypt key=secret.key ciphertext=ciphertextfile.qrc plaintext=plaintextfile.txt
qrc --validate-keys secret=secret.key public=public.key
qrc --revoke-keys secret=secret.key public=public.key`
)
