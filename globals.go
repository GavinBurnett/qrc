package main

const SHARED_KEY_LENGTH int = 32
const SHARED_CIPHERTEXT_LENGTH int = 1568
const CIPHER_BLOCK_LENGTH int = 16
const CIPHER_TEXT_HEADER_SIZE int = 24

const INT_64_LENGTH int64 = 8

const OWNER_NAME_LENGTH int = 50
const OWNER_EMAIL_LENGTH int = 50
const KEY_TYPE string = "ML-KEM"
const KEY_TYPE_LENGTH int = 6
const KEY_LENGTH int32 = 1024
const DATE_CREATED_LENGTH int = 10
const SECRET_KEY_LENGTH int = 64
const SECRET_KEY_CIPHER_LENGTH int = 92
const PUBLIC_KEY_LENGTH int = 1568

const PASSWORD_HASH_LENGTH = 32
const MD5_HASH_LENGTH = 16
const SHA256_HASH_LENGTH = 32

const CIPHER_TEXT_HEADER_MAGIC_NUMBER int64 = 19780811
const SECRET_KEY_MAGIC_NUMBER int64 = 20140205
const PUBLIC_KEY_MAGIC_NUMBER int64 = 19790125

const CMD_GENERATE_KEYS = "--generate-keys"
const CMD_SHOW_KEY = "--show-key="
const CMD_ENCRYPT = "--encrypt"
const CMD_DECRYPT = "--decrypt"
const CMD_VALIDATE_KEYS = "--validate-keys"
const CMD_REVOKE_KEYS = "--revoke-keys"

const CMD_KEY = "key="
const CMD_PLAINTEXT = "plaintext="
const CMD_CIPHERTEXT = "ciphertext="
const CMD_SECRET = "secret="
const CMD_PUBLIC = "public="

const DEBUG bool = false
const TEST bool = false
