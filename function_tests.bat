@echo off

set SECRET_KEY=secret.key
set PUBLIC_KEY=public.key
set PLAINTEXT_FILE=plaintextfile.txt
set CIPHERTEXT_FILE=plaintextfile.qrc
set DECODED_PLAINTEXT_FILE=plaintextfile-new.txt

echo Functional test script v1.0

if exist %SECRET_KEY% (
    echo secret.key already exists. Tests not performed.
) else (
    if exist %PUBLIC_KEY% (
        echo public.key already exists. Tests not performed.
    ) else (
            echo Secret key must be called: %SECRET_KEY%
            echo Public key must be called: %PUBLIC_KEY%
            echo Plain text must be called: %PLAINTEXT_FILE%
            pause
            qrc.exe --generate-keys
            pause
            qrc.exe --show-key=%SECRET_KEY%
            echo ----
            qrc.exe --show-key=%PUBLIC_KEY%
            pause
            qrc.exe --validate-keys secret=%SECRET_KEY% public=%PUBLIC_KEY%
            pause
            qrc.exe --encrypt key=%PUBLIC_KEY% plaintext=%PLAINTEXT_FILE% ciphertext=%CIPHERTEXT_FILE%
            dir %CIPHERTEXT_FILE%
            pause
            qrc.exe --decrypt key=%SECRET_KEY% ciphertext=%CIPHERTEXT_FILE% plaintext=%DECODED_PLAINTEXT_FILE%
            type %DECODED_PLAINTEXT_FILE%
            pause
            del %CIPHERTEXT_FILE%
            del %DECODED_PLAINTEXT_FILE%
            qrc.exe --revoke-keys secret=%SECRET_KEY% public=%PUBLIC_KEY%
            pause
            qrc.exe --validate-keys secret=%SECRET_KEY% public=%PUBLIC_KEY%
            pause
            qrc.exe --show-key=%SECRET_KEY%
            echo ----
            qrc.exe --show-key=%PUBLIC_KEY%
            pause
            qrc.exe --encrypt key=%PUBLIC_KEY% plaintext=%PLAINTEXT_FILE% ciphertext=%CIPHERTEXT_FILE%
            pause
            qrc.exe --decrypt key=%SECRET_KEY% ciphertext=%CIPHERTEXT_FILE% plaintext=%DECODED_PLAINTEXT_FILE%
            pause
            del %SECRET_KEY%
            del %PUBLIC_KEY%
    )
)
