#!/bin/bash
SHELL=/bin/bash
PATH=~/bin:/usr/bin
SECRET_KEY="secret.key"
PUBLIC_KEY="public.key"
PLAINTEXT_FILE="plaintextfile.txt"
CIPHERTEXT_FILE=$PLAINTEXT_FILE".qrc"
DECODED_PLAINTEXT_FILE=$PLAINTEXT_FILE"-new.txt"

echo "Functional test script v1.0"

if [ -f "$SECRET_KEY" ] && [ -f "$PUBLIC_KEY" ]; then
    echo "$SECRET_KEY or $PUBLIC_KEY already exists. Tests not performed."
else
    echo "Secret key must be called:" $SECRET_KEY
    echo "Public key must be called:" $PUBLIC_KEY
    echo "Plain text must be called:" $PLAINTEXT_FILE
    read -N 1 -p "Press any key to continue..."
    echo
    ./qrc --generate-keys
     read -N 1 -p "Press any key to continue..."
    echo
    ./qrc --show-key=$SECRET_KEY
    echo
    ./qrc --show-key=$PUBLIC_KEY
     read -N 1 -p "Press any key to continue..."
    echo
    ./qrc --validate-keys secret=$SECRET_KEY public=$PUBLIC_KEY
      read -N 1 -p "Press any key to continue..."
    echo
    ./qrc --encrypt key=$PUBLIC_KEY plaintext=$PLAINTEXT_FILE ciphertext=$CIPHERTEXT_FILE
    ls -l $CIPHERTEXT_FILE
    read -N 1 -p "Press any key to continue..."
    echo
    ./qrc --decrypt key=$SECRET_KEY ciphertext=$CIPHERTEXT_FILE plaintext=$DECODED_PLAINTEXT_FILE
    cat $DECODED_PLAINTEXT_FILE
    read -N 1 -p "Press any key to continue..."
    echo
    rm $CIPHERTEXT_FILE
    rm $DECODED_PLAINTEXT_FILE
    ./qrc --revoke-keys secret=$SECRET_KEY public=$PUBLIC_KEY
    read -N 1 -p "Press any key to continue..."
    echo
    ./qrc --validate-keys secret=$SECRET_KEY public=$PUBLIC_KEY
    read -N 1 -p "Press any key to continue..."
    echo
    ./qrc --show-key=$SECRET_KEY
    echo
    ./qrc --show-key=$PUBLIC_KEY
     read -N 1 -p "Press any key to continue..."
    #echo
   ./qrc --encrypt key=$PUBLIC_KEY plaintext=$PLAINTEXT_FILE ciphertext=$CIPHERTEXT_FILE
    read -N 1 -p "Press any key to continue..."
    echo
    ./qrc --decrypt key=$SECRET_KEY ciphertext=$CIPHERTEXT_FILE plaintext=$DECODED_PLAINTEXT_FILE
    read -N 1 -p "Press any key to continue..."
    echo
    rm $SECRET_KEY
    rm $PUBLIC_KEY
fi


