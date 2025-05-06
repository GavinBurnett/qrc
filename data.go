package main

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
