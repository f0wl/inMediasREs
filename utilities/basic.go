package utilimr

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
)

// Hashfilemd5 returns the MD5 Hash of the analysed file
func Hashfilemd5(filePath string) (string, error) {
	var returnMD5String string

	file, err := os.Open(filePath)
	if err != nil {
		return returnMD5String, err
	}

	defer file.Close()

	hash := md5.New()

	if _, err := io.Copy(hash, file); err != nil {
		return returnMD5String, err
	}

	hashInBytes := hash.Sum(nil)[:16]

	returnMD5String = hex.EncodeToString(hashInBytes)

	return returnMD5String, nil

}

// Hashfilesha1 returns the SHA1 Hash of the analysed file
func Hashfilesha1(filePath string) (string, error) {
	var returnSHA1String string

	file, err := os.Open(filePath)
	if err != nil {
		return returnSHA1String, err
	}

	defer file.Close()

	hash := sha1.New()

	if _, err := io.Copy(hash, file); err != nil {
		return returnSHA1String, err
	}

	hashInBytes := hash.Sum(nil)[:20]

	returnSHA1String = hex.EncodeToString(hashInBytes)

	return returnSHA1String, nil

}

// Hashfilesha256 returns the SHA256 Hash of the analysed file
func Hashfilesha256(filePath string) (string, error) {
	var returnSHA256String string

	file, err := os.Open(filePath)
	if err != nil {
		return returnSHA256String, err
	}

	defer file.Close()

	hash := sha256.New()

	if _, err := io.Copy(hash, file); err != nil {
		return returnSHA256String, err
	}

	hashInBytes := hash.Sum(nil)[:32]

	returnSHA256String = hex.EncodeToString(hashInBytes)

	return returnSHA256String, nil

}
