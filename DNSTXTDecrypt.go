package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
)

var TargetDomain = "cron.iap5u1rbety6vifaxsi9vovnc9jjay2l.com"

//var TargetDomain = "update.iap5u1rbety6vifaxsi9vovnc9jjay2l.com"
//var TargetDomain = "shell.iap5u1rbety6vifaxsi9vovnc9jjay2l.com"
//var TargetDomain = "1x32.iap5u1rbety6vifaxsi9vovnc9jjay2l.com"
//var TargetDomain = "2x32.iap5u1rbety6vifaxsi9vovnc9jjay2l.com"
//var TargetDomain = "3x32.iap5u1rbety6vifaxsi9vovnc9jjay2l.com"
//var TargetDomain = "1x64.iap5u1rbety6vifaxsi9vovnc9jjay2l.com"
//var TargetDomain = "2x64.iap5u1rbety6vifaxsi9vovnc9jjay2l.com"
//var TargetDomain = "3x64.iap5u1rbety6vifaxsi9vovnc9jjay2l.com"

func ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func ZeroUnPadding(origData []byte) []byte {
	return bytes.TrimFunc(origData, func(r rune) bool {
		return r == rune(0)
	})
}

// AesDecrypt to decreypt data
func AesDecrypt(cipherData, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	blockMode := cipher.NewCBCDecrypter(block, iv)
	plainData := make([]byte, len(cipherData))
	blockMode.CryptBlocks(plainData, cipherData)
	plainData = ZeroUnPadding(plainData)
	return plainData, nil
}

func main() {
	dnsTXTRes, err := net.LookupTXT(TargetDomain)
	if err != nil {
		fmt.Printf("Failed to lookup TXT Records.")
		panic(err)
	}

	for idx, txtRec := range dnsTXTRes {
		fmt.Printf("DNS TXT Record [%d]:\n %s\n\n", idx+1, txtRec)

		b64DecRes, err := base64.RawURLEncoding.DecodeString(txtRec)
		if err != nil {
			fmt.Println("Failed to b64 decode DNS TXT Record.")
			panic(err)
		}

		fmt.Printf("b64 decoded raw DNS TXT Record data:\n%s\n", hex.Dump(b64DecRes))

		md5Hash := md5.New()
		md5Hash.Write([]byte(TargetDomain))
		r1Hash := md5Hash.Sum(nil)
		r1HashStr := hex.EncodeToString(r1Hash)
		fmt.Println("Round 1 MD5 hash result: ", r1HashStr)

		aesKey := []byte(r1HashStr)[:aes.BlockSize]

		//r2Hash := md5Hash.Sum(nil)
		//r2hashStr := hex.EncodeToString(r2Hash)
		//fmt.Println("Round 2 MD5 hash result: ", r2hashStr)

		iv := []byte(r1HashStr)[16:32]

		plainData, err := AesDecrypt(b64DecRes, aesKey, iv)
		if err != nil {
			fmt.Println("Failed to Decrypt data:")
			panic(err)
		}

		fmt.Printf("AES Decrypted data: %s\n", plainData)

		fmt.Println("------------------------------------------------------------------------------")
	}
}
