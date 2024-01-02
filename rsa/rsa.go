package rsa

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
)

func GenerateKeyPair(bits int) (*rsa.PrivateKey, error) {
	keyPair, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to create key pair: %w", err)
	}

	err = keyPair.Validate()
	if err != nil {
		return nil, fmt.Errorf("failed to validate key pair: %w", err)
	}

	return keyPair, nil
}

func SavePrivateKey(filename string, keyPair *rsa.PrivateKey) error {
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	}

	return saveKeyFile(filename, privateKeyBlock)
}

func SavePublicKey(filename string, keyPair *rsa.PrivateKey) error {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&keyPair.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to save public key: %w", err)
	}

	publicKeyBlock := &pem.Block{
		Type:  "RSA PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return saveKeyFile(filename, publicKeyBlock)
}

func saveKeyFile(filename string, block *pem.Block) error {
	keyFile, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("failed to create keyfile %s: %w", filename, err)
	}
	defer keyFile.Close()

	return pem.Encode(keyFile, block)
}

func LoadPrivateKey(filename string) (*rsa.PrivateKey, error) {
	keyBlock, err := loadKeyFile(filename)
	if err != nil {
		return nil, err
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return privateKey, nil
}

func LoadPublicKey(filename string) (*rsa.PublicKey, error) {
	keyBlock, err := loadKeyFile(filename)
	if err != nil {
		return nil, err
	}

	publicKey, err := x509.ParsePKIXPublicKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	switch publicKey := publicKey.(type) {
	case *rsa.PublicKey:
		return publicKey, nil
	default:
		return nil, fmt.Errorf("key is not of public type")
	}
}

func loadKeyFile(filename string) (*pem.Block, error) {
	keyData, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	keyBlock, _ := pem.Decode(keyData)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode public key: %w", err)
	}

	return keyBlock, nil
}

func ComparePrivateKeys(k1, k2 *rsa.PrivateKey) bool {
	return k1.N.Cmp(k2.N) == 0 &&
		k1.E == k2.E &&
		k1.D.Cmp(k2.D) == 0 &&
		k1.Primes[0].Cmp(k2.Primes[0]) == 0 &&
		k1.Primes[1].Cmp(k2.Primes[1]) == 0 &&
		k1.Precomputed.Dp.Cmp(k2.Precomputed.Dp) == 0 &&
		k1.Precomputed.Dq.Cmp(k2.Precomputed.Dq) == 0 &&
		k1.Precomputed.Qinv.Cmp(k2.Precomputed.Qinv) == 0
}

func ComparePublicKeys(k1, k2 *rsa.PublicKey) bool {
	return k1.N.Cmp(k2.N) == 0 &&
		k1.E == k2.E
}

func PrintPrivateKey(keyPair *rsa.PrivateKey) error {
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	}

	return pem.Encode(os.Stdout, privateKeyBlock)
}

func PrivateKeyData(keyPair *rsa.PrivateKey) (string, error) {
	privateKeyBlock := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(keyPair),
	}

	var privateKeyData bytes.Buffer

	if err := pem.Encode(&privateKeyData, privateKeyBlock); err != nil {
		return "", err
	}

	return privateKeyData.String(), nil
}

// func getIdRsaStr() string {
// 	keyData, err := ioutil.ReadFile(config.idRsa)
// 	if err != nil {
// 		log.Printf("ERROR: fail get idrsa, %s", err.Error())
// 		os.Exit(1)
// 	}

// 	keyBlock, _ := pem.Decode(keyData)
// 	if keyBlock == nil {
// 		log.Printf("ERROR: fail get idrsa, invalid key")
// 		os.Exit(1)
// 	}

// 	// encode base64 key data
// 	return base64.StdEncoding.EncodeToString(keyBlock.Bytes)
// }

// func getIdRsaPubStr() string {
// 	keyData, err := ioutil.ReadFile(config.idRsaPub)
// 	if err != nil {
// 		log.Printf("ERROR: fail get idrsapubstr, %s", err.Error())
// 		return ""
// 	}

// 	keyBlock, _ := pem.Decode(keyData)
// 	if keyBlock == nil {
// 		log.Printf("ERROR: fail get idrsapubstr, invalid key")
// 		return ""
// 	}

// 	// encode base64 key data
// 	return base64.StdEncoding.EncodeToString(keyBlock.Bytes)
// }

// func getIdRsaFromStr(keyStr string) *rsa.PrivateKey {
// 	// key is base64 encoded
// 	data, err := base64.StdEncoding.DecodeString(keyStr)
// 	if err != nil {
// 		log.Printf("ERROR: fail get rsa, %s", err.Error())
// 		return nil
// 	}

// 	// get rsa private key
// 	key, err := x509.ParsePKCS8PrivateKey(data)
// 	if err != nil {
// 		log.Printf("ERROR: fail get rsa, %s", err.Error())
// 		return nil
// 	}
// 	switch key := key.(type) {
// 	case *rsa.PrivateKey:
// 		return key
// 	default:
// 		return nil
// 	}

// 	return nil
// }

// func getIdRsaPubFromStr(keyStr string) *rsa.PublicKey {
// 	// key is base64 encoded
// 	data, err := base64.StdEncoding.DecodeString(keyStr)
// 	if err != nil {
// 		log.Printf("ERROR: fail get rsapub, %s", err.Error())
// 		return nil
// 	}

// 	// this for ios key
// 	var pubKey rsa.PublicKey
// 	if rest, err := asn1.Unmarshal(data, &pubKey); err != nil {
// 		log.Printf("INFO: not ios key", keyStr)
// 	} else if len(rest) != 0 {
// 		log.Printf("INFO: not ios key, invalid lenght, %s", keyStr)
// 	} else {
// 		return &pubKey
// 	}

// 	// this is for android
// 	// get rsa public key
// 	pub, err := x509.ParsePKIXPublicKey(data)
// 	if err != nil {
// 		log.Printf("INFO: not android key, %s", keyStr)
// 		return nil
// 	}
// 	switch pub := pub.(type) {
// 	case *rsa.PublicKey:
// 		return pub
// 	default:
// 		return nil
// 	}

// 	return nil
// }

// func Sign(payload string, key *rsa.PrivateKey) (string, error) {
// 	replacer := strings.NewReplacer("\n", "", "\r", "", " ", "")
// 	msg := strings.TrimSpace(strings.ToLower(replacer.Replace(payload)))
// 	hashed := sha256.Sum256([]byte(msg))

// 	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hashed[:])
// 	if err != nil {
// 		return "", fmt.Errorf("failed to sign: %w", err)
// 	}

// 	return base64.StdEncoding.EncodeToString(signature), nil
// }

// func Verify(payload string, signature64 string, key *rsa.PublicKey) error {
// 	signature, err := base64.StdEncoding.DecodeString(signature64)
// 	if err != nil {
// 		return fmt.Errorf("failed to base64 decode: %w", err)
// 	}

// 	replacer := strings.NewReplacer("\n", "", "\r", "", " ", "")
// 	msg := strings.TrimSpace(strings.ToLower(replacer.Replace(payload)))
// 	hashed := sha256.Sum256([]byte(msg))

// 	return rsa.VerifyPKCS1v15(key, crypto.SHA256, hashed[:], signature)
// }

// func Encrypt(payload string, key *rsa.PublicKey) (string, error) {
// 	msg := []byte(payload)
// 	rnd := rand.Reader
// 	hash := sha256.New()

// 	ciperText, err := rsa.EncryptOAEP(hash, rnd, key, msg, nil)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to encrypt, %s", err)
// 	}

// 	return base64.StdEncoding.EncodeToString(ciperText), nil
// }

// func Decrypt(payload string, key *rsa.PrivateKey) (string, error) {
// 	msg, err := base64.StdEncoding.DecodeString(payload)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to base64 decode: %w", err)
// 	}

// 	rnd := rand.Reader
// 	hash := sha256.New()

// 	plainText, err := rsa.DecryptOAEP(hash, rnd, key, msg, nil)
// 	if err != nil {
// 		return "", fmt.Errorf("failed to decrypt: %w", err)
// 	}

// 	return string(plainText), nil
// }

// func crearCertificado(clavePrivada *rsa.PrivateKey, algoritmo string) ([]byte, error) {
// 	// Crear un certificado autofirmado
// 	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
// 	if err != nil {
// 		return nil, err
// 	}

// 	notBefore := time.Now()
// 	notAfter := notBefore.Add(365 * 24 * time.Hour) // Un año de validez

// 	template := x509.Certificate{
// 		SerialNumber: serialNumber,
// 		Subject: pkix.Name{
// 			Organization: []string{"My Organization"},
// 		},
// 		NotBefore:             notBefore,
// 		NotAfter:              notAfter,
// 		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
// 		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
// 		BasicConstraintsValid: true,
// 	}

// 	certificadoDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &clavePrivada.PublicKey, clavePrivada)
// 	if err != nil {
// 		return nil, err
// 	}

// 	return certificadoDER, nil
// }

// func guardarClavePrivadaComoPEM(clavePrivada *rsa.PrivateKey, nombreArchivo string) error {
// 	clavePrivadaPEM := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clavePrivada)}
// 	archivo, err := os.Create(nombreArchivo)
// 	if err != nil {
// 		return err
// 	}
// 	defer archivo.Close()

// 	return pem.Encode(archivo, clavePrivadaPEM)
// }

// func guardarCertificadoComoPEM(certificadoDER []byte, nombreArchivo string) error {
// 	certificadoPEM := &pem.Block{Type: "CERTIFICATE", Bytes: certificadoDER}
// 	archivo, err := os.Create(nombreArchivo)
// 	if err != nil {
// 		return err
// 	}
// 	defer archivo.Close()

// 	return pem.Encode(archivo, certificadoPEM)
// }

// func main() {
// 	// Generar un par de claves RSA
// 	clavePrivada, err := generarParDeClaves("rsa", 4096)
// 	if err != nil {
// 		panic(err)
// 	}

// 	// Crear certificado autofirmado
// 	certificadoDER, err := crearCertificado(clavePrivada, "rsa")
// 	if err != nil {
// 		panic(err)
// 	}

// 	// Guardar clave privada como archivo PEM
// 	err = guardarClavePrivadaComoPEM(clavePrivada, "private_key.pem")
// 	if err != nil {
// 		panic(err)
// 	}

// 	// Guardar certificado como archivo PEM
// 	err = guardarCertificadoComoPEM(certificadoDER, "certificate.pem")
// 	if err != nil {
// 		panic(err)
// 	}
// }
