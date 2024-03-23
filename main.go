package main

import (
	"bufio"
	"crypto/aes"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	randv2 "math/rand/v2"
	"os"

	"github.com/MidnightWonderer/IGE-go/ige"
	"github.com/google/uuid"
	"github.com/mtraver/base91"
	"github.com/skip2/go-qrcode"
	"github.com/xlzd/gotp"
	"golang.org/x/crypto/scrypt"
)

type Creds struct {
	Id       string
	Url      string
	User     string
	Size     int
	Pattern  string
	Password string
}

type vault struct {
	UUID       string
	IV         string
	SecretTOTP string
	Seed       string
	Body       []Creds
}

func main() {

	var mode, pass, url, user, pattern, newpass, otp, idpass string
	var size int
	var safe bool
	flag.StringVar(&mode, "mode", "", "")
	flag.StringVar(&pass, "password", "", "")
	flag.StringVar(&newpass, "newpassword", "", "")
	flag.StringVar(&url, "url", "", "")
	flag.StringVar(&user, "user", "", "")
	flag.StringVar(&pattern, "pattern", "", "")
	flag.StringVar(&idpass, "id", "", "")
	flag.StringVar(&otp, "otp", "", "")
	flag.IntVar(&size, "size", 0, "")
	flag.BoolVar(&safe, "safe", true, "")

	flag.CommandLine.SetOutput(io.Discard)

	flag.Usage = func() {
		fmt.Println()
		fmt.Fprintf(os.Stderr, "Usage (size 4 - 32):\n")
		fmt.Println()
		fmt.Fprintf(os.Stderr, "SAFE MODE : Remove -safe=false, passwords and OTP\n")
		fmt.Fprintf(os.Stderr, "$ vault -mode=generatevault -safe=false -password=YourPasswordHere\n")
		fmt.Fprintf(os.Stderr, "$ vault -mode=viewvault -safe=false -password=YourPasswordHere \n")
		fmt.Fprintf(os.Stderr, "$ vault -mode=changepass -safe=false -password=YourPasswordHere -newpassword=YourNewPasswordHere -otp=000000\n")
		fmt.Fprintf(os.Stderr, "$ vault -mode=removepass -safe=false -id=00000000-0000-0000-0000-000000000000")
		fmt.Println()
		fmt.Fprintf(os.Stderr, "$ vault -mode=addpass -safe=false -password=YourPasswordHere -url=\"http://example.com\" -user=admin -size=16 -pattern=2 -otp=000000\n")
		fmt.Println()
		fmt.Println("Enter your Pattern (0 - 3):")
		fmt.Println("Pattern 0: [0-9]")
		fmt.Println("Pattern 1: [a-zA-Z]")
		fmt.Println("Pattern 2: [a-zA-Z0-9]")
		fmt.Println("Pattern 3: * (base91)")
		fmt.Println()
		os.Exit(0)
	}
	flag.Parse()

	switch mode {
	case "generatevault":

		if safe && pass == "" {
			fmt.Println("Password:")
			getpass := bufio.NewScanner(os.Stdin)
			if getpass.Scan() {
				pass = getpass.Text()
			}
		} else {
			if pass == "" {
				flag.Usage()
			}
		}

		fmt.Println("Generating Vault")
		//gerando senha derivada
		newkey := derivateKey([]byte(pass))

		//Gerando seed aleatorio
		initSeed := generateKey(32)

		//Gerando IV
		hxiv := generateKey(32)
		newiv := fmt.Sprintf("%x", hxiv)
		//Gerando UUID do vault
		id := uuid.New()
		//Gerando segredo do OTP
		secretOTP := generateKey(32)
		EncodedSecretOtp := base32.StdEncoding.EncodeToString(secretOTP[0:10])
		fmt.Println("secret OTP: ", EncodedSecretOtp)
		fmt.Println()

		qrcode.WriteFile("otpauth://totp/SAJO VAULT?secret="+EncodedSecretOtp+"&issuer=VAULT", qrcode.Medium, 256, "vault.png")

		//Criptografando o secretOTP
		cipherOTP := IGEencrypter(newkey, string(secretOTP), hxiv)
		cipherseed := IGEencrypter(newkey, string(initSeed), hxiv)

		data := vault{}
		data.UUID = id.String()
		data.IV = newiv
		data.SecretTOTP = cipherOTP
		data.Seed = cipherseed

		file, _ := json.MarshalIndent(data, "", " ")
		_ = os.WriteFile("vault.json", file, 0600)

	case "addpass":

		if safe && pass == "" && otp == "" {
			fmt.Println("Password:")
			getpass := bufio.NewScanner(os.Stdin)
			if getpass.Scan() {
				pass = getpass.Text()
			}
			fmt.Println("OTP:")
			getotp := bufio.NewScanner(os.Stdin)
			if getotp.Scan() {
				otp = getotp.Text()
			}
		} else {
			if pass == "" {
				flag.Usage()
			}
		}
		if pass == "" || url == "" || user == "" || otp == "" || pattern == "" || size < 4 || size > 32 {
			flag.Usage()
		}

		file, _ := os.ReadFile("vault.json")
		data := vault{}
		_ = json.Unmarshal([]byte(file), &data)

		ivImported := decodeHex(data.IV)
		key := derivateKey([]byte(pass))
		plainSeed := IGEDecrypter(key, data.Seed, ivImported)

		plainOTP := IGEDecrypter(key, data.SecretTOTP, ivImported)
		secret := decodeHex(fmt.Sprintf("%02X", plainOTP[0:10]))
		EncodedSecretOtp := base32.StdEncoding.EncodeToString(secret)
		totp := gotp.NewDefaultTOTP(EncodedSecretOtp)
		if totp.Now() != otp {
			fmt.Println("Erro verificador OTP")
			fmt.Println("Certifique que a senha e o horario do seu celular esta correto")
			fmt.Println("OTP derivado: ", totp.Now())
			fmt.Println("Seu OTP: ", otp)
			flag.Usage()

		}

		switch pattern {

		case "0":
			pattern = "[0-9]"
		case "1":
			pattern = "[a-zA-Z]"
		case "2":
			pattern = "[a-zA-Z0-9]"
		case "3":
			pattern = "*"
		default:
			flag.Usage()

		}

		//Gerando dados para nova senha
		id := uuid.New()
		passGen := string(generateKey(32))
		cipherpass := IGEencrypter(plainSeed, passGen, ivImported)

		data.Body = append(data.Body, Creds{
			Id:       id.String(),
			Url:      url,
			User:     user,
			Size:     size,
			Pattern:  pattern,
			Password: cipherpass,
		})

		file, _ = json.MarshalIndent(data, "", " ")
		_ = os.WriteFile("vault.json", file, 0600)

	case "viewvault":
		file, _ := os.ReadFile("vault.json")
		data := vault{}
		_ = json.Unmarshal([]byte(file), &data)

		ivImported := decodeHex(data.IV)
		if safe && pass == "" {
			fmt.Println("Password:")
			getpass := bufio.NewScanner(os.Stdin)
			if getpass.Scan() {
				pass = getpass.Text()
			}
		} else {
			if pass == "" {
				flag.Usage()
			}
		}
		key := derivateKey([]byte(pass))
		plainSeed := IGEDecrypter(key, data.Seed, ivImported)
		plainOTP := IGEDecrypter(key, data.SecretTOTP, ivImported)
		secret := decodeHex(fmt.Sprintf("%02X", plainOTP[0:10]))
		EncodedSecretOtp := base32.StdEncoding.EncodeToString(secret)
		totp := gotp.NewDefaultTOTP(EncodedSecretOtp)
		fmt.Println("OTP Pin Checker: ", totp.Now())
		fmt.Println()
		for i := 0; i < len(data.Body); i++ {
			fmt.Println("ID:", data.Body[i].Id)
			fmt.Println("Url:", data.Body[i].Url)
			fmt.Println("User:", data.Body[i].User)

			plainSeed := IGEDecrypter(plainSeed, data.Body[i].Password, ivImported)
			fmt.Printf("Raw Pass: %02x \n", plainSeed)

			switch data.Body[i].Pattern {
			case "[0-9]":
				RandSeed := binary.BigEndian.Uint64([]byte(plainSeed))
				fmt.Println("Pass generated:", RandomInt(data.Body[i].Size, uint64(RandSeed)))
			case "[a-zA-Z]":
				RandSeed := binary.BigEndian.Uint64([]byte(plainSeed))
				fmt.Println("Pass generated:", RandomString(data.Body[i].Size, uint64(RandSeed)))

			case "[a-zA-Z0-9]":
				fmt.Println("Pass generated:", toBase([]byte(plainSeed), 36)[0:data.Body[i].Size])

			case "*":
				EncodedSecretOtp := base91.StdEncoding.EncodeToString([]byte(plainSeed))
				fmt.Println("Pass generated:", EncodedSecretOtp[0:data.Body[i].Size])

			default:
				fmt.Println("Houve um erro na senha de id ", data.Body[i].Id)

			}

			fmt.Println()
		}

	case "changepass":
		file, _ := os.ReadFile("vault.json")
		data := vault{}
		_ = json.Unmarshal([]byte(file), &data)

		ivImported := decodeHex(data.IV)
		key := derivateKey([]byte(pass))
		plainSeed := IGEDecrypter(key, data.Seed, ivImported)

		plainOTP := IGEDecrypter(key, data.SecretTOTP, ivImported)
		secret := decodeHex(fmt.Sprintf("%02X", plainOTP[0:10]))
		EncodedSecretOtp := base32.StdEncoding.EncodeToString(secret)
		totp := gotp.NewDefaultTOTP(EncodedSecretOtp)

		if safe && otp == "" && newpass == "" {
			fmt.Println("New Password:")
			getnewpass := bufio.NewScanner(os.Stdin)
			if getnewpass.Scan() {
				newpass = getnewpass.Text()
			}

			fmt.Println("OTP:")
			getotp := bufio.NewScanner(os.Stdin)
			if getotp.Scan() {
				otp = getotp.Text()
			}

		} else {
			if pass == "" || newpass == "" || otp == "" {
				flag.Usage()
			}
		}

		if totp.Now() != otp {
			fmt.Println("Erro verificador OTP")
			fmt.Println("Certifique que as senhas e o horario do seu celular")
			fmt.Println("OTP derivado: ", totp.Now())
			fmt.Println("Seu OTP: ", otp)
			flag.Usage()

		}

		//Gerando chave e IV novo
		newkey := derivateKey([]byte(newpass))

		newiv := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, newiv); err != nil {
			panic(err.Error())
		}
		hxiv := fmt.Sprintf("%x", newiv)

		for i := 0; i < len(data.Body); i++ {
			plainPass := IGEDecrypter(plainSeed, data.Body[i].Password, ivImported)
			NewCipherpass := IGEencrypter(plainSeed, plainPass, newiv)
			data.Body[i].Password = NewCipherpass

		}

		NewCipherOTP := IGEencrypter(newkey, plainOTP, newiv)
		NewCipherseed := IGEencrypter(newkey, plainSeed, newiv)

		data.SecretTOTP = NewCipherOTP
		data.Seed = NewCipherseed
		data.IV = hxiv

		file, _ = json.MarshalIndent(data, "", " ")
		_ = os.WriteFile("vault.json", file, 0600)

	case "removepass":
		file, _ := os.ReadFile("vault.json")
		data := vault{}
		_ = json.Unmarshal([]byte(file), &data)

		for i := 0; i < len(data.Body); i++ {
			if data.Body[i].Id == idpass {
				data.Body[i] = data.Body[len(data.Body)-1] // Copia o ultimo elemento para i.
				data.Body[len(data.Body)-1] = Creds{}      // apaga o ultimo elemento
				data.Body = data.Body[:len(data.Body)-1]   // remove o ultimo elemento
			}

		}

		file, _ = json.MarshalIndent(data, "", " ")
		_ = os.WriteFile("vault.json", file, 0600)

	default:
		flag.Usage()

	}

}

func decodeHex(iv string) []byte {

	ivImported, err := hex.DecodeString(iv)
	if err != nil {
		panic(err)
	}
	return ivImported
}

func derivateKey(passDerivate []byte) string {
	dk, err := scrypt.Key([]byte(passDerivate), nil, 1<<16, 8, 1, 32)
	if err != nil {
		flag.Usage()
	}
	return string(dk)
}

func generateKey(size int) []byte {

	randKey := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, randKey); err != nil {
		panic(err.Error())
	}

	return randKey

}

func IGEencrypter(key string, plaintext string, iv []byte) string {
	aesBlock, _ := aes.NewCipher([]byte(key))
	igeEnc := ige.NewIGEEncrypter(aesBlock, iv)
	nplain := fmt.Sprintf("%X", plaintext)
	plain, _ := hex.DecodeString(nplain)
	igeEnc.CryptBlocks(plain, plain)

	return hex.EncodeToString(plain)
}

func IGEDecrypter(key string, ct string, iv []byte) string {
	aesBlock, _ := aes.NewCipher([]byte(key))
	igeDec := ige.NewIGEDecrypter(aesBlock, iv)
	ciphered, _ := hex.DecodeString(ct)
	igeDec.CryptBlocks(ciphered, ciphered)
	return string(ciphered[:])
}

func toBase(pass2base []byte, base int) string {
	var i big.Int
	i.SetBytes(pass2base[:])
	return i.Text(base)
}

func RandomString(n int, RandSeed uint64) string {
	s2 := randv2.NewPCG(RandSeed, RandSeed)
	al := randv2.New(s2)
	var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[al.IntN(len(letters))]
	}
	return string(s)
}
func RandomInt(n int, RandSeed uint64) string {

	s2 := randv2.NewPCG(RandSeed, RandSeed)
	al := randv2.New(s2)

	var letters = []rune("0123456789")

	s := make([]rune, n)
	for i := range s {
		s[i] = letters[al.IntN(len(letters))]
	}
	return string(s)
}
