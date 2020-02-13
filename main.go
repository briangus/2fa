// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// 2fa is a two-factor authentication agent.
//
// Usage:
//
//	2fa -add [-7] [-8] [-hotp] name
//	2fa -list
//	2fa [-clip] name
//
// “2fa -add name” adds a new key to the 2fa keychain with the given name.
// It prints a prompt to standard error and reads a two-factor key from standard input.
// Two-factor keys are short case-insensitive strings of letters A-Z and digits 2-7.
//
// By default the new key generates time-based (TOTP) authentication codes;
// the -hotp flag makes the new key generate counter-based (HOTP) codes instead.
//
// By default the new key generates 6-digit codes; the -7 and -8 flags select
// 7- and 8-digit codes instead.
//
// “2fa -list” lists the names of all the keys in the keychain.
//
// “2fa name” prints a two-factor authentication code from the key with the
// given name. If “-clip” is specified, 2fa also copies the code to the system
// clipboard.
//
// With no arguments, 2fa prints two-factor authentication codes from all
// known time-based keys.
//
// The default time-based authentication codes are derived from a hash of
// the key and the current time, so it is important that the system clock have
// at least one-minute accuracy.
//
// The keychain is stored unencrypted in the text file $HOME/.2fa.
//
// Example
//
// During GitHub 2FA setup, at the “Scan this barcode with your app” step,
// click the “enter this text code instead” link. A window pops up showing
// “your two-factor secret,” a short string of letters and digits.
//
// Add it to 2fa under the name github, typing the secret at the prompt:
//
//	$ 2fa -add github
//	2fa key for github: nzxxiidbebvwk6jb
//	$
//
// Then whenever GitHub prompts for a 2FA code, run 2fa to obtain one:
//
//	$ 2fa github
//	268346
//	$
//
// Or to type less:
//
//	$ 2fa
//	268346	github
//	$
//
package main

import (
	"bufio"
//	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/md5"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"syscall"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
//	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/atotto/clipboard"
	"golang.org/x/crypto/ssh/terminal"
)

var (
	flagAdd  = flag.Bool("add", false, "add a key")
	flagList = flag.Bool("list", false, "list keys")
	flagHotp = flag.Bool("hotp", false, "add key as HOTP (counter-based) key")
	flag7    = flag.Bool("7", false, "generate 7-digit code")
	flag8    = flag.Bool("8", false, "generate 8-digit code")
	flagClip = flag.Bool("clip", false, "copy code to the clipboard")
	flagp    = flag.Bool("p", false, "passphrase piped in")
	flagDump = flag.Bool("dump", false, "Dump json data")
)

func usage() {
	fmt.Fprintf(os.Stderr, "usage:\n")
	fmt.Fprintf(os.Stderr, "\t2fa -add [-7] [-8] [-hotp] keyname\n")
	fmt.Fprintf(os.Stderr, "\t2fa [-p] -list\n")
	fmt.Fprintf(os.Stderr, "\t2fa [-p] [-clip] keyname\n")
	fmt.Fprintf(os.Stderr, "\t2fa [-p] -dump\n")
	os.Exit(2)
}

func getPassphrase() (string, error) {
	if *flagp {
		passphrase, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil {
			log.Fatalf("error reading key: %v", err)
		}
		if passphrase[len(passphrase)-1] == '\n' {
			return passphrase[:len(passphrase) - 1], nil
		}
		fmt.Println("passphrase:",passphrase)
		return passphrase, nil
	} else {
		fmt.Fprintf(os.Stderr, "Passphrase: ")
		passphrase, err := terminal.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return "", err
		}
		fmt.Fprintf(os.Stderr, "\n")
		return string(passphrase), nil
	}
}

func main() {
	log.SetPrefix("2fa: ")
	log.SetFlags(0)
	flag.Usage = usage
	flag.Parse()

	passphrase, err := getPassphrase()
	if err != nil {
		log.Fatalf("error reading passphrase: %v", err)
	}

	k := readKeychain(filepath.Join(os.Getenv("HOME"), ".2fa.json"), passphrase)

	if *flagDump {
		data, err := json.Marshal(k.keys)
		if err != nil {
			log.Fatalf("Error dumping file: %v", err)
		}
		fmt.Println(string(data))
		return
	}

	if *flagList {
		if flag.NArg() != 0 {
			usage()
		}
		k.list()
		return
	}
	if flag.NArg() == 0 && !*flagAdd {
		if *flagClip {
			usage()
		}
		k.showAll()
		return
	}
	if flag.NArg() != 1 {
		usage()
	}
	name := flag.Arg(0)
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		log.Fatal("name must not contain spaces")
	}
	if *flagAdd {
		if *flagClip {
			usage()
		}
		k.add(name)
		return
	}
	k.show(name)
}

type Keychain struct {
	file string
	passphrase string
	keys map[string]Key
}

type Key struct {
	Raw    string
	Digits int
	Offset int64 // offset of counter
}

func createHash(key string) string {
	hasher := md5.New()
	hasher.Write([]byte(key))
	return hex.EncodeToString(hasher.Sum(nil))
}

func encrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(createHash(passphrase)))
	if err != nil {
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return []byte{}, err
	}
	return gcm.Seal(nonce, nonce, data, nil), nil
}

func decrypt(data []byte, passphrase string) ([]byte, error) {
	block, err := aes.NewCipher([]byte(createHash(passphrase)))
	if err != nil {
		return []byte{}, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return []byte{}, err
	}
	nonceSize := gcm.NonceSize()
	return gcm.Open(nil, data[:nonceSize], data[nonceSize:], nil)
}

func encryptFile(filename string, data []byte, passphrase string) error {
	fd, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	fd.Chmod(0600)
	defer fd.Close()
	ciphertext, err := encrypt(data, passphrase)
	if err != nil {
		return err
	}
	_, err = fd.Write(ciphertext)
	return err
}

func decryptFile(filename string, passphrase string) ([]byte, error) {
	ciphertext, err := ioutil.ReadFile(filename)
	if err != nil {
		return []byte{}, err
	}
	return decrypt(ciphertext, passphrase)
}

func readKeychain(file string, passphrase string) *Keychain {
	c := &Keychain{
		file: file,
		passphrase: passphrase,
		keys: make(map[string]Key),
	}
	data, err := decryptFile(file, passphrase)
	if err != nil {
		if os.IsNotExist(err) {
			c.keys = make(map[string]Key)
			return c
		}
		log.Fatal(err)
	}
	
	err = json.Unmarshal(data, &(c.keys))
	if err != nil {
		log.Fatal(err)
	}
	return c
}

func (c *Keychain) list() {
	var names []string
	for name := range c.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
}

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

func (c *Keychain) writeKeyChain() error {
	data, err := json.Marshal(c.keys)
	if err != nil {
		return err
	}
	return encryptFile(c.file, data, c.passphrase)
}

func (c *Keychain) add(name string) {
	size := 6
	if *flag7 {
		size = 7
		if *flag8 {
			log.Fatalf("cannot use -7 and -8 together")
		}
	} else if *flag8 {
		size = 8
	}

	fmt.Fprintf(os.Stderr, "2fa key for %s: ", name)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	text = strings.Map(noSpace, text)
	text += strings.Repeat("=", -len(text)&7) // pad to 8 bytes
	if _, err := decodeKey(text); err != nil {
		log.Fatalf("invalid key: %v", err)
	}

	var offset int64
	offset = -1
	if *flagHotp {
		offset = 0
	}
    c.keys[name] =  Key{text, size, offset}
	c.writeKeyChain()
}

func (c *Keychain) code(name string) string {
	k, ok := c.keys[name]
	if !ok {
		log.Fatalf("no such key %q", name)
	}
	var code int
	thekey, err := decodeKey(k.Raw)
	if err != nil {
		log.Fatalf("invalid key: %v", err)
	}
	if k.Offset != -1 {
		k.Offset ++
		c.keys[name] = Key{k.Raw, k.Digits, k.Offset}
		code = hotp(thekey, uint64(k.Offset), k.Digits)
		c.writeKeyChain()
	} else {
		// Time-based key.
		code = totp(thekey, time.Now(), k.Digits)
	}
	return fmt.Sprintf("%0*d", k.Digits, code)
}

func (c *Keychain) show(name string) {
	code := c.code(name)
	if *flagClip {
		clipboard.WriteAll(code)
	}
	fmt.Printf("%s\n", code)
}

func (c *Keychain) showAll() {
	var names []string
	max := 0
	for name, k := range c.keys {
		names = append(names, name)
		if max < k.Digits {
			max = k.Digits
		}
	}
	sort.Strings(names)
	for _, name := range names {
		k := c.keys[name]
		code := strings.Repeat("-", k.Digits)
		if k.Offset == 0 {
			code = c.code(name)
		}
		fmt.Printf("%-*s\t%s\n", max, code, name)
	}
}

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func hotp(key []byte, counter uint64, digits int) int {
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(key []byte, t time.Time, digits int) int {
	return hotp(key, uint64(t.UnixNano())/30e9, digits)
}
