//go:build ignore

// p11-init-token initializes a token of a PKCS#11 module and sets its user
// PIN, for scripts/config-kryoptic.sh: C_InitToken with an SO PIN derived from
// the user PIN, then C_InitPIN. It stands in for pkcs11-tool, so a fixture needs
// no OpenSC. It reinitializes a token that already exists, erasing its keys.
//
//	go run scripts/p11-init-token.go --module libkryoptic_pkcs11.so \
//		--slot 1 --label xpki_mldsa --pin-file pin.txt
package main

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/cockroachdb/errors"
	"github.com/miekg/pkcs11"
)

// soPinPrefix derives the SO PIN from the user PIN, as config-softhsm.sh does.
const soPinPrefix = "so"

func main() {
	module := flag.String("module", "", "PKCS#11 module file")
	slot := flag.Uint("slot", 0, "slot of the token to initialize")
	label := flag.String("label", "", "token label")
	pinFile := flag.String("pin-file", "", "file with the user PIN")
	flag.Parse()

	if err := run(*module, *slot, *label, *pinFile); err != nil {
		fmt.Fprintf(os.Stderr, "p11-init-token: %v\n", err)
		os.Exit(1)
	}
}

func run(module string, slot uint, label, pinFile string) error {
	if module == "" || label == "" || pinFile == "" {
		return errors.New("--module, --label and --pin-file are required")
	}
	data, err := os.ReadFile(pinFile)
	if err != nil {
		return errors.WithMessage(err, "unable to read the PIN file")
	}
	pin := strings.TrimRight(string(data), "\r\n")
	if pin == "" {
		return errors.New("the PIN file is empty")
	}

	ctx := pkcs11.New(module)
	if ctx == nil {
		return errors.Errorf("unable to load module: %s", module)
	}
	defer ctx.Destroy()
	if err := ctx.Initialize(); err != nil {
		return errors.WithMessage(err, "C_Initialize")
	}
	defer func() { _ = ctx.Finalize() }()

	soPin := soPinPrefix + pin
	if err := ctx.InitToken(slot, soPin, label); err != nil {
		return errors.WithMessage(err, "C_InitToken")
	}
	// a module may move an initialized token to another slot, as SoftHSM does
	if slot, err = findSlot(ctx, label); err != nil {
		return err
	}
	session, err := ctx.OpenSession(slot, pkcs11.CKF_SERIAL_SESSION|pkcs11.CKF_RW_SESSION)
	if err != nil {
		return errors.WithMessage(err, "C_OpenSession")
	}
	defer func() { _ = ctx.CloseSession(session) }()
	if err := ctx.Login(session, pkcs11.CKU_SO, soPin); err != nil {
		return errors.WithMessage(err, "C_Login as SO")
	}
	defer func() { _ = ctx.Logout(session) }()
	if err := ctx.InitPIN(session, pin); err != nil {
		return errors.WithMessage(err, "C_InitPIN")
	}
	return nil
}

// findSlot returns the slot of the token with label.
func findSlot(ctx *pkcs11.Ctx, label string) (uint, error) {
	slots, err := ctx.GetSlotList(true)
	if err != nil {
		return 0, errors.WithMessage(err, "C_GetSlotList")
	}
	for _, slot := range slots {
		info, err := ctx.GetTokenInfo(slot)
		if err != nil {
			return 0, errors.WithMessage(err, "C_GetTokenInfo")
		}
		if strings.TrimRight(info.Label, " \x00") == label {
			return slot, nil
		}
	}
	return 0, errors.Errorf("no token with label %q", label)
}
