package cli

import (
	"fmt"
	"time"

	"github.com/effective-security/xpki/cryptoprov"
	"github.com/pkg/errors"
)

// HsmCmd is the parent for HSM command
type HsmCmd struct {
	Lskey HsmLsKeyCmd `cmd:"" help:"List keys"`
}

// HsmLsKeyCmd prints Keys
type HsmLsKeyCmd struct {
	Token  string `help:"specifies slot token (optional)"`
	Serial string `help:"specifies slot serial (optional)"`
	Prefix string `help:"specifies key label prefix (optional)"`
}

// Run the command
func (a *HsmLsKeyCmd) Run(ctl *Cli) error {
	keyProv, ok := ctl.CryptoProv().Default().(cryptoprov.KeyManager)
	if !ok {
		return errors.Errorf("unsupported command for this crypto provider")
	}

	isDefaultSlot := a.Serial == "" && a.Token == ""
	filterSerial := a.Serial
	if filterSerial == "" {
		filterSerial = "--@--"
	}
	filterLabel := a.Token
	if filterLabel == "" {
		filterLabel = "--@--"
	}

	out := ctl.Writer()
	printSlot := func(slotID uint, description, label, manufacturer, model, serial string) error {
		if isDefaultSlot || serial == filterSerial || label == filterLabel {
			fmt.Fprintf(out, "Slot: %d\n", slotID)
			fmt.Fprintf(out, "  Description:  %s\n", description)
			fmt.Fprintf(out, "  Token serial: %s\n", serial)
			fmt.Fprintf(out, "  Token label:  %s\n", label)

			count := 0
			err := keyProv.EnumKeys(slotID, a.Prefix, func(id, label, typ, class, currentVersionID string, creationTime *time.Time) error {
				count++
				fmt.Fprintf(out, "[%d]\n", count)
				fmt.Fprintf(out, "  Id:    %s\n", id)
				fmt.Fprintf(out, "  Label: %s\n", label)
				fmt.Fprintf(out, "  Type:  %s\n", typ)
				fmt.Fprintf(out, "  Class: %s\n", class)
				fmt.Fprintf(out, "  Version: %s\n", currentVersionID)
				if creationTime != nil {
					fmt.Fprintf(out, "  Created: %s\n", creationTime.Format(time.RFC3339))
				}
				return nil
			})
			if err != nil {
				return errors.WithMessagef(err, "failed to list keys on slot %d", slotID)
			}

			if a.Prefix != "" && count == 0 {
				fmt.Fprintf(out, "no keys found with prefix: %s\n", a.Prefix)
			}
		}
		return nil
	}

	return keyProv.EnumTokens(isDefaultSlot, printSlot)
}
