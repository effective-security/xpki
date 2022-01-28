package ctl

import (
	"reflect"
	"strings"

	"github.com/alecthomas/kong"
	"github.com/pkg/errors"
)

type boolPtrMapper struct{}

func (boolPtrMapper) Decode(ctx *kong.DecodeContext, target reflect.Value) error {
	trueVal := true
	falseVal := false

	truePtr := &trueVal
	falsePtr := &falseVal

	peekType := ctx.Scan.Peek().Type
	if peekType == kong.FlagValueToken {
		token := ctx.Scan.Pop()
		switch v := token.Value.(type) {
		case string:
			v = strings.ToLower(v)
			switch v {
			case "true", "1", "yes":
				target.Set(reflect.ValueOf(truePtr))

			case "false", "0", "no":
				target.Set(reflect.ValueOf(falsePtr))

			default:
				return errors.Errorf("bool value must be true, 1, yes, false, 0 or no but got %q", v)
			}

		case bool:
			target.Set(reflect.ValueOf(&v))

		default:
			return errors.Errorf("expected bool but got %q (%T)", token.Value, token.Value)
		}
	} else {
		target.Set(reflect.ValueOf(truePtr))
	}
	return nil
}

func (boolPtrMapper) IsBool() bool { return true }

var b bool

// BoolPtrMapper is an option to register a mapper to *bool type flag
var BoolPtrMapper = kong.TypeMapper(reflect.TypeOf(&b), boolPtrMapper{})
