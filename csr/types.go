package csr

import (
	"encoding/asn1"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/pkg/errors"
)

const (
	// UserNoticeQualifierType defines id-qt-unotice
	UserNoticeQualifierType = "id-qt-unotice"
	// CpsQualifierType defines id-qt-cps
	CpsQualifierType = "id-qt-cps"

	// OneYear duration
	OneYear = Duration(8760 * time.Hour)
)

// BasicConstraints CSR information RFC 5280, 4.2.1.9
type BasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

// OID is the asn1's ObjectIdentifier, provide a custom
// JSON marshal / unmarshal.
type OID asn1.ObjectIdentifier

// Equal reports whether oi and other represent the same identifier.
func (oid OID) Equal(other OID) bool {
	return asn1.ObjectIdentifier(oid).Equal(asn1.ObjectIdentifier(other))
}

func (oid OID) String() string {
	return asn1.ObjectIdentifier(oid).String()
}

// UnmarshalJSON unmarshals a JSON string into an OID.
func (oid *OID) UnmarshalJSON(data []byte) (err error) {
	last := len(data) - 1
	if data[0] != '"' || data[last] != '"' {
		return errors.New("OID JSON string not wrapped in quotes: " + string(data))
	}
	parsedOid, err := ParseObjectIdentifier(string(data[1:last]))
	if err != nil {
		return err
	}
	*oid = OID(parsedOid)
	return
}

// UnmarshalYAML unmarshals a YAML string into an OID.
func (oid *OID) UnmarshalYAML(unmarshal func(any) error) error {
	var buf string
	err := unmarshal(&buf)
	if err != nil {
		return err
	}

	parsedOid, err := ParseObjectIdentifier(buf)
	if err != nil {
		return err
	}
	*oid = OID(parsedOid)
	return err
}

// MarshalJSON marshals an oid into a JSON string.
func (oid OID) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf(`"%v"`, asn1.ObjectIdentifier(oid))), nil
}

// ParseObjectIdentifier returns OID
func ParseObjectIdentifier(oidString string) (oid asn1.ObjectIdentifier, err error) {
	validOID, err := regexp.MatchString("\\d(\\.\\d+)*", oidString)
	if err != nil {
		return
	}
	if !validOID {
		err = errors.Errorf("invalid OID: %q", oidString)
		return
	}

	segments := strings.Split(oidString, ".")
	oid = make(asn1.ObjectIdentifier, len(segments))
	for i, intString := range segments {
		oid[i], err = strconv.Atoi(intString)
		if err != nil {
			err = errors.WithMessagef(err, "invalid OID")
			return
		}
	}
	return
}

// Duration represents a period of time, its the same as time.Duration
// but supports better marshalling from json
type Duration time.Duration

// UnmarshalJSON handles decoding our custom json serialization for Durations
// json values that are numbers are treated as seconds
// json values that are strings, can use the standard time.Duration units indicators
// e.g. this can decode val:100 as well as val:"10m"
func (d *Duration) UnmarshalJSON(b []byte) error {
	if b[0] == '"' {
		dir, err := time.ParseDuration(string(b[1 : len(b)-1]))
		*d = Duration(dir)
		return err
	}
	i, err := json.Number(string(b)).Int64()
	*d = Duration(time.Duration(i) * time.Second)
	return err
}

// UnmarshalYAML handles decoding our custom json serialization for Durations
func (d *Duration) UnmarshalYAML(unmarshal func(any) error) error {
	var buf string
	err := unmarshal(&buf)
	if err != nil {
		return err
	}

	dir, err := time.ParseDuration(buf)
	*d = Duration(dir)
	return err
}

// MarshalJSON encodes our custom Duration value as a quoted version of its underlying value's String() output
// this means you get a duration with a trailing units indicator, e.g. "10m0s"
func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(`"` + d.String() + `"`), nil
}

// String returns a string formatted version of the duration in a valueUnits format, e.g. 5m0s for 5 minutes
func (d Duration) String() string {
	return time.Duration(d).String()
}

// TimeDuration returns this duration in a time.Duration type
func (d Duration) TimeDuration() time.Duration {
	return time.Duration(d)
}
