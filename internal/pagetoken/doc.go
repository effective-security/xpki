// Package pagetoken encodes the position of a paged listing as an opaque
// string and binds it to the request it was issued for.
//
// A token is the base64url encoding of a JSON envelope: a version, a binding
// and the payload. The binding is a short hash of whatever the caller says the
// token belongs to (cryptoprov uses the filter and the field mask of a
// ListKeysRequest), so a token presented with another request is rejected
// instead of resuming a different listing. Tokens are neither secret nor
// authenticated: whoever holds one can read and forge it, which only moves
// that caller's own cursor.
//
//	token, err := pagetoken.Encode(binding, cursor{Marker: "m", Offset: 20})
//	...
//	var c cursor
//	err = pagetoken.Decode(binding, token, &c) // errors.Is(err, pagetoken.ErrInvalid)
package pagetoken
