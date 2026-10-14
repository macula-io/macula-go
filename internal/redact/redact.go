// Package redact formats a struct that carries a credential (a UCAN grant
// and its delegation proofs) without printing the credential: a log line or
// an error built with %v, %+v or %#v names it by its size instead.
package redact

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
)

// Grant names a credential by its length, never its bytes.
func Grant(grant []byte) string {
	if len(grant) == 0 {
		return "none"
	}
	return fmt.Sprintf("<grant, %d bytes>", len(grant))
}

// Struct writes v, a struct or a pointer to one, as {Name:value ...} with
// the fields named in secret shown as Grant shows them ([]byte) or by count
// and total size ([][]byte). Byte arrays and slices show in hex.
func Struct(v any, secret ...string) string {
	rv := reflect.Indirect(reflect.ValueOf(v))
	if rv.Kind() != reflect.Struct {
		return fmt.Sprintf("<%T>", v)
	}
	t := rv.Type()
	var b strings.Builder
	b.WriteByte('{')
	for i := range rv.NumField() {
		if i > 0 {
			b.WriteByte(' ')
		}
		name := t.Field(i).Name
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(field(rv.Field(i), slices.Contains(secret, name)))
	}
	b.WriteByte('}')
	return b.String()
}

func field(f reflect.Value, secret bool) string {
	switch {
	case secret && f.Kind() == reflect.Slice && f.Type().Elem().Kind() == reflect.Uint8:
		return Grant(f.Bytes())
	case secret && f.Kind() == reflect.Slice:
		size := 0
		for i := range f.Len() {
			size += f.Index(i).Len()
		}
		return fmt.Sprintf("<%d proofs, %d bytes>", f.Len(), size)
	case secret:
		return "<redacted>"
	case (f.Kind() == reflect.Array || f.Kind() == reflect.Slice) && f.Type().Elem().Kind() == reflect.Uint8:
		return fmt.Sprintf("%x", f)
	case f.Kind() == reflect.Pointer && f.IsNil():
		return "nil"
	default:
		return fmt.Sprintf("%+v", f)
	}
}
