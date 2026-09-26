// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

package dcap

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
	"unicode/utf8"
)

// The collateral JSON is decoded the way upstream's serde derives decode
// it, not the way encoding/json does: keys match exactly (encoding/json
// folds case), a repeated known key is an error (encoding/json keeps the
// last), every field without a default must be present, null is not a
// value for a number or string, and unknown keys are ignored. Two serde
// leniencies are not reproduced, so such input is rejected here: structs
// written as JSON arrays and unit enum variants written as {"Name": null}.

var errJSON = errors.New("json")

func jsonErr(format string, args ...any) error {
	return fmt.Errorf("%w: %w: %s", ErrMalformed, errJSON, fmt.Sprintf(format, args...))
}

// jsonFields maps the known keys of an object to their raw values; a key
// that must be present is required.
type jsonFields map[string]*jsonField

type jsonField struct {
	raw      json.RawMessage
	optional bool
	seen     bool
}

func (f jsonFields) get(key string) json.RawMessage { return f[key].raw }

func (f jsonFields) has(key string) bool { return f[key].seen }

// decodeObject reads the JSON object in data into fields. data must be
// valid UTF-8 and hold exactly one value, surrounding whitespace aside.
func decodeObject(data []byte, fields jsonFields) error {
	if !utf8.Valid(data) {
		return jsonErr("invalid UTF-8")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	tok, err := dec.Token()
	if err != nil {
		return jsonErr("%v", err)
	}
	if tok != json.Delim('{') {
		return jsonErr("expected an object")
	}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return jsonErr("%v", err)
		}
		key, _ := tok.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return jsonErr("%v", err)
		}
		f, ok := fields[key]
		if !ok {
			continue
		}
		if f.seen {
			return jsonErr("duplicate field %q", key)
		}
		f.raw, f.seen = raw, true
	}
	if _, err := dec.Token(); err != nil {
		return jsonErr("%v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return jsonErr("trailing data")
	}
	for key, f := range fields {
		if !f.seen && !f.optional {
			return jsonErr("missing field %q", key)
		}
	}
	return nil
}

// fieldsOf returns required fields for keys.
func fieldsOf(keys ...string) jsonFields {
	f := make(jsonFields, len(keys))
	for _, k := range keys {
		f[k] = &jsonField{}
	}
	return f
}

func isNull(raw json.RawMessage) bool { return bytes.Equal(bytes.TrimSpace(raw), []byte("null")) }

func decodeUint(raw json.RawMessage, bits int, name string) (uint64, error) {
	s := string(bytes.TrimSpace(raw))
	v, err := strconv.ParseUint(s, 10, bits)
	if err != nil || (len(s) > 1 && s[0] == '0') {
		return 0, jsonErr("%s: invalid u%d %s", name, bits, s)
	}
	return v, nil
}

func decodeU8(raw json.RawMessage, name string) (uint8, error) {
	v, err := decodeUint(raw, 8, name)
	return uint8(v), err //nolint:gosec // G115: ParseUint bounded v to 8 bits
}

func decodeU16(raw json.RawMessage, name string) (uint16, error) {
	v, err := decodeUint(raw, 16, name)
	return uint16(v), err //nolint:gosec // G115: ParseUint bounded v to 16 bits
}

func decodeString(raw json.RawMessage, name string) (string, error) {
	var s string
	if isNull(raw) {
		return "", jsonErr("%s: null", name)
	}
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", jsonErr("%s: %v", name, err)
	}
	return s, nil
}

// decodeHex decodes a hex string of exactly len(dst) bytes.
func decodeHex(raw json.RawMessage, dst []byte, name string) error {
	s, err := decodeString(raw, name)
	if err != nil {
		return err
	}
	if hex.DecodedLen(len(s)) != len(dst) || len(s)%2 != 0 {
		return jsonErr("%s: want %d hex bytes", name, len(dst))
	}
	if _, err := hex.Decode(dst, []byte(s)); err != nil {
		return jsonErr("%s: %v", name, err)
	}
	return nil
}

func decodeTime(raw json.RawMessage, name string) (time.Time, error) {
	s, err := decodeString(raw, name)
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, jsonErr("%s: %v", name, err)
	}
	return t, nil
}

// decodeArray splits a JSON array into its raw elements.
func decodeArray(raw json.RawMessage, name string) ([]json.RawMessage, error) {
	var elems []json.RawMessage
	if isNull(raw) {
		return nil, jsonErr("%s: null", name)
	}
	if err := json.Unmarshal(raw, &elems); err != nil {
		return nil, jsonErr("%s: %v", name, err)
	}
	return elems, nil
}

// decodeEnum decodes a unit enum variant written as a string.
func decodeEnum[T any](raw json.RawMessage, variants map[string]T, name string) (T, error) {
	var zero T
	s, err := decodeString(raw, name)
	if err != nil {
		return zero, err
	}
	v, ok := variants[s]
	if !ok {
		return zero, jsonErr("%s: unknown variant %q", name, s)
	}
	return v, nil
}
