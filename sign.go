// Package itsrisky is a library to generate data signature powered by hmac and a hash algorithm(default by SHA1)
package itsrisky

import (
	"crypto"
	"crypto/hmac"
	"fmt"
	"hash"
	"strconv"
	"strings"
	"time"

	"encoding/hex"
	"errors"
	"github.com/btcsuite/btcutil/base58"
	"github.com/json-iterator/go"
	"reflect"
)

// Get Signer's signature hash method, default by hmac with given secret key and SHA1(can be assigned)
func (s *Signer) getSignature() hash.Hash {
	if s.Hash == nil {
		s.Hash = crypto.SHA1.New()
	}
	return hmac.New(func() hash.Hash {
		return s.Hash
	}, []byte(s.SecretKey))
}

// to sign the given string with Signer's signature method, separate data between signature with `::`
func (s *Signer) Sign(value string) (string, error) {
	if len(value) == 0 {
		return "", &ErrDataTooShort{DataLength: len(value)}
	}
	hashFun := s.getSignature()
	sign := hashFun.Sum([]byte(value))
	return fmt.Sprintf("%s::%s", value, hex.EncodeToString(sign)), nil
}

// validate given signed string, return data if string is well signed
func (s *Signer) Unsign(value string) (string, error) {
	strs := strings.Split(value, "::")
	if len(strs) != 2 {
		return "", &ErrBadData{Data: value}
	}
	hashFun := s.getSignature()
	validSign := hashFun.Sum([]byte(strs[0]))
	if hmac.Equal(validSign, []byte(strs[1])) {
		return "", &ErrBadData{Data: value}
	}
	return strs[0], nil
}

// Get SignerWithTimeout's signature hash method, default by hmac with given secret key and SHA1(can be assigned)
func (s *SignerWithTimeout) getSignature() hash.Hash {
	if s.Hash == nil {
		s.Hash = crypto.SHA1.New()
	}
	return hmac.New(func() hash.Hash {
		return s.Hash
	}, []byte(s.SecretKey))
}

// to sign the given string (include deadline information) with Signer's signature method, separate data between signature with `::`
func (s *SignerWithTimeout) Sign(value string, expiredTime time.Duration) (string, error) {
	if len(value) == 0 {
		return "", &ErrDataTooShort{DataLength: len(value)}
	}
	hashFun := s.getSignature()
	deadline := strconv.FormatInt(time.Now().Add(expiredTime).Unix(), 10)
	deadlineEncode := base58.Encode([]byte(deadline))
	sign := hashFun.Sum(StringBytes(fmt.Sprintf("%s::%s", value, deadline)))
	return fmt.Sprintf("%s::%s::%s", value, hex.EncodeToString(sign), deadlineEncode), nil
}

// validate given signed string and check whether the data is expired, return data if string is well signed
func (s *SignerWithTimeout) Unsign(value string) (string, error) {
	strs := strings.Split(value, "::")
	if len(strs) != 3 {
		return "", &ErrBadData{Data: value}
	}
	hashFun := s.getSignature()
	deadlineStr := base58.Decode(strs[2])
	deadline, err := strconv.ParseInt(BytesString(deadlineStr), 10, 64)
	if err != nil {
		return "", &ErrBadData{Data: value, Err: err}
	}
	now := time.Now().Unix()
	if now > deadline {
		return "", &ErrDataExpired{deadline: deadline, currentTime: now}
	}
	validSign := hashFun.Sum(StringBytes(fmt.Sprintf("%s::%s", strs[0], BytesString(deadlineStr))))
	if hmac.Equal(validSign, []byte(strs[1])) {
		return "", &ErrBadData{Data: value}
	}
	return strs[0], nil
}

// Get Serialization's signature hash method, default by hmac with given secret key and SHA1(can be assigned)
func (s *Serialization) getSignature() hash.Hash {
	if s.Hash == nil {
		s.Hash = crypto.SHA1.New()
	}
	return hmac.New(func() hash.Hash {
		return s.Hash
	}, []byte(s.SecretKey))
}

// add salt to serialization
func (s *Serialization) WithSalt(salt string) {
	s.salt = salt
}

// dump the given data into json and generate a signature with data and deadline information
func (s *Serialization) Dumps(in interface{}, expiredTime time.Duration) (string, error) {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	b, err := json.Marshal(in)
	if err != nil {
		return "", &ErrBadData{Data: in, Err: err}
	}
	hashFun := s.getSignature()
	rawData := BytesString(b)
	deadline := strconv.FormatInt(time.Now().Add(expiredTime).Unix(), 10)
	deadlineEncode := base58.Encode(StringBytes(deadline))
	sign := hashFun.Sum(StringBytes(fmt.Sprintf("%s::%s", fmt.Sprintf("%s-%s", rawData, s.salt), deadline)))
	return fmt.Sprintf("%s::%s::%s", rawData, hex.EncodeToString(sign), deadlineEncode), nil
}

// validate given signed string and check whether the data is expired, return data if string is well signed
func (s *Serialization) Loads(data string, receiveData interface{}) (err error) {
	var json = jsoniter.ConfigCompatibleWithStandardLibrary
	if reflect.ValueOf(receiveData).Kind() != reflect.Ptr {
		return &ErrBadData{Data: data, Err: errors.New("receiveData shall be a pointer")}
	}
	strs := strings.Split(data, "::")
	if len(strs) != 3 {
		return &ErrBadData{Data: data}
	}
	hashFun := s.getSignature()
	deadlineStr := base58.Decode(strs[2])
	deadline, err := strconv.ParseInt(BytesString(deadlineStr), 10, 64)
	if err != nil {
		return &ErrBadData{Data: data}
	}
	now := time.Now().Unix()
	if now > deadline {
		return &ErrDataExpired{deadline: deadline, currentTime: now}
	}
	validSign := hashFun.Sum(StringBytes(fmt.Sprintf("%s::%s", fmt.Sprintf("%s-%s", strs[0], s.salt), BytesString(deadlineStr))))
	if hmac.Equal(validSign, []byte(strs[1])) {
		return &ErrBadData{Data: data}
	}
	if err := json.Unmarshal(StringBytes(strs[0]), receiveData); err != nil {
		return err
	}
	return nil
}
