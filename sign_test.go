package itsrisky

import (
	"crypto/sha1"
	"reflect"
	"strconv"
	"testing"
	"time"
)

func TestSigner(t *testing.T) {
	s := Signer{
		SecretKey: GenerateSecretKey(32),
		Hash:      sha1.New(),
	}
	var (
		str = "something information quite long"
	)
	signed, err := s.Sign(str)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := s.Unsign(signed)
	if err != nil {
		t.Fatal(err)
	}
	if unsigned != str {
		t.Errorf("expect %s got %s", str, unsigned)
	}
}

func TestSignerWithTimeout(t *testing.T) {
	s := SignerWithTimeout{
		SecretKey: GenerateSecretKey(32),
		Hash:      sha1.New(),
	}
	var (
		str = "something information quite long"
	)
	signed, err := s.Sign(str, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	unsigned, err := s.Unsign(signed)
	if err != nil {
		t.Fatal(err)
	}
	if unsigned != str {
		t.Errorf("expect %s got %s", str, unsigned)
	}
	time.Sleep(time.Second * 2)
	_, err = s.Unsign(signed)
	if _, ok := err.(*ErrDataExpired); !ok {
		t.Errorf("expect got expired err got %v", err)
	}
}

func TestSerialization(t *testing.T) {
	s := Serialization{
		SecretKey: GenerateSecretKey(32),
		Hash:      sha1.New(),
	}
	s.WithSalt(strconv.FormatInt(time.Now().UnixNano(), 10))
	type tokenData struct {
		UserId        uint64
		UserName      string
		UserAvatar    string
		UserCreatedAt int64
		IsVIP         bool
		UserLevel     []int
	}
	data := tokenData{
		UserId:        12580,
		UserName:      "UserName",
		UserAvatar:    "www.fakeuser.org/user/12580.png",
		UserCreatedAt: time.Now().Unix(),
		IsVIP:         false,
		UserLevel: []int{
			1,
			2,
			3,
		},
	}
	signed, err := s.Dumps(data, time.Hour*72)
	if err != nil {
		t.Fatal(err)
	}
	receiveData := new(tokenData)
	err = s.Loads(signed, receiveData)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(data, *receiveData) {
		t.Errorf("expect %v got %v", data, *receiveData)
	}
}

func BenchmarkSigner_Sign(b *testing.B) {
	b.StopTimer()
	s := Signer{
		SecretKey: GenerateSecretKey(32),
		Hash:      sha1.New(),
	}
	var (
		str = "something information quite long"
	)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.Sign(str)
		if err != nil {
			b.Log(err)
		}
	}
}

func BenchmarkSigner_Unsign(b *testing.B) {
	b.StopTimer()
	s := Signer{
		SecretKey: GenerateSecretKey(32),
		Hash:      sha1.New(),
	}
	var (
		str = "something information quite long"
	)
	signed, err := s.Sign(str)
	if err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.Unsign(signed)
		if err != nil {
			b.Log(err)
		}
	}
}

func BenchmarkSignerWithTimeout_Sign(b *testing.B) {
	b.StopTimer()
	s := SignerWithTimeout{
		SecretKey: GenerateSecretKey(32),
		Hash:      sha1.New(),
	}
	var (
		str = "something information quite long"
	)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.Sign(str, time.Hour*72)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSignerWithTimeout_Unsign(b *testing.B) {
	b.StopTimer()
	s := SignerWithTimeout{
		SecretKey: GenerateSecretKey(32),
		Hash:      sha1.New(),
	}
	var (
		str = "something information quite long"
	)
	signed, err := s.Sign(str, time.Hour)
	if err != nil {
		b.Fatal(err)
	}
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.Unsign(signed)
		if err != nil {
			b.Log(err)
		}
	}
}

func BenchmarkSerialization_Dumps(b *testing.B) {
	b.StopTimer()
	type tokenData struct {
		UserId        uint64
		UserName      string
		UserAvatar    string
		UserCreatedAt time.Time
		IsVIP         bool
		UserLevel     []int
	}
	data := tokenData{
		UserId:        12580,
		UserName:      "UserName",
		UserAvatar:    "www.fakeuser.org/user/12580.png",
		UserCreatedAt: time.Now(),
		IsVIP:         false,
		UserLevel: []int{
			1,
			2,
			3,
		},
	}
	s := Serialization{
		SecretKey: GenerateSecretKey(32),
		Hash:      sha1.New(),
	}
	s.WithSalt(strconv.FormatInt(time.Now().Unix(), 10))
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		_, err := s.Dumps(data, time.Hour*72)
		if err != nil {
			b.Log(err)
		}
	}
}

func BenchmarkSerialization_Loads(b *testing.B) {
	b.StopTimer()
	type tokenData struct {
		UserId        uint64
		UserName      string
		UserAvatar    string
		UserCreatedAt time.Time
		IsVIP         bool
		UserLevel     []int
	}
	data := tokenData{
		UserId:        12580,
		UserName:      "UserName",
		UserAvatar:    "www.fakeuser.org/user/12580.png",
		UserCreatedAt: time.Now(),
		IsVIP:         false,
		UserLevel: []int{
			1,
			2,
			3,
		},
	}
	s := Serialization{
		SecretKey: GenerateSecretKey(32),
		Hash:      sha1.New(),
	}
	s.WithSalt(strconv.FormatInt(time.Now().Unix(), 10))
	dumpsData, err := s.Dumps(data, time.Hour*72)
	if err != nil {
		b.Log(err)
	}
	receivedData := new(tokenData)
	b.StartTimer()
	for i := 0; i < b.N; i++ {
		err := s.Loads(dumpsData, receivedData)
		if err != nil {
			b.Log(err)
		}
	}
}
