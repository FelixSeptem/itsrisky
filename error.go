package itsrisky

import "fmt"

// Err about invalid data length
type ErrDataTooShort struct {
	DataLength int
}

func (e *ErrDataTooShort) Error() string {
	return fmt.Sprintf("data length:%d too short", e.DataLength)
}

// Err about data format invalid
type ErrBadData struct {
	Data interface{}
	Err  error
}

func (e *ErrBadData) Error() string {
	return fmt.Sprintf("data:%v invald with err:%+v", e.Data, e.Err)
}

// Err about data has been expired
type ErrDataExpired struct {
	deadline    int64
	currentTime int64
}

func (e *ErrDataExpired) Error() string {
	return fmt.Sprintf("data expired at %d,now is %d", e.deadline, e.currentTime)
}
