package config

import "errors"

// 错误列表
var (
	Errors                *ErrorsList
	errAssertion          = errors.New("工人函数断言错误")
	errTargetEmpty        = errors.New("目标为空")
	errTaskFailed         = errors.New("任务执行失败")
	errPortocolScanFailed = errors.New("全协议扫描失败")
	errPortNotProtocol    = errors.New("端口号没有对应的协议")
)

// ErrorsList 错误列表结构体
type ErrorsList struct {
	ErrAssertion          error
	ErrTargetEmpty        error
	ErrTaskFailed         error
	ErrPortocolScanFailed error
	ErrPortNotProtocol    error
}

// GetErrors 获取错误列表
func GetErrors() *ErrorsList {
	if Errors != nil {
		return Errors
	}
	Errors = &ErrorsList{
		ErrAssertion:          errAssertion,
		ErrTargetEmpty:        errTargetEmpty,
		ErrTaskFailed:         errTaskFailed,
		ErrPortocolScanFailed: errPortocolScanFailed,
		ErrPortNotProtocol:    errPortNotProtocol,
	}
	return Errors
}
