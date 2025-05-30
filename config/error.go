package config

import "errors"

// ErrorsList 错误列表结构体
type ErrorsList struct {
	ErrAssertion          error
	ErrTargetEmpty        error
	ErrTaskFailed         error
	ErrPortocolScanFailed error
	ErrPortNotProtocol    error
}

// 错误列表
var (
	errorsList            *ErrorsList
	errAssertion          = errors.New("工人函数断言错误")
	errTargetEmpty        = errors.New("目标为空")
	errTaskFailed         = errors.New("任务执行失败")
	errPortocolScanFailed = errors.New("全协议扫描失败")
	errPortNotProtocol    = errors.New("端口号没有对应的协议")
)

// GetErrors 获取错误列表
func GetErrors() *ErrorsList {
	if errorsList != nil {
		return errorsList
	}
	errorsList = &ErrorsList{
		ErrAssertion:          errAssertion,
		ErrTargetEmpty:        errTargetEmpty,
		ErrTaskFailed:         errTaskFailed,
		ErrPortocolScanFailed: errPortocolScanFailed,
		ErrPortNotProtocol:    errPortNotProtocol,
	}
	return errorsList
}
