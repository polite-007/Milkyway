package config

// 内置协议爆破词典
var (
	userMysql     = []string{"root", "admin", "test"}
	passwordMysql = []string{"", "root", "123456", "password", "qweasd", "QWE123qwe", "qweasdzxc", "123qwe", "123QWE", "Admin123", "admin123"}

	passwordRedis = []string{"", "root", "123456", "password", "12345678", "redis", "QWE123qwe"}

	userSsh     = []string{"root", "myuser", "test"}
	passwordSsh = []string{"", "root", "123456", "password", "12345678", "QWE123qwe", "mypassword", "123qwe", "123QWE", "Admin123", "admin123"}

	passwordVnc = []string{"", "root", "123456", "password", "12345678", "QWE123qwe", "vnc", "123qwe", "123QWE", "Admin123", "admin123"}
)

// Dict 爆破词典结构体
type Dict struct {
	UserMysql     []string
	PasswordMysql []string

	PasswordRedis []string

	UserSsh     []string
	PasswordSsh []string

	PasswordVnc []string
}

var dict *Dict

// GetDict 获取爆破词典
func GetDict() *Dict {
	if dict != nil {
		return dict
	}
	dict = &Dict{
		UserMysql:     userMysql,
		PasswordMysql: passwordMysql,

		PasswordRedis: passwordRedis,

		UserSsh:     userSsh,
		PasswordSsh: passwordSsh,

		PasswordVnc: passwordVnc,
	}
	return dict
}
