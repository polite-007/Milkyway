package config

type Dict struct {
	UserMysql     []string
	PasswordMysql []string

	PasswordRedis []string

	UserSsh     []string
	PasswordSsh []string

	PasswordVnc []string
}

var dict *Dict

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

var (
	userMysql     = []string{"root", "admin"}
	passwordMysql = []string{"", "root", "123456", "password", "qweasd", "QWE123qwe", "qweasdzxc", "123qwe", "123QWE"}

	passwordRedis = []string{"", "root", "123456", "password", "12345678", "redis", "QWE123qwe"}

	userSsh     = []string{"root", "myuser"}
	passwordSsh = []string{"", "root", "123456", "password", "12345678", "QWE123qwe", "mypassword", "123qwe", "123QWE"}

	passwordVnc = []string{"", "root", "123456", "password", "12345678", "QWE123qwe", "vnc", "123qwe", "123QWE"}
)
