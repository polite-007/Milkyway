package vulprotocol

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	_const "github.com/polite007/Milkyway/common/const"
	"github.com/polite007/Milkyway/common/proxy"
	"github.com/polite007/Milkyway/pkg/log"
	"github.com/polite007/Milkyway/pkg/utils"
	"net"
	"time"
)

func MysqlConn(ip string, port int, user, pass string) error {
	mysql.RegisterDialContext("socks", func(ctx context.Context, addr string) (net.Conn, error) {
		return proxy.WrapperTCP("tcp", addr, 5*time.Second)
	})

	Host, Port, Username, Password := ip, port, user, pass
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v", Username, Password, Host, Port, _const.PortScanTimeout)
	db, err := sql.Open("mysql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(_const.PortScanTimeout)
		db.SetConnMaxIdleTime(_const.PortScanTimeout)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[%s] %v:%v %v:%v\n", utils.Red("mysql"), Host, Port, utils.Red(Username), utils.Red(Password))
			log.OutLog(result)
		} else {
			return err
		}
	}
	return err
}

func MysqlScan(ip string, port int) {
	for _, user := range _const.UserMysql {
		for _, pass := range _const.PasswordMysql {
			if err := MysqlConn(ip, port, user, pass); err == nil {
				return
			}
		}
	}
}
