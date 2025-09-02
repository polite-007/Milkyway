package protocol_vul

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"time"

	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/pkg/proxy"
	"github.com/polite007/Milkyway/pkg/color"
	"github.com/polite007/Milkyway/pkg/logger"
)

func mysqlConn(ip string, port int, user, pass string) error {
	mysql.RegisterDialContext("socks", func(ctx context.Context, addr string) (net.Conn, error) {
		return proxy.WrapperTCP("tcp", addr, 5*time.Second)
	})

	Host, Port, Username, Password := ip, port, user, pass
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v", Username, Password, Host, Port, config.Get().PortScanTimeout)
	db, err := sql.Open("mysql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(config.Get().PortScanTimeout)
		db.SetConnMaxIdleTime(config.Get().PortScanTimeout)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[%s] %v:%v %v:%v\n", color.Red("mysql"), Host, Port, color.Red(Username), color.Red(Password))
			logger.OutLog(result)
			config.Get().Result.AddProtocolVul(Host, port, "mysql", fmt.Sprintf("%v:%v", Username, Password))
		} else {
			return err
		}
	}
	return err
}

func mysqlScan(ip string, port int) {
	for _, user := range config.GetDict().UserMysql {
		for _, pass := range config.GetDict().PasswordMysql {
			if err := mysqlConn(ip, port, user, pass); err == nil {
				return
			}
		}
	}
}
