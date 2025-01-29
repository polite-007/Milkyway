package protocol_vul

import (
	"context"
	"database/sql"
	"fmt"
	"github.com/go-sql-driver/mysql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/polite007/Milkyway/config"
	"github.com/polite007/Milkyway/internal/service/connx"
	"github.com/polite007/Milkyway/internal/utils/color"
	"github.com/polite007/Milkyway/pkg/logger"
	"net"
	"time"
)

func mysqlConn(ip string, port int, user, pass string) error {
	mysql.RegisterDialContext("socks", func(ctx context.Context, addr string) (net.Conn, error) {
		return connx.WrapperTCP("tcp", addr, 5*time.Second)
	})

	Host, Port, Username, Password := ip, port, user, pass
	dataSourceName := fmt.Sprintf("%v:%v@tcp(%v:%v)/mysql?charset=utf8&timeout=%v", Username, Password, Host, Port, config.PortScanTimeout)
	db, err := sql.Open("mysql", dataSourceName)
	if err == nil {
		db.SetConnMaxLifetime(config.PortScanTimeout)
		db.SetConnMaxIdleTime(config.PortScanTimeout)
		db.SetMaxIdleConns(0)
		defer db.Close()
		err = db.Ping()
		if err == nil {
			result := fmt.Sprintf("[%s] %v:%v %v:%v\n", color.Red("mysql"), Host, Port, color.Red(Username), color.Red(Password))
			logger.OutLog(result)
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
