package bootstrap

import (
	libdb "github.com/anasamu/go-micro-libs/database"
	dbpg "github.com/anasamu/go-micro-libs/database/providers/postgresql"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

func InitPostgres(core *logrus.Logger, host string, port int, user, password, dbname, sslmode string, maxConns, minConns int) (*libdb.DatabaseManager, error) {
	dm := libdb.NewDatabaseManager(nil, core)
	prov := dbpg.NewProvider(core)
	if err := dm.RegisterProvider(prov); err != nil {
		return nil, err
	}
	if err := prov.Configure(map[string]interface{}{
		"host":            host,
		"port":            port,
		"user":            user,
		"password":        password,
		"database":        dbname,
		"ssl_mode":        sslmode,
		"max_connections": maxConns,
		"min_connections": minConns,
	}); err != nil {
		return nil, err
	}
	if err := dm.Connect(context.Background(), "postgresql"); err != nil {
		return nil, err
	}
	return dm, nil
}
