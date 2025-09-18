package bootstrap

import (
	micro "github.com/anasamu/go-micro-libs"
	cfgfile "github.com/anasamu/go-micro-libs/config/providers/file"
	cfgtypes "github.com/anasamu/go-micro-libs/config/types"
)

func LoadConfig(configPath string) (*micro.ConfigManager, *cfgtypes.Config, error) {
	cfgMgr := micro.NewConfigManager()
	prov := cfgfile.NewProvider(configPath, "yaml")
	cfgMgr.RegisterProvider("file", prov)
	if err := cfgMgr.SetCurrentProvider("file"); err != nil {
		return nil, nil, err
	}
	cfg, err := cfgMgr.Load()
	if err != nil {
		return nil, nil, err
	}
	return cfgMgr, cfg, nil
}
