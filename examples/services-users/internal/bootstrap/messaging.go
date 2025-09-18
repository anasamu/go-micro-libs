package bootstrap

import (
	micro "github.com/anasamu/go-micro-libs"
	msgkafka "github.com/anasamu/go-micro-libs/messaging/providers/kafka"
	"github.com/sirupsen/logrus"
	"golang.org/x/net/context"
)

func InitMessaging(core *logrus.Logger, brokers []string, groupID string) (*micro.MessagingManager, error) {
	mm := micro.NewMessagingManager(nil, core)
	prov := msgkafka.NewProvider(core)
	if err := mm.RegisterProvider(prov); err != nil {
		return nil, err
	}
	if err := prov.Configure(map[string]interface{}{
		"brokers":  brokers,
		"group_id": groupID,
	}); err != nil {
		return nil, err
	}
	if err := mm.Connect(context.Background(), "kafka"); err != nil {
		return nil, err
	}
	return mm, nil
}
