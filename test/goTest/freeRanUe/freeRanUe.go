package freeRanUe

import (
	"context"
	"sync"

	loggerUtil "github.com/Alonza0314/logger-go/v2/util"
	"github.com/free-ran-ue/free-ran-ue/v2/logger"
	"github.com/free-ran-ue/free-ran-ue/v2/model"
	"github.com/free-ran-ue/free-ran-ue/v2/ue"
	"github.com/free-ran-ue/util"
)

const (
	UE_CONFIG_PATH = "/free-ran-ue/uecfg.yaml"
)

type FreeRanUe struct {
	isActivate bool
	ueConfig   model.UeConfig

	ctx    context.Context
	cancel context.CancelFunc

	wg *sync.WaitGroup

	ue *ue.Ue
}

func NewFreeRanUe() (*FreeRanUe, error) {
	ueConfig := model.UeConfig{}
	if err := util.LoadFromYaml(UE_CONFIG_PATH, &ueConfig); err != nil {
		return nil, err
	}
	if err := util.ValidateUe(&ueConfig); err != nil {
		return nil, err
	}

	logger := logger.NewUeLogger(loggerUtil.LogLevelString(ueConfig.Logger.Level), "", true)

	return &FreeRanUe{
		isActivate: false,
		ueConfig:   ueConfig,

		ctx:    nil,
		cancel: nil,

		wg: &sync.WaitGroup{},

		ue: ue.NewUe(&ueConfig, &logger),
	}, nil
}

func (fru *FreeRanUe) Activate() error {
	if fru.isActivate {
		return nil
	}

	fru.ctx, fru.cancel = context.WithCancel(context.Background())
	if err := fru.ue.Start(fru.ctx, fru.wg); err != nil {
		return err
	}

	fru.isActivate = true

	return nil
}

func (fru *FreeRanUe) Deactivate() error {
	if !fru.isActivate {
		return nil
	}

	fru.cancel()
	fru.wg.Wait()

	fru.ue.Stop()

	fru.isActivate = false

	return nil
}
