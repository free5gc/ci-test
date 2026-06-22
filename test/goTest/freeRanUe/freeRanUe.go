package freeRanUe

import (
	"os"
	"os/exec"
)

type FreeRanUe struct {
	done     chan bool
	isActive bool
	cmd      *exec.Cmd
}

func NewFreeRanUe() *FreeRanUe {
	return &FreeRanUe{
		done:     make(chan bool),
		isActive: false,
	}
}

func (fru *FreeRanUe) Activate() {
	if fru.isActive {
		return
	}

	fru.done = make(chan bool)
	fru.isActive = true

	go func() {
		fru.cmd = exec.Command("/free-ran-ue/free-ran-ue", "ue", "-c", "/free-ran-ue/uecfg.yaml")

		go fru.cmd.Run()

		<-fru.done

		if fru.cmd != nil && fru.cmd.Process != nil {
			fru.cmd.Process.Kill()
		}
		exec.Command("pkill", "free-ran-ue").Run()
		fru.isActive = false
	}()
}

func (fru *FreeRanUe) Deactivate() {
	if !fru.isActive {
		return
	}

	go func() { fru.done <- true }()

	if fru.cmd != nil && fru.cmd.Process != nil {
		fru.cmd.Process.Signal(os.Interrupt)
		fru.cmd.Wait()
	}
	exec.Command("pkill", "free-ran-ue").Run()
	fru.isActive = false
}

func (fru *FreeRanUe) IsActive() bool {
	return fru.isActive
}
