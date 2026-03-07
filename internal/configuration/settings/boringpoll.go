package settings

import (
	"github.com/qdm12/gosettings"
	"github.com/qdm12/gosettings/reader"
	"github.com/qdm12/gotree"
)

type BoringPoll struct {
	GluetunCom *bool
}

func (b BoringPoll) validate() error {
	return nil
}

func (b BoringPoll) Copy() BoringPoll {
	return BoringPoll{
		GluetunCom: gosettings.CopyPointer(b.GluetunCom),
	}
}

func (b *BoringPoll) overrideWith(other BoringPoll) {
	b.GluetunCom = gosettings.OverrideWithPointer(b.GluetunCom, other.GluetunCom)
}

func (b *BoringPoll) setDefaults() {
	b.GluetunCom = gosettings.DefaultPointer(b.GluetunCom, false)
}

func (b BoringPoll) String() string {
	return b.toLinesNode().String()
}

func (b BoringPoll) toLinesNode() *gotree.Node {
	if !*b.GluetunCom {
		return nil
	}

	node := gotree.New("Boring-poll settings:")
	node.Append("gluetun.com: on")
	return node
}

func (b *BoringPoll) read(r *reader.Reader) (err error) {
	b.GluetunCom, err = r.BoolPtr("BORINGPOLL_GLUETUNCOM")
	if err != nil {
		return err
	}
	return nil
}
