package test

import (
	"io"
	"testing"

	nasIE "github.com/free5gc/nas/ie"
	nas "github.com/free5gc/nas/message"
	ngapIE "github.com/free5gc/ngap/ie"
	ngap "github.com/free5gc/ngap/message"
	"github.com/free5gc/openapi/models"
	"github.com/stretchr/testify/require"
)

// An SCTP read returns one NGAP message, even when two messages are queued.
type registrationFrames struct {
	incoming [][]byte
	outgoing [][]byte
}

func (f *registrationFrames) Read(buf []byte) (int, error) {
	if len(f.incoming) == 0 {
		return 0, io.EOF
	}
	frame := f.incoming[0]
	f.incoming = f.incoming[1:]
	return copy(buf, frame), nil
}

func (f *registrationFrames) Write(buf []byte) (int, error) {
	f.outgoing = append(f.outgoing, append([]byte(nil), buf...))
	return len(buf), nil
}

func TestRegistrationCompleteExchange(t *testing.T) {
	for _, tc := range []struct {
		name      string
		messages  []string
		wantAcks  int
		wantError bool
	}{
		{"normal", []string{"update"}, 1, false},
		{"queued duplicate", []string{"duplicate", "update"}, 1, false},
		{"fresh retransmission", []string{"fresh accept", "update"}, 2, false},
		{"missing update", []string{"duplicate"}, 1, true},
		{"other UE", []string{"wrong UE"}, 1, true},
		{"unexpected NAS", []string{"wrong NAS"}, 1, true},
		{"persistent duplicate", []string{"duplicate", "duplicate", "duplicate", "duplicate", "duplicate", "update"}, 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ue := NewRanUeContext(UE_IMSI, 1, nas.AlgCiphering128NEA0, nas.AlgIntegrity128NIA2, models.AccessType_3_GPP_ACCESS)
			ue.AmfUeNgapId = 1
			core := nas.NewSecCtx(nas.CoreNetworkSide, ue.GetBearerType(), ue.CipheringAlg, ue.IntegrityAlg, ue.KnasEnc[:], ue.KnasInt[:])
			accept := &nas.RegAccept{RegResult5GS: &nasIE.RegResult5GS{Value: 1}}
			encode := func(msg nas.Message) []byte {
				b, err := nas.Marshal(msg, core, nas.SecHdrTypeIntegrityProtectedAndCiphered)
				require.NoError(t, err)
				return b
			}
			first := encode(accept)
			_, err := nas.Parse(first, ue.NewSecCtx())
			require.NoError(t, err)
			frames := &registrationFrames{}
			for _, name := range tc.messages {
				id := ue.RanUeNgapId
				var b []byte
				switch name {
				case "duplicate":
					b = first
				case "fresh accept":
					b = encode(accept)
				case "wrong NAS":
					b = encode(&nas.RegComplete{})
				case "wrong UE", "update":
					b = encode(&nas.CfgUpdateCmd{})
					if name == "wrong UE" {
						id++
					}
				}
				frame, err := (&ngap.DownlinkNASTransport{
					AMFUENGAPID: &ngapIE.AMFUENGAPID{Value: ue.AmfUeNgapId},
					RANUENGAPID: &ngapIE.RANUENGAPID{Value: id},
					NASPDU:      &ngapIE.NASPDU{Value: b},
				}).MarshalBinary()
				require.NoError(t, err)
				frames.incoming = append(frames.incoming, frame)
			}
			err = completeRegistration(frames, ue, first)
			if tc.wantError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			require.Len(t, frames.outgoing, tc.wantAcks)
			for _, ack := range frames.outgoing {
				msg, err := ngap.Parse(ack)
				require.NoError(t, err)
				uplink := msg.(*ngap.UplinkNASTransport)
				complete, err := nas.Parse(uplink.NASPDU.Value, core)
				require.NoError(t, err)
				require.IsType(t, (*nas.RegComplete)(nil), complete)
			}
		})
	}
}
