package model

import "testing"

func TestPacketValidate(t *testing.T) {
	tests := []struct {
		name    string
		packet  Packet
		wantErr bool
	}{
		{
			name: "tcp 报文合法",
			packet: Packet{
				Protocol: "tcp",
				SrcIP:    "1.1.1.1",
				DstIP:    "2.2.2.2",
				SrcPort:  1000,
				DstPort:  80,
			},
		},
		{
			name: "协议非法",
			packet: Packet{
				Protocol: "http",
				SrcIP:    "1.1.1.1",
				DstIP:    "2.2.2.2",
			},
			wantErr: true,
		},
		{
			name: "tcp 缺失目标端口",
			packet: Packet{
				Protocol: "tcp",
				SrcIP:    "1.1.1.1",
				DstIP:    "2.2.2.2",
				SrcPort:  1000,
			},
			wantErr: true,
		},
		{
			name: "ip 非法",
			packet: Packet{
				Protocol: "udp",
				SrcIP:    "bad-ip",
				DstIP:    "2.2.2.2",
				SrcPort:  53,
				DstPort:  53,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.packet.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("wantErr=%v, got err=%v", tt.wantErr, err)
			}
		})
	}
}
