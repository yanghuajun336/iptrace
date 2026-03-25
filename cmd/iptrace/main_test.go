package main

import "testing"

func TestRunArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		code int
	}{
		{name: "无参数", args: []string{}, code: 1},
		{name: "未知子命令", args: []string{"unknown"}, code: 1},
		{name: "check 子命令（缺少参数）", args: []string{"check"}, code: 1},
		{name: "trace 子命令（非 root）", args: []string{"trace"}, code: 2},
		{name: "export 子命令（缺少参数）", args: []string{"export"}, code: 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := runArgs(tt.args); got != tt.code {
				t.Fatalf("expected exit code %d, got %d", tt.code, got)
			}
		})
	}
}
