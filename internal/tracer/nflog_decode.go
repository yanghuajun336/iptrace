package tracer

import (
	"fmt"
	"strconv"
	"strings"

	"iptrace/pkg/model"
)

func DecodeMockEvent(line string) (model.TraceStep, error) {
	fields := strings.Fields(line)
	kv := map[string]string{}
	for _, f := range fields {
		parts := strings.SplitN(f, "=", 2)
		if len(parts) != 2 {
			continue
		}
		kv[parts[0]] = parts[1]
	}

	ruleNum := 0
	if kv["rule"] != "" {
		n, err := strconv.Atoi(kv["rule"])
		if err != nil {
			return model.TraceStep{}, fmt.Errorf("invalid rule number: %w", err)
		}
		ruleNum = n
	}

	return model.TraceStep{
		HookPoint:  kv["hook"],
		Table:      kv["table"],
		Chain:      kv["chain"],
		RuleNumber: ruleNum,
		Action:     kv["action"],
	}, nil
}
