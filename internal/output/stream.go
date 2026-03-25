package output

import (
	"encoding/json"
	"fmt"
	"time"

	"iptrace/pkg/model"
)

func RenderStepHuman(step model.TraceStep) string {
	ts := time.Now().Format("15:04:05.000")
	return fmt.Sprintf("[%s] %s\t%s\t%s\trule %d\t%s", ts, step.HookPoint, step.Table, step.Chain, step.RuleNumber, step.Action)
}

func RenderStepNDJSON(step model.TraceStep) (string, error) {
	data, err := json.Marshal(step)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
