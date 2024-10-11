package setupconsole

// WS3 测试辅助：内存维护日志替身（真实 MaintLog 由 WS1 实现；测试只验证调用与
// 记录次序，不伪装生产写盘）。

import (
	"context"
	"sync"
)

type fakeMaintLog struct {
	mu      sync.Mutex
	entries []MaintLogEntry
}

func (f *fakeMaintLog) Record(_ context.Context, entry MaintLogEntry) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.entries = append(f.entries, entry)
	return entry.OperationID, nil
}

func (f *fakeMaintLog) snapshot() []MaintLogEntry {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]MaintLogEntry(nil), f.entries...)
}

// newFakeMaintRecorder 构造维护日志替身记录器；identity 字段仅满足录制路径。
func newFakeMaintRecorder() (*ws3MaintRecorder, *fakeMaintLog) {
	log := &fakeMaintLog{}
	return &ws3MaintRecorder{log: log,
		identity: MaintenanceIdentity{Kind: "local_os", OSUser: "tester",
			Machine: "test", InstanceID: "fake"},
		instanceDir: "."}, log
}
