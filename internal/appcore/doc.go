// Package appcore 是公开 app 包依赖的内部基础设施装配层（步骤 138 / Phase B 起步）。
//
// 当前范围：配置覆盖后的数据库打开、迁移门禁、主密钥环加载与安全审计构造。
// 它不监听端口、不读 CLI、不启动后台任务；不得反向导入 internal/serverapp、
// cmd/** 或公开 app 包（由 imports_test 守卫）。后续可将 serverapp 的完整构建
// 函数继续迁移到本包，serverapp 只保留 serve/init/锁/维护生命周期。
package appcore
