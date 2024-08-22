package login

// 步骤 215：公共生命周期/扩展/授权契约的根包兼容桥。
//
// 唯一实现位于可导入公共包 extension/access/lifecycle/version；根包只保留
// 类型别名、常量别名与薄函数，确保既有 login.* 公共 API 不破坏。
// 不得在本文件添加第二套实现或内部类型。

import (
	"github.com/kagurazakayashi/EvernightLogin/access"
	"github.com/kagurazakayashi/EvernightLogin/extension"
	"github.com/kagurazakayashi/EvernightLogin/lifecycle"
	buildversion "github.com/kagurazakayashi/EvernightLogin/version"
)

// ===== extension =====

type Extension = extension.Extension
type ExtensionKind = extension.ExtensionKind
type ExtensionInfo = extension.ExtensionInfo

const (
	MaxExtensions                = extension.MaxExtensions
	DefaultExtensionStartTimeout = extension.DefaultExtensionStartTimeout
	MinExtensionStartTimeout     = extension.MinExtensionStartTimeout
	MaxExtensionStartTimeout     = extension.MaxExtensionStartTimeout
	ExtensionStartCancelWait     = extension.ExtensionStartCancelWait
	MaxExtensionNameLength       = extension.MaxExtensionNameLength
	MaxExtensionVersionLength    = extension.MaxExtensionVersionLength
	ExtensionKindComponent       = extension.ExtensionKindComponent
	ExtensionKindStorage         = extension.ExtensionKindStorage
	ExtensionKindNotification    = extension.ExtensionKindNotification
	ExtensionKindAuthentication  = extension.ExtensionKindAuthentication
	ExtensionKindMFA             = extension.ExtensionKindMFA
	ExtensionKindPage            = extension.ExtensionKindPage
)

// ===== access =====

type Permission = access.Permission
type PermissionScope = access.PermissionScope
type AccessRequest = access.AccessRequest
type AccessDecision = access.AccessDecision
type AccessController = access.AccessController
type AccessControllerFunc = access.AccessControllerFunc

const (
	MaxPermissionLength        = access.MaxPermissionLength
	MaxResourceIDLength        = access.MaxResourceIDLength
	PermissionScopeSystem      = access.PermissionScopeSystem
	PermissionScopeApplication = access.PermissionScopeApplication
)

// ===== lifecycle =====

type State = lifecycle.State
type Options = lifecycle.Options
type BackgroundComponent = lifecycle.BackgroundComponent
type Database = lifecycle.Database
type DatabaseFunc = lifecycle.DatabaseFunc
type Notifier = lifecycle.Notifier
type NotifierFunc = lifecycle.NotifierFunc
type ReadyChecker = lifecycle.ReadyChecker
type LifecycleEventKind = lifecycle.LifecycleEventKind
type LifecycleEvent = lifecycle.LifecycleEvent
type Runner = lifecycle.Runner
type Factory = lifecycle.Factory

const (
	StateNew             = lifecycle.StateNew
	StateRunning         = lifecycle.StateRunning
	StateClosed          = lifecycle.StateClosed
	LifecycleStarted     = lifecycle.LifecycleStarted
	LifecycleStartFailed = lifecycle.LifecycleStartFailed
	LifecycleClosed      = lifecycle.LifecycleClosed
	LifecycleCloseFailed = lifecycle.LifecycleCloseFailed
)

// ===== version =====

type BuildInfo = buildversion.BuildInfo
