// 本文件定义宿主注册扩展的公开契约（步骤 88）。扩展用于把宿主拥有的基础设施
// 或业务适配能力接入 login.Instance，由实例统一管理启动与关闭：
//
//   - 扩展对象由宿主构造，但一旦通过 Options.Extensions 注册就由实例管理启动与
//     关闭；同一个扩展对象不得同时注册到多个实例。
//   - 启动顺序为「扩展声明顺序 → 后台组件声明顺序」，关闭为整体逆序（先关闭
//     后台组件，再逆序关闭扩展）。任一扩展或组件启动失败时，实例回滚关闭已成功
//     启动的全部扩展与组件并进入 StateClosed，不会留下半启动状态。
//   - 扩展只释放自己创建的资源。宿主传入实例或扩展的数据库连接、HTTP 服务器、
//     日志器、密钥文件句柄、页面资源等由宿主关闭，扩展不得关闭；实例也不会关闭
//     宿主注入的 Database/Notifier/AccessController。
//   - 认证（ExtensionKindAuthentication）与第二因素（ExtensionKindMFA）属于安全
//     敏感扩展：任何启动或健康检查失败都必须视为整体不可用（fail-closed），不会
//     退化为「跳过认证」或「关闭鉴权」。本包不提供伪造 root、跳过授权或关闭鉴权
//     的公开选项，也不提供把请求参数直接提升为可信身份的入口。
//   - 多实例共享状态与集群协调尚未实现（本步只保留扩展分类与文档契约，不提前
//     实现集群）；同一进程内多个 Instance 不共享任何扩展、配置或全局单例。
package extension

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/kagurazakayashi/EvernightLogin/correlation"
)

// MaxExtensions 是单个 Instance 允许注册的扩展数量上限。上限用于约束启动/关闭
// 时间与诊断输出，避免宿主误注册过多对象。
const MaxExtensions = 32

// DefaultExtensionStartTimeout 是单个扩展 Start 的默认墙钟上限；可通过
// Options.ExtensionStartTimeout 在允许范围内调整。超时的扩展按启动失败处理。
const DefaultExtensionStartTimeout = 30 * time.Second

// MinExtensionStartTimeout / MaxExtensionStartTimeout 是
// Options.ExtensionStartTimeout 的允许范围。
const (
	MinExtensionStartTimeout = 100 * time.Millisecond
	MaxExtensionStartTimeout = 10 * time.Minute
)

// ExtensionStartCancelWait 是启动取消或扩展启动超时后，Instance 额外等待扩展
// 协程自行返回（完成自清理）的墙钟上限；实际等待为
// min(Options.ExtensionStartTimeout, ExtensionStartCancelWait)。超过该窗口仍未
// 返回的扩展会被标记为「可能遗留资源」，Instance 不会永久阻塞。
const ExtensionStartCancelWait = 2 * time.Second

// MaxExtensionNameLength / MaxExtensionVersionLength 是扩展元数据字段的长度上限。
const (
	MaxExtensionNameLength    = 64
	MaxExtensionVersionLength = 64
)

// ExtensionKind 是扩展点的稳定分类，决定扩展在实例装配与失败策略中的角色。
type ExtensionKind string

const (
	// ExtensionKindComponent 是通用后台组件类扩展（调度循环、后台消费者等）。
	ExtensionKindComponent ExtensionKind = "component"
	// ExtensionKindStorage 是存储/持久化适配类扩展（数据库方言、仓储实现等）。
	ExtensionKindStorage ExtensionKind = "storage"
	// ExtensionKindNotification 是通知投递类扩展（邮件、Webhook、站内通知等）。
	ExtensionKindNotification ExtensionKind = "notification"
	// ExtensionKindAuthentication 是认证类扩展（外部 IdP、定制口令校验等）。
	// 属于安全敏感扩展。
	ExtensionKindAuthentication ExtensionKind = "authentication"
	// ExtensionKindMFA 是第二因素/强认证类扩展（TOTP、Passkey 以外的补充因素
	// 或宿主自建强认证等）。属于安全敏感扩展。
	ExtensionKindMFA ExtensionKind = "mfa"
	// ExtensionKindPage 是页面/前端资源类扩展（自定义页面渲染或资源来源）。
	ExtensionKindPage ExtensionKind = "page"
)

// Valid 报告扩展分类是否已定义。
func (k ExtensionKind) Valid() bool {
	switch k {
	case ExtensionKindComponent, ExtensionKindStorage, ExtensionKindNotification,
		ExtensionKindAuthentication, ExtensionKindMFA, ExtensionKindPage:
		return true
	default:
		return false
	}
}

// SecuritySensitive 报告该分类的扩展失败时是否必须整体 fail-closed。认证与第二
// 因素扩展失败时不能降级为「跳过认证」或「关闭鉴权」，因此返回 true。
func (k ExtensionKind) SecuritySensitive() bool {
	return k == ExtensionKindAuthentication || k == ExtensionKindMFA
}

// ExtensionInfo 是扩展的公开元数据，用于注册校验、诊断输出与生命周期通知。
// 它不包含任何秘密或宿主内部标识。
type ExtensionInfo struct {
	// Name 是同类扩展内的稳定名称，只允许 ASCII 字母、数字、点、下划线与连字符，
	// 最长 MaxExtensionNameLength；同类内不得重名。
	Name string
	// Version 是宿主声明的扩展版本，只用于诊断与兼容判断，不参与授权。安全敏感
	// 扩展（认证/第二因素）必须显式声明非空版本，避免无法追溯的鉴权组件。
	Version string
	// Kind 是扩展分类，必须是已定义的 ExtensionKind。
	Kind ExtensionKind
}

// Validate 校验扩展元数据：分类已定义、名称合法且同类内可唯一识别、安全敏感
// 扩展必须显式声明版本。它只做结构校验，不代表扩展已经可用或可信。
func (i ExtensionInfo) Validate() error {
	if !i.Kind.Valid() {
		return fmt.Errorf("扩展分类未定义: %q", string(i.Kind))
	}
	if i.Name == "" {
		return fmt.Errorf("扩展名称不能为空")
	}
	if len(i.Name) > MaxExtensionNameLength {
		return fmt.Errorf("扩展名称长度不能超过 %d 个字符", MaxExtensionNameLength)
	}
	if err := correlation.Validate("扩展名称", i.Name); err != nil {
		return err
	}
	if i.Version != "" {
		if len(i.Version) > MaxExtensionVersionLength {
			return fmt.Errorf("扩展版本长度不能超过 %d 个字符", MaxExtensionVersionLength)
		}
		for index := 0; index < len(i.Version); index++ {
			character := i.Version[index]
			if character < 0x21 || character > 0x7e ||
				strings.ContainsRune(`/?#%\`, rune(character)) {
				return fmt.Errorf("扩展版本只能包含可见 ASCII 字符，且不能包含 /、?、#、%% 或反斜杠")
			}
		}
	}
	if i.Kind.SecuritySensitive() && i.Version == "" {
		return fmt.Errorf("安全敏感扩展（%s）必须声明非空版本", string(i.Kind))
	}
	return nil
}

// key 返回注册去重键：分类 + 名称。
func (i ExtensionInfo) key() string {
	return string(i.Kind) + "/" + i.Name
}

// Extension 是宿主注册到 login.Instance 的扩展契约。
//
// 生命周期约定与 BackgroundComponent 一致：Start 按注册顺序调用；返回错误表示
// 启动失败，实现必须在返回错误前清理自己已创建的资源，实例不会对启动失败的
// 扩展调用 Close。Close 按启动顺序的逆序调用，只对成功启动过的扩展各调用一次，
// 必须响应 ctx 取消且不得在取消后继续阻塞。
//
// ExtensionInfo 会在注册时被校验并复制保存，因此实现必须返回稳定元数据，不能
// 随请求变化，也不能把请求参数当作扩展身份。
type Extension interface {
	// ExtensionInfo 返回扩展的公开元数据；实例注册时校验并复制该值。
	ExtensionInfo() ExtensionInfo
	// Start 启动扩展。失败时必须自行清理已创建资源。
	Start(ctx context.Context) error
	// Close 停止扩展并释放扩展自己创建的资源，不得关闭宿主拥有的资源。
	Close(ctx context.Context) error
}
