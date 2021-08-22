// 一次展示秘密的复制增强：不自动复制、不在模块内持久保存秘密；无 JavaScript
// 时用户仍可手动选择并复制服务端渲染的文本。
export function mount(root) {
  const button = root.querySelector("[data-ln-secret-copy]");
  const secretElement = root.querySelector(".ln-secret");
  const status = root.querySelector("[data-ln-secret-status]");
  if (!button || !secretElement) return () => {};
  if (typeof navigator === "undefined" || !navigator.clipboard ||
      typeof navigator.clipboard.writeText !== "function") {
    return () => {};
  }
  // 只有真实可用的剪贴板能力才显示按钮，避免无后端支持的假控件。
  button.hidden = false;
  const announce = (message) => {
    if (status) status.textContent = message;
  };
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(secretElement.textContent || "");
      announce(button.getAttribute("data-ln-copied") || "已复制");
    } catch (error) {
      announce(button.getAttribute("data-ln-copy-failed") || "无法写入剪贴板，请手动选择并复制");
    }
  };
  // 离开页面或前进/后退缓存恢复前清理秘密 DOM，避免再次显示。
  const clear = () => { secretElement.textContent = ""; };
  const onPageHide = () => { clear(); };
  button.addEventListener("click", copy);
  window.addEventListener("pagehide", onPageHide);
  return () => {
    button.removeEventListener("click", copy);
    window.removeEventListener("pagehide", onPageHide);
  };
}
