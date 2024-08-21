// 二次确认增强：使用原生 dialog 语义；无 JavaScript 时由独立确认页承担。
export function mount(root, context) {
  const dialog = root.querySelector("dialog");
  if (!dialog || typeof dialog.showModal !== "function") return () => {};
  const trigger = root.querySelector("[data-ln-confirm-trigger]");
  const cancel = root.querySelector("[data-ln-confirm-cancel]");
  const open = () => dialog.showModal();
  const close = () => dialog.close();
  if (trigger) trigger.addEventListener("click", open);
  if (cancel) cancel.addEventListener("click", close);
  root.addEventListener("close", () => { if (trigger) trigger.focus(); });
  return () => {
    if (trigger) trigger.removeEventListener("click", open);
    if (cancel) cancel.removeEventListener("click", close);
  };
}
