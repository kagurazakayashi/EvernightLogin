// 扫码登录：服务端节奏轮询、倒计时与过期处理；页面卸载/过期时停止计时器，
// 不无限补发请求，不引入任何在线资源。
export function mount(root, context) {
  let stopped = false;
  let pollTimer = 0;
  let countdownTimer = 0;

  // 倒计时：显示剩余秒数；归零后标记过期、禁用轮询并在页面提示重新生成。
  if (root.hasAttribute && root.hasAttribute("data-ln-deadline")) {
    const deadline = Number(root.getAttribute("data-ln-deadline") || "0");
    const remaining = root.querySelector("[data-ln-countdown]");
    const expired = root.querySelector("[data-ln-expired]");
    const tick = () => {
      if (stopped) return;
      const left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
      if (remaining) remaining.textContent = String(left) + "s";
      if (left <= 0) {
        if (remaining) remaining.hidden = true;
        if (expired) expired.hidden = false;
        for (const form of document.querySelectorAll("form[data-ln-module='qr-poll'], form[data-ln-module='qr-claim']")) {
          for (const button of form.querySelectorAll("button[type=submit]")) {
            button.disabled = true;
            button.setAttribute("aria-disabled", "true");
          }
        }
        return;
      }
      countdownTimer = window.setTimeout(tick, 1000);
    };
    tick();
    return () => { stopped = true; if (countdownTimer) window.clearTimeout(countdownTimer); };
  }

  const form = root.tagName === "FORM" ? root : root.querySelector("form[data-ln-module='qr-poll']");
  const claim = root.querySelector("form[data-ln-module='qr-claim']");
  if (form) {
    const interval = Math.max(2, Number(root.getAttribute("data-ln-interval") || "5"));
    const schedule = () => {
      if (stopped) return;
      pollTimer = window.setTimeout(() => {
        if (stopped) return;
        const deadlineElement = document.querySelector("[data-ln-deadline]");
        if (deadlineElement) {
          const deadline = Number(deadlineElement.getAttribute("data-ln-deadline") || "0");
          if (deadline > 0 && Date.now() >= deadline) return;
        }
        form.submit();
      }, interval * 1000);
    };
    schedule();
  }
  if (claim) {
    window.setTimeout(() => { if (!stopped) claim.submit(); }, 200);
  }
  return () => { stopped = true; if (pollTimer) window.clearTimeout(pollTimer); };
}
