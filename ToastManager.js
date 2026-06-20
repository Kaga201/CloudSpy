export class ToastManager {
  constructor(containerId = 'toast-container') {
    this.container = document.getElementById(containerId);
  }

  show(msg, type = 'success') {
    if (!this.container) return;
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    el.textContent = msg;
    this.container.appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 300);
    }, 4000);
  }
}
