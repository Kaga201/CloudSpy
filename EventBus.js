export class EventBus {
  constructor() {
    this._handlers = new Map();
  }

  on(event, handler) {
    if (!this._handlers.has(event)) this._handlers.set(event, new Set());
    this._handlers.get(event).add(handler);
    return () => this._handlers.get(event)?.delete(handler);
  }

  emit(event, payload) {
    this._handlers.get(event)?.forEach(fn => fn(payload));
  }
}

export const Events = {
  STATE_CHANGED: 'state:changed',
  LOG: 'log',
  TOAST: 'toast',
  RISK_EVENT: 'risk:event',
  RENDER_ALL: 'ui:render-all',
  RENDER_PARTIAL: 'ui:render-partial'
};
