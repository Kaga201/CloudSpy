export class CostAnalyzer {
  constructor(store) {
    this.store = store;
  }

  _vmCost(v) {
    return v.cost ?? v.costMonthly ?? 0;
  }

  _vmIdle(v) {
    return v.idle ?? v.isIdle ?? false;
  }

  _vmOversized(v) {
    return v.oversized ?? v.isOversized ?? false;
  }

  computeWaste() {
    return this.store.get().vms.reduce((sum, v) => {
      let waste = 0;
      const cost = this._vmCost(v);
      if (this._vmIdle(v)) waste += cost * 0.85;
      if (this._vmOversized(v)) waste += cost * 0.4;
      return sum + waste;
    }, 0);
  }

  getMonthlySpend() {
    return this.store.get().vms.reduce((s, v) => s + this._vmCost(v), 0);
  }

  rightSizeVms() {
    let saved = 0;
    this.store.get().vms.forEach(v => {
      if (this._vmOversized(v)) {
        const cost = this._vmCost(v);
        saved += Math.round(cost * 0.4);
        v.oversized = false;
        v.isOversized = false;
        v.cost = Math.round(cost * 0.6);
        v.costMonthly = v.cost;
        v.kwh = Math.round((v.kwh || v.kwhMonthly || 0) * 0.65);
        v.kwhMonthly = v.kwh;
      }
    });
    return saved;
  }

  getResourceAnalysis(vm) {
    let issue = 'Healthy';
    let savings = 0;
    const cost = this._vmCost(vm);
    if (this._vmIdle(vm)) { issue = 'Idle resource'; savings += Math.round(cost * 0.85); }
    if (this._vmOversized(vm)) { issue = 'Oversized VM'; savings += Math.round(cost * 0.4); }
    return { issue, savings };
  }
}
