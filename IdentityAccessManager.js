export class IdentityAccessManager {
  constructor(store) {
    this.store = store;
  }

  enforceMfa(userId) {
    const user = this.store.get().users.find(u => u.id === userId);
    if (user && !user.mfa) {
      user.mfa = true;
      return user;
    }
    return null;
  }

  enableMfaGlobally() {
    this.store.get().users.forEach(u => { if (!u.mfa) u.mfa = true; });
  }

  constrainContractors() {
    this.store.get().users.filter(u => u.role === 'contractor').forEach(u => { u.mfa = true; });
  }

  trackLogin(user) {
    user.lastLogin = Date.now();
    user.logins24h++;
    return user;
  }

  getStats() {
    const users = this.store.get().users;
    return {
      total: users.length,
      mfaOk: users.filter(u => u.mfa).length,
      mfaMissing: users.filter(u => !u.mfa).length
    };
  }

  getWeakCount() {
    return this.store.get().users.filter(u => !u.mfa).length;
  }
}
