import { BACKEND_URL } from './gemini-config.js';

const TOKEN_KEY = 'cloudspy_backend_token';

class BackendAPI {
  constructor() {
    this._token = null;
    this._available = null;
  }

  get _isExtension() {
    return typeof chrome !== 'undefined' && !!chrome.runtime?.id;
  }

  async _getToken() {
    if (this._token) return this._token;
    if (this._isExtension && chrome.storage?.local) {
      const data = await chrome.storage.local.get(TOKEN_KEY);
      if (data[TOKEN_KEY]) { this._token = data[TOKEN_KEY]; return this._token; }
    } else {
      const stored = localStorage.getItem(TOKEN_KEY);
      if (stored) { this._token = stored; return this._token; }
    }
    return null;
  }

  async _saveToken(token) {
    this._token = token;
    if (this._isExtension && chrome.storage?.local) {
      await chrome.storage.local.set({ [TOKEN_KEY]: token });
    } else {
      localStorage.setItem(TOKEN_KEY, token);
    }
  }

  // All HTTP calls go through the background service worker when in extension context
  async _request(path, method = 'GET', body = undefined) {
    const token = await this._getToken();
    const url = `${BACKEND_URL}${path}`;

    if (this._isExtension) {
      return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage(
          { type: 'BACKEND_FETCH', payload: { url, method, body, token } },
          resp => {
            if (chrome.runtime.lastError) return reject(new Error(chrome.runtime.lastError.message));
            if (!resp) return reject(new Error('No response from service worker'));
            if (!resp.ok && resp.error && !resp.data?.error) {
              resp.data = { error: resp.error };
            }
            resolve(resp);
          }
        );
      });
    }

    // Non-extension fallback (web console / dev)
    const headers = { 'Content-Type': 'application/json' };
    if (token) headers['Authorization'] = `Bearer ${token}`;
    const r = await fetch(url, { method, headers, body: body ? JSON.stringify(body) : undefined });
    const data = await r.json().catch(() => ({}));
    return { ok: r.ok, status: r.status, data };
  }

  async login(email, password) {
    const result = await this._request('/api/v1/auth/login', 'POST', { email, password });
    if (!result.ok) {
      const msg = result.data?.error || result.error || 'Login failed';
      throw new Error(msg.includes('Failed to fetch') ? 'Backend is not running. Start backend with npm run dev first.' : msg);
    }
    await this._saveToken(result.data.token);
    return result.data;
  }

  async clearToken() {
    this._token = null;
    if (this._isExtension && chrome.storage?.local) {
      await chrome.storage.local.remove(TOKEN_KEY);
    } else {
      localStorage.removeItem(TOKEN_KEY);
    }
  }

  async isAvailable() {
    if (this._available !== null) return this._available;
    try {
      const result = await this._request('/health');
      this._available = result.ok;
    } catch {
      this._available = false;
    }
    return this._available;
  }

  async get(path) {
    const result = await this._request(path, 'GET');
    if (!result.ok) throw new Error(`GET ${path} failed: ${result.status}`);
    return result.data;
  }

  async post(path, body) {
    const result = await this._request(path, 'POST', body);
    if (!result.ok) throw new Error(`POST ${path} failed: ${result.status}`);
    return result.data;
  }

  async patch(path, body) {
    const result = await this._request(path, 'PATCH', body);
    if (!result.ok) throw new Error(`PATCH ${path} failed: ${result.status}`);
    return result.data;
  }
}

export const backendAPI = new BackendAPI();
