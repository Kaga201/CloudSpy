/**
 * GeminiClient — calls Google Gemini with a pre-configured API key.
 * Routes through the CloudSpy backend when available (keeps API key server-side).
 * Falls back to direct Gemini call or Chrome background proxy when backend is offline.
 */
import { DEFAULT_GEMINI_API_KEY, GEMINI_MODELS } from '../core/gemini-config.js';
import { backendAPI } from '../core/BackendAPI.js';

const STORAGE_KEY = 'cloudspy_gemini_api_key';

export class GeminiClient {
  constructor() {
    this._cachedKey = null;
  }

  static get isExtension() {
    return typeof chrome !== 'undefined' && !!chrome.runtime?.id;
  }

  async getKey() {
    if (this._cachedKey) return this._cachedKey;

    if (GeminiClient.isExtension && chrome.storage?.local) {
      const data = await chrome.storage.local.get(STORAGE_KEY);
      this._cachedKey = data[STORAGE_KEY] || DEFAULT_GEMINI_API_KEY;
    } else {
      this._cachedKey = localStorage.getItem(STORAGE_KEY) || DEFAULT_GEMINI_API_KEY;
    }
    return this._cachedKey;
  }

  async hasKey() {
    const key = await this.getKey();
    return !!key?.trim();
  }

  async generate({ systemInstruction, history = [], userMessage }) {
    // Try backend proxy first (keeps API key server-side)
    try {
      const online = await backendAPI.isAvailable();
      if (online) {
        const result = await backendAPI.post('/api/v1/ai/chat', { userMessage, history });
        if (result.ok) return result.text;
        if (result.error) throw new Error(result.error);
      }
    } catch (err) {
      if (!String(err.message).includes('fetch') && !String(err.message).includes('Failed')) throw err;
      // Backend unreachable — fall through to direct call
    }

    const key = await this.getKey();
    if (!key) throw new Error('No Gemini API key available.');

    const payload = { key, systemInstruction, history, userMessage, models: GEMINI_MODELS };

    if (GeminiClient.isExtension) {
      return new Promise((resolve, reject) => {
        chrome.runtime.sendMessage({ type: 'GEMINI_GENERATE', payload }, resp => {
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          if (resp?.ok) resolve(resp.text);
          else reject(new Error(resp?.error || 'Gemini request failed'));
        });
      });
    }

    return this._fetchDirect(payload);
  }

  async _fetchDirect({ key, systemInstruction, history, userMessage, models }) {
    let lastError = null;

    for (const model of models) {
      try {
        return await this._callModel(model, key, systemInstruction, history, userMessage);
      } catch (err) {
        lastError = err;
        if (!String(err.message).includes('404') && !String(err.message).includes('429')) throw err;
      }
    }
    throw lastError || new Error('All Gemini models failed');
  }

  async _callModel(model, key, systemInstruction, history, userMessage) {
    const contents = [
      ...history.filter(h => !h.pending).map(h => ({
        role: h.role === 'assistant' ? 'model' : 'user',
        parts: [{ text: h.text }]
      })),
      { role: 'user', parts: [{ text: userMessage }] }
    ];

    const body = {
      contents,
      ...(systemInstruction ? { system_instruction: { parts: [{ text: systemInstruction }] } } : {})
    };

    const baseUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

    let resp = await fetch(baseUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-goog-api-key': key
      },
      body: JSON.stringify(body)
    });

    if (resp.status === 401 || resp.status === 403) {
      resp = await fetch(`${baseUrl}?key=${encodeURIComponent(key)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
    }

    if (!resp.ok) {
      const errText = await resp.text().catch(() => '');
      throw new Error(`Gemini ${model} failed (${resp.status}): ${errText.slice(0, 300)}`);
    }

    const data = await resp.json();
    const text = data?.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('').trim();
    if (!text) throw new Error('Gemini returned an empty response.');
    return text;
  }
}
