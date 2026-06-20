import { GEMINI_MODELS } from '../js/core/gemini-config.js';

export async function callGemini(payload) {
  const key = payload.key;
  const { systemInstruction, history, userMessage } = payload;
  const models = payload.models || GEMINI_MODELS;

  const contents = [
    ...(history || []).filter(h => !h.pending).map(h => ({
      role: h.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: h.text }]
    })),
    { role: 'user', parts: [{ text: userMessage }] }
  ];

  const body = {
    contents,
    ...(systemInstruction ? { system_instruction: { parts: [{ text: systemInstruction }] } } : {})
  };

  let lastError = null;

  for (const model of models) {
    try {
      const text = await requestModel(model, key, body);
      return text;
    } catch (err) {
      lastError = err;
      if (String(err.message).includes('404')) continue;
    }
  }

  throw lastError || new Error('All Gemini models failed');
}

async function requestModel(model, key, body) {
  const baseUrl = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`;

  // AQ auth keys: header only (do not mix Bearer + x-goog-api-key)
  let resp = await fetch(baseUrl, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-goog-api-key': key
    },
    body: JSON.stringify(body)
  });

  // Legacy AIza keys often work via query param
  if (resp.status === 401 || resp.status === 403) {
    resp = await fetch(`${baseUrl}?key=${encodeURIComponent(key)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
  }

  if (!resp.ok) {
    const errText = await resp.text().catch(() => '');
    throw new Error(`Gemini ${model} (${resp.status}): ${errText.slice(0, 300)}`);
  }

  const data = await resp.json();
  const text = data?.candidates?.[0]?.content?.parts?.map(p => p.text || '').join('').trim();
  if (!text) throw new Error('Empty Gemini response');
  return text;
}
