const fetch = require('node-fetch');
const { GEMINI_API_KEY } = require('../config/env');

const MODELS = [
  'gemini-2.0-flash',
  'gemini-1.5-flash',
  'gemini-1.5-flash-latest',
  'gemini-pro',
];

const BASE_URL = 'https://generativelanguage.googleapis.com/v1beta/models';

async function generate({ systemInstruction, history = [], userMessage }) {
  if (!GEMINI_API_KEY) {
    return { ok: false, error: 'Gemini API key not configured on server' };
  }

  const contents = [
    ...history.map(m => ({
      role: m.role === 'assistant' ? 'model' : 'user',
      parts: [{ text: m.text || m.message }],
    })),
    { role: 'user', parts: [{ text: userMessage }] },
  ];

  const body = {
    contents,
    ...(systemInstruction && {
      system_instruction: { parts: [{ text: systemInstruction }] },
    }),
  };

  for (const model of MODELS) {
    try {
      const response = await fetch(`${BASE_URL}/${model}:generateContent?key=${GEMINI_API_KEY}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      if (!response.ok) continue;
      const data = await response.json();
      const text = data?.candidates?.[0]?.content?.parts?.[0]?.text;
      if (text) return { ok: true, text };
    } catch {
      // try next model
    }
  }

  return { ok: false, error: 'All Gemini models failed to respond' };
}

module.exports = { generate };
