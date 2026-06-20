/** Pre-configured Gemini API key — chatbot works out of the box. */
export const DEFAULT_GEMINI_API_KEY = 'AQ.Ab8RN6J5ejaCzO4KBcicCXsbtMzpa0XO3B2n--veIfZWXFi85w';

/** Backend API base URL — AI calls are routed through this to keep the Gemini key server-side. */
export const BACKEND_URL = 'http://127.0.0.1:3000';

export const GEMINI_MODELS = [
  'gemini-2.0-flash',
  'gemini-1.5-flash',
  'gemini-1.5-flash-latest',
  'gemini-pro'
];
