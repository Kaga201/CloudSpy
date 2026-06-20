import { fmtTime } from '../core/utils.js';
import { GeminiClient } from './GeminiClient.js';

export class AIEngine {
  constructor(store, modules) {
    this.store = store;
    this.modules = modules;
    this.gemini = new GeminiClient();
  }

  /** Full exchange — adds user + assistant messages to history. */
  async chat(userMessage) {
    const s = this.store.get();
    s.chatHistory.push({
      role: 'user',
      text: userMessage,
      time: fmtTime()
    });
    const response = await this.completeReply(userMessage);
    s.chatHistory.push(response);
    if (s.chatHistory.length > 40) s.chatHistory.splice(0, s.chatHistory.length - 40);
    return response;
  }

  /** Assistant reply only (user message already in history). */
  async completeReply(userMessage) {
    const text = (userMessage || '').trim().toLowerCase();
    const s = this.store.get();
    let reply;
    let usedGemini = false;

    try {
      reply = await this._generateGeminiReply(userMessage, s);
      usedGemini = true;
    } catch (err) {
      console.warn('[CloudSpy] Gemini call failed, using local reply:', err.message);
      reply = this._generateReply(text, s);
    }

    return {
      role: 'assistant',
      text: reply,
      time: fmtTime(),
      source: usedGemini ? 'gemini' : 'local'
    };
  }

  async seedWelcome(onProgress) {
    const s = this.store.get();
    if (s.chatHistory?.length) return;

    s.chatHistory.push({
      role: 'assistant',
      text: 'Connecting to Gemini…',
      time: fmtTime(),
      pending: true
    });
    onProgress?.();

    try {
      const welcome = await this._generateGeminiReply(
        'Introduce yourself in one friendly sentence as CloudSpy AI, a cloud security assistant for this browser extension.',
        s
      );
      s.chatHistory = [{
        role: 'assistant',
        text: welcome,
        time: fmtTime(),
        source: 'gemini'
      }];
    } catch {
      s.chatHistory = [{
        role: 'assistant',
        text: this._generateReply('hello', s),
        time: fmtTime(),
        source: 'local'
      }];
    }
    onProgress?.();
  }

  async _generateGeminiReply(userMessage, s) {
    const threats = s.threatSurfaces.filter(t => t.status !== 'compliant').length;
    const files = s.scannedFiles || [];
    const badFiles = files.filter(f => f.verdict !== 'safe');
    const anomalies = this.modules.anomaly.getRecent(5);
    const iamStats = this.modules.iam.getStats();

    const systemInstruction = `You are CloudSpy AI, the in-app security assistant for a cloud security browser extension.
Answer the user's question helpfully and concisely (2-5 sentences unless a list is clearer), using the live telemetry below when relevant. Do not invent data that isn't given to you.

Current telemetry snapshot:
- Risk score: ${s.riskScore}/100
- Active threat surfaces: ${threats}
- Files scanned: ${files.length} (${badFiles.length} flagged as suspicious/malicious)
- Recent anomalies: ${anomalies.map(a => `[${a.severity}] ${a.detail}`).join('; ') || 'none'}
- IAM: ${iamStats.total} users, ${iamStats.mfaOk} with MFA, ${iamStats.mfaMissing} missing MFA`;

    const recentHistory = (s.chatHistory || []).filter(m => !m.pending).slice(-10);

    return this.gemini.generate({
      systemInstruction,
      history: recentHistory,
      userMessage
    });
  }

  _generateReply(text, s) {
    const threats = s.threatSurfaces.filter(t => t.status !== 'compliant').length;
    const files = s.scannedFiles || [];
    const badFiles = files.filter(f => f.verdict !== 'safe');
    const anomalies = this.modules.anomaly.getRecent(5);

    if (/help|command|what can/.test(text)) {
      return 'I can help with: "scan files", "show threats", "anomalies", "risk score", "malicious files", "onedrive", "recommendations". Ask me about your current security posture.';
    }
    if (/scan.*file|file.*scan|scan files/.test(text)) {
      const n = files.length;
      const bad = badFiles.length;
      return n
        ? `Scanned ${n} file(s) on the current page. ${bad} flagged as suspicious or malicious. Open the File Threat Scanner table for details, or click Scan All Files.`
        : 'No files detected yet. Browse a page with downloads (OneDrive, Google Drive, etc.) then click Scan All Files or Execute Scan.';
    }
    if (/malicious|virus|dangerous file/.test(text)) {
      if (!badFiles.length) return 'No malicious files detected in the current scan. Browse a test page with downloads to scan.';
      return `Found ${badFiles.length} risky file(s):\n${badFiles.slice(0, 5).map(f => `• ${f.name} — ${f.verdict} (${f.threats[0]?.message || 'threat'})`).join('\n')}`;
    }
    if (/onedrive|sharepoint|google drive|dropbox|cloud/.test(text)) {
      const cloud = files.filter(f => f.cloudProvider);
      return cloud.length
        ? `Detected ${cloud.length} cloud-hosted file link(s): ${cloud.map(f => f.name + ' (' + f.cloudProvider + ')').join(', ')}. I scan each for double extensions, executables, and type spoofing.`
        : 'No cloud file links found yet. Open OneDrive or Google Drive in a tab — CloudSpy auto-detects file links on the page.';
    }
    if (/anomal|behavio|unusual/.test(text)) {
      if (!anomalies.length) return 'No anomalies recorded yet. The engine monitors off-hours activity, MFA gaps, and file threat clusters continuously.';
      return `Recent anomalies:\n${anomalies.map(a => `• [${a.severity}] ${a.detail}`).join('\n')}`;
    }
    if (/risk|score/.test(text)) {
      return `Current AI risk score: ${s.riskScore}/100. ${this.modules.riskEngine.getBehaviorProfile()}`;
    }
    if (/threat|finding|issue|vulnerabil/.test(text)) {
      return threats
        ? `${threats} active threat surface(s). ${badFiles.length} file threat(s). Top issue: ${s.threatSurfaces.find(t => t.status === 'critical')?.impact || 'Review Threat Scanner module.'}`
        : 'Environment looks stable. No critical threat surfaces detected.';
    }
    if (/recommend|fix|suggest/.test(text)) {
      const recs = s.recommendations.filter(r => !r.applied);
      return recs.length
        ? `Top recommendations:\n${recs.slice(0, 3).map(r => `• ${r.title}`).join('\n')}\nApply them from the sidebar panel.`
        : 'All recommendations have been applied. Environment is optimized.';
    }
    if (/mfa|login|identity/.test(text)) {
      const stats = this.modules.iam.getStats();
      return `IAM status: ${stats.total} users, ${stats.mfaOk} with MFA, ${stats.mfaMissing} missing MFA. ${stats.mfaMissing ? 'Recommend enforcing MFA immediately.' : 'Identity posture is strong.'}`;
    }
    if (/hello|hi|hey/.test(text)) {
      return `Hello! I'm CloudSpy AI. Risk score is ${s.riskScore}/100 with ${files.length} files scanned. How can I help secure your cloud environment?`;
    }

    return `Based on current telemetry: risk ${s.riskScore}/100, ${threats} threats, ${badFiles.length} risky files, ${s.anomaliesDetected} anomaly signals. Try asking "scan files", "show anomalies", or "malicious files".`;
  }

  runAnalysis() {
    return this.modules.anomaly.analyzeState();
  }
}
