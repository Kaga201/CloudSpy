import { CloudSpyApp } from './CloudSpyApp.js';

const app = new CloudSpyApp();
window.cloudSpy = app;

document.addEventListener('DOMContentLoaded', () => app.start());
