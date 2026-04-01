const db = require('../lib/db');
const { createDashboardApp } = require('../web/dashboard');

let initPromise = null;
let app = null;

async function ensureReady() {
  if (!initPromise) {
    initPromise = db.init().catch((err) => {
      initPromise = null;
      throw err;
    });
  }
  await initPromise;
  if (!app) {
    app = createDashboardApp(null);
  }
  return app;
}

module.exports = async (req, res) => {
  try {
    const readyApp = await ensureReady();
    return readyApp(req, res);
  } catch (err) {
    console.error('vercel dashboard bootstrap error:', err);
    res.statusCode = 500;
    res.setHeader('Content-Type', 'application/json; charset=utf-8');
    res.end(JSON.stringify({ error: 'dashboard_bootstrap_failed' }));
  }
};
