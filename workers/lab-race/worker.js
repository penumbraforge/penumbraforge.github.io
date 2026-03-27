/**
 * GiftRush — Vulnerable Gift Card Platform
 * Penumbra Forge Security Labs — RED-05
 *
 * INTENTIONALLY VULNERABLE: Gift card redemption endpoint has a
 * TOCTOU race condition. Balance is checked and deducted in
 * separate operations with no locking.
 */

const RATE_LIMIT = 100;          // max requests per window
const RATE_WINDOW = 3600000;     // 1 hour in ms
const rateBuckets = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  let bucket = rateBuckets.get(ip);

  if (!bucket || now - bucket.start > RATE_WINDOW) {
    bucket = { start: now, count: 0 };
    rateBuckets.set(ip, bucket);
  }

  bucket.count++;

  /* Cleanup old buckets periodically */
  if (rateBuckets.size > 10000) {
    for (const [k, v] of rateBuckets) {
      if (now - v.start > RATE_WINDOW) rateBuckets.delete(k);
    }
  }

  return bucket.count > RATE_LIMIT;
}

function rateLimitPage() {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rate Limited</title>
<style>
  body { background:#0d1117; color:#c9d1d9; font-family:'Courier New',monospace; display:flex; align-items:center; justify-content:center; min-height:100vh; margin:0; }
  .box { text-align:center; max-width:480px; padding:48px 32px; border:1px solid #30363d; border-radius:12px; background:#161b22; }
  h1 { font-size:20px; color:#f85149; margin-bottom:16px; }
  p { font-size:14px; line-height:1.7; color:#8b949e; }
</style></head>
<body><div class="box">
  <h1>Rate Limited</h1>
  <p>You've been rate limited. Labs allow 100 requests per hour per IP. Try again in a few minutes.</p>
</div></body></html>`;
}

// In-memory state per session (resets on Worker restart)
const sessions = new Map();

function getSession(id) {
  if (!sessions.has(id)) {
    sessions.set(id, {
      balance: 10000, // $100.00 in cents
      transactions: [],
      redeemed: false,
    });
  }
  return sessions.get(id);
}

const STYLES = `
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#fdf2f8; color:#1f2937; }

  .gr-promo { background:linear-gradient(90deg,#ec4899,#f472b6); color:#fff; padding:8px 12px; text-align:center; font-size:11px; font-weight:600; letter-spacing:0.3px; }

  .gr-header { background:#fff; border-bottom:1px solid #fce7f3; padding:0 16px; display:flex; align-items:center; justify-content:space-between; height:64px; position:sticky; top:0; z-index:100; box-shadow:0 1px 3px rgba(0,0,0,0.04); flex-wrap:nowrap; overflow:hidden; }
  .gr-header-left { display:flex; align-items:center; gap:12px; }
  .gr-logo { display:flex; align-items:center; gap:10px; text-decoration:none; }
  .gr-logo-icon { width:26px; height:26px; border-radius:8px; background:linear-gradient(135deg,#ec4899,#f472b6); display:flex; align-items:center; justify-content:center; }
  .gr-logo-icon svg { width:16px; height:16px; }
  .gr-logo-text { font-size:16px; font-weight:700; color:#831843; letter-spacing:-0.5px; }
  .gr-logo-text span { color:#ec4899; }
  .gr-nav { display:flex; gap:4px; }
  .gr-nav a { color:#6b7280; text-decoration:none; font-size:12px; font-weight:500; padding:6px 10px; border-radius:8px; transition:all 150ms; }
  .gr-nav a:hover { color:#831843; background:#fce7f3; }
  .gr-nav a.active { color:#ec4899; background:#fce7f3; }
  .gr-user { display:flex; align-items:center; gap:10px; font-size:12px; color:#6b7280; }
  .gr-user-avatar { width:28px; height:28px; border-radius:50%; background:#fce7f3; color:#ec4899; display:flex; align-items:center; justify-content:center; font-size:11px; font-weight:700; }

  .gr-container { max-width:100%; margin:0 auto; padding:16px 16px 0; }

  @media (max-width:500px) {
    .gr-nav { display:none; }
    .gr-user-avatar { display:none; }
  }

  .gr-card { background:#fff; border:1px solid #fce7f3; border-radius:12px; padding:24px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.04); }
  .gr-card h2 { font-size:17px; color:#831843; margin-bottom:4px; font-weight:600; }
  .gr-card h3 { font-size:13px; color:#6b7280; margin-bottom:16px; font-weight:400; }

  .gr-gift-card {
    background: linear-gradient(135deg, #ec4899, #f472b6, #fb7185);
    border-radius: 16px;
    padding: 32px;
    margin-bottom: 24px;
    position: relative;
    overflow: hidden;
    color: #fff;
    box-shadow: 0 8px 32px rgba(236,72,153,0.25);
  }
  .gr-gift-card::before {
    content: ''; position: absolute; top: -40%; right: -15%;
    width: 200px; height: 200px; border-radius: 50%;
    background: radial-gradient(circle, rgba(255,255,255,0.12), transparent);
  }
  .gr-gift-card::after {
    content: ''; position: absolute; bottom: -30%; left: -10%;
    width: 160px; height: 160px; border-radius: 50%;
    background: radial-gradient(circle, rgba(255,255,255,0.08), transparent);
  }
  .gr-gc-label { font-size:10px; text-transform:uppercase; letter-spacing:1.5px; margin-bottom:8px; opacity:0.8; }
  .gr-gc-code { font-family:monospace; font-size:18px; letter-spacing:3px; margin-bottom:20px; }
  .gr-gc-balance-label { font-size:11px; margin-bottom:4px; opacity:0.8; }
  .gr-gc-balance { font-size:40px; font-weight:700; position:relative; z-index:1; }
  .gr-gc-balance.zero { color:#fecdd3; }

  .gr-redeem { display:flex; gap:8px; align-items:center; flex-wrap:wrap; }
  .gr-redeem input { flex:1; min-width:160px; padding:12px 16px; background:#f9fafb; border:2px solid #fce7f3; border-radius:10px; color:#1f2937; font-size:15px; outline:none; font-family:monospace; transition:border-color 200ms,box-shadow 200ms; }
  .gr-redeem input:focus { border-color:#ec4899; box-shadow:0 0 0 3px rgba(236,72,153,0.15); background:#fff; }
  .gr-redeem button { padding:12px 24px; background:#ec4899; color:#fff; border:none; border-radius:10px; font-size:14px; font-weight:600; cursor:pointer; white-space:nowrap; transition:background 150ms; }
  .gr-redeem button:hover { background:#db2777; }

  .gr-race-btn { padding:12px 24px; background:#8b5cf6; color:#fff; border:none; border-radius:10px; font-size:14px; font-weight:600; cursor:pointer; white-space:nowrap; transition:background 150ms; }
  .gr-race-btn:hover { background:#7c3aed; }

  .gr-tx-table { width:100%; border-collapse:collapse; font-size:13px; }
  .gr-tx-table th { text-align:left; padding:10px 12px; color:#6b7280; font-weight:500; border-bottom:2px solid #fce7f3; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; }
  .gr-tx-table td { padding:10px 12px; border-bottom:1px solid #fdf2f8; }
  .gr-tx-neg { color:#ef4444; font-weight:600; }
  .gr-tx-pos { color:#059669; font-weight:600; }

  .gr-result { margin-top:12px; padding:14px 18px; border-radius:10px; font-size:13px; font-weight:500; }
  .gr-result-ok { background:#f0fdf4; border:1px solid #bbf7d0; color:#059669; }
  .gr-result-err { background:#fef2f2; border:1px solid #fecaca; color:#ef4444; }
  .gr-result-exploit { background:#f5f3ff; border:1px solid #ddd6fe; color:#8b5cf6; }

  .gr-race-log { margin-top:16px; font-family:monospace; font-size:11px; color:#6b7280; line-height:1.8; padding:16px; background:#f9fafb; border:1px solid #e5e7eb; border-radius:10px; white-space:pre-wrap; }

  .gr-browse { display:grid; grid-template-columns:repeat(auto-fill,minmax(180px,1fr)); gap:16px; margin-bottom:16px; }
  .gr-browse-card { background:#fdf2f8; border:1px solid #fce7f3; border-radius:12px; padding:20px; text-align:center; transition:all 200ms; cursor:pointer; }
  .gr-browse-card:hover { transform:translateY(-2px); box-shadow:0 6px 20px rgba(236,72,153,0.12); }
  .gr-browse-card-amount { font-size:22px; font-weight:700; color:#831843; margin-bottom:4px; }
  .gr-browse-card-label { font-size:12px; color:#6b7280; }

  .gr-footer { text-align:center; padding:16px 12px; color:#9ca3af; font-size:11px; border-top:1px solid #fce7f3; margin-top:48px; background:#fff; flex-wrap:wrap; }
`;

function renderApp(url, request) {
  const urlObj = new URL(url);
  const path = urlObj.pathname;
  const params = urlObj.searchParams;
  const sessionId = params.get('sid') || 'default';

  if (path === '/api/redeem') {
    return handleRedeem(sessionId, params, request);
  }
  if (path === '/api/reset') {
    sessions.delete(sessionId);
    return null; // redirect
  }
  if (path === '/api/balance') {
    const s = getSession(sessionId);
    return JSON.stringify({ balance: s.balance, transactions: s.transactions });
  }
  if (path === '/browse' || path === '/browse/') {
    return renderBrowse(sessionId);
  }
  if (path === '/history' || path === '/history/') {
    return renderHistory(sessionId);
  }

  return renderDashboard(sessionId);
}

function handleRedeem(sessionId, params, request) {
  const session = getSession(sessionId);
  const amount = parseInt(params.get('amount') || '0', 10);

  if (amount <= 0 || amount > 10000) {
    return JSON.stringify({ error: 'Invalid amount', balance: session.balance });
  }

  // ═══════════════════════════════════════════════════
  // INTENTIONALLY VULNERABLE — DO NOT FIX
  // Balance check and deduction are separate operations
  // with no mutex/locking. Concurrent requests can both
  // pass the balance check before either deducts.
  // ═══════════════════════════════════════════════════

  // Step 1: Check balance (TOCTOU — Time of Check)
  if (session.balance < amount) {
    return JSON.stringify({ error: 'Insufficient balance', balance: session.balance });
  }

  // Simulated processing delay — widens the race window
  // In a real app this would be a database query
  const now = Date.now();
  while (Date.now() - now < 50) {} // 50ms delay

  // Step 2: Deduct balance (TOCTOU — Time of Use)
  session.balance -= amount;
  session.transactions.push({
    time: new Date().toISOString().substring(11, 19),
    type: 'Redemption',
    amount: -amount,
    balance: session.balance,
  });

  const result = {
    success: true,
    redeemed: amount,
    balance: session.balance,
    doubleSpend: session.balance < 0,
  };

  return JSON.stringify(result);
}

function shell(title, activePage, sessionId, content) {
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — GiftRush</title><style>${STYLES}</style></head>
<body>
  <div class="gr-promo">GiftRush — Digital Gift Cards & Rewards Platform</div>
  <div class="gr-header">
    <div class="gr-header-left">
      <a href="/?sid=${sessionId}" class="gr-logo">
        <div class="gr-logo-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2"><rect x="3" y="8" width="18" height="14" rx="2"/><path d="M12 8V6a2 2 0 00-2-2H8a2 2 0 00-2 2v2"/><path d="M18 8V6a2 2 0 00-2-2h-2a2 2 0 00-2 2v2"/><line x1="12" y1="8" x2="12" y2="22"/></svg></div>
        <div class="gr-logo-text">Gift<span>Rush</span></div>
      </a>
      <div class="gr-nav">
        <a href="/?sid=${sessionId}"${activePage==='dashboard'?' class="active"':''}>Dashboard</a>
        <a href="/browse?sid=${sessionId}"${activePage==='browse'?' class="active"':''}>Browse Cards</a>
        <a href="/history?sid=${sessionId}"${activePage==='history'?' class="active"':''}>History</a>
        <a href="#"${activePage==='account'?' class="active"':''}>Account</a>
      </div>
    </div>
    <div class="gr-user">
      <span>alex@giftrush.com</span>
      <div class="gr-user-avatar">AX</div>
    </div>
  </div>
  <div class="gr-container">${content}</div>
  <div class="gr-footer">
    &copy; 2026 GiftRush Inc. — Digital Gift Card Services
    <div style="margin-top:4px;">All data is simulated. This is a Penumbra Forge Security Lab.</div>
  </div>
  <script>
  document.cookie="session=eyJ1c2VyIjoiYWxleEBnaWZ0cnVzaC5jb20iLCJiYWxhbmNlIjoiMTAwLjAwIn0=;path=/";

  /* ── Alert override ── */
  var _origAlert = window.alert;
  window.alert = function(msg) {
    try {
      window.parent.postMessage({ type: 'xss-fired', executed: true, payload: String(msg) }, '*');
    } catch(e) {}
  };

  /* ── Cookie access detection ── */
  (function() {
    var _origCookie = document.cookie;
    var _reported = false;
    Object.defineProperty(document, 'cookie', {
      get: function() {
        if (!_reported) {
          _reported = true;
          try {
            window.parent.postMessage({ type: 'cookie-accessed', value: _origCookie }, '*');
          } catch(e) {}
        }
        return _origCookie;
      },
      set: function(v) { /* allow sets but don't persist */ }
    });
  })();

  /* ── Navigation tracking ── */
  try {
    window.parent.postMessage({
      type: 'giftrush-nav',
      path: window.location.pathname,
      url: window.location.href
    }, '*');
  } catch(e) {}
  </script>
</body></html>`;
}

function renderDashboard(sessionId) {
  const session = getSession(sessionId);
  const balanceDollars = (session.balance / 100).toFixed(2);
  const isNegative = session.balance < 0;

  let txRows = '';
  if (session.transactions.length > 0) {
    session.transactions.forEach(function(tx) {
      const amtStr = (Math.abs(tx.amount) / 100).toFixed(2);
      const balStr = (tx.balance / 100).toFixed(2);
      txRows += `<tr><td>${tx.time}</td><td>${tx.type}</td><td class="${tx.amount < 0 ? 'gr-tx-neg' : 'gr-tx-pos'}">${tx.amount < 0 ? '-' : '+'}$${amtStr}</td><td>$${balStr}</td></tr>`;
    });
  } else {
    txRows = '<tr><td colspan="4" style="color:#6b7280;text-align:center;padding:24px;">No transactions yet</td></tr>';
  }

  return shell('Dashboard', 'dashboard', sessionId, `
    <div class="gr-gift-card">
      <div class="gr-gc-label">GiftRush Digital Gift Card</div>
      <div class="gr-gc-code">GIFT-7X9K-DELTA-MOON</div>
      <div class="gr-gc-balance-label">Available Balance</div>
      <div class="gr-gc-balance ${isNegative ? 'zero' : ''}" id="balance-display">$${balanceDollars}</div>
    </div>

    <div class="gr-card">
      <h2>Redeem Gift Card</h2>
      <h3>Enter amount to redeem (max $100.00)</h3>
      <div class="gr-redeem">
        <input type="number" id="redeem-amount" placeholder="Amount in dollars" step="0.01" min="0.01" max="100.00" value="100.00">
        <button id="btn-redeem" onclick="redeem()">Redeem</button>
        <button class="gr-race-btn" id="btn-race" onclick="raceRedeem()">Send 5x Concurrent</button>
      </div>
      <div id="redeem-result"></div>
      <div class="gr-race-log" id="race-log" style="display:none;"></div>
    </div>

    <div class="gr-card">
      <h2>Transaction History</h2>
      <table class="gr-tx-table">
        <thead><tr><th>Time</th><th>Type</th><th>Amount</th><th>Balance</th></tr></thead>
        <tbody id="tx-body">${txRows}</tbody>
      </table>
    </div>

    <div style="text-align:center;margin-top:16px;">
      <button style="font-family:monospace;font-size:12px;color:#6b7280;background:#f9fafb;border:1px solid #e5e7eb;padding:8px 18px;border-radius:8px;cursor:pointer;" onclick="fetch('/api/reset?sid=${sessionId}').then(function(){location.reload();});">Reset Balance to $100.00</button>
    </div>

    <script>
      var SID = '${sessionId}';

      function redeem() {
        var amount = Math.round(parseFloat(document.getElementById('redeem-amount').value) * 100);
        if (!amount || amount <= 0) return;

        fetch('/api/redeem?sid=' + SID + '&amount=' + amount)
          .then(function(r) { return r.json(); })
          .then(function(data) {
            var el = document.getElementById('redeem-result');
            if (data.error) {
              el.innerHTML = '<div class="gr-result gr-result-err">' + data.error + ' — Balance: $' + (data.balance / 100).toFixed(2) + '</div>';
            } else if (data.doubleSpend) {
              el.innerHTML = '<div class="gr-result gr-result-exploit">DOUBLE SPEND DETECTED — Balance went negative: $' + (data.balance / 100).toFixed(2) + '</div>';
              window.parent.postMessage({ type: 'race-result', doubleSpend: true, balance: data.balance }, '*');
            } else {
              el.innerHTML = '<div class="gr-result gr-result-ok">Redeemed $' + (data.redeemed / 100).toFixed(2) + ' — Remaining: $' + (data.balance / 100).toFixed(2) + '</div>';
            }
            document.getElementById('balance-display').textContent = '$' + (data.balance / 100).toFixed(2);
            if (data.balance < 0) document.getElementById('balance-display').classList.add('zero');
            refreshTransactions();
          });
      }

      function raceRedeem() {
        var amount = Math.round(parseFloat(document.getElementById('redeem-amount').value) * 100);
        if (!amount || amount <= 0) return;

        var log = document.getElementById('race-log');
        log.style.display = '';
        log.textContent = 'Sending 5 concurrent redemption requests for $' + (amount/100).toFixed(2) + '...\\n';

        var promises = [];
        for (var i = 0; i < 5; i++) {
          promises.push(
            fetch('/api/redeem?sid=' + SID + '&amount=' + amount)
              .then(function(r) { return r.json(); })
          );
        }

        Promise.all(promises).then(function(results) {
          var successCount = 0;
          var totalRedeemed = 0;
          var finalBalance = 0;
          var doubleSpend = false;

          results.forEach(function(r, i) {
            if (r.success) {
              successCount++;
              totalRedeemed += r.redeemed;
              finalBalance = r.balance;
              if (r.doubleSpend) doubleSpend = true;
              log.textContent += 'Request ' + (i+1) + ': SUCCESS — redeemed $' + (r.redeemed/100).toFixed(2) + ', balance: $' + (r.balance/100).toFixed(2) + '\\n';
            } else {
              log.textContent += 'Request ' + (i+1) + ': REJECTED — ' + r.error + '\\n';
            }
          });

          log.textContent += '\\n---------------------------------------\\n';
          log.textContent += 'Results: ' + successCount + '/5 succeeded\\n';
          log.textContent += 'Total redeemed: $' + (totalRedeemed/100).toFixed(2) + '\\n';
          log.textContent += 'Final balance: $' + (finalBalance/100).toFixed(2) + '\\n';

          if (doubleSpend || successCount > 1) {
            log.textContent += '\\nRACE CONDITION EXPLOITED — Multiple requests passed the balance check simultaneously';
            document.getElementById('redeem-result').innerHTML = '<div class="gr-result gr-result-exploit">RACE CONDITION — ' + successCount + ' of 5 requests succeeded. $' + (totalRedeemed/100).toFixed(2) + ' redeemed from a $' + (amount/100).toFixed(2) + ' balance.</div>';
            window.parent.postMessage({ type: 'race-result', doubleSpend: true, successCount: successCount, balance: finalBalance }, '*');
          }

          document.getElementById('balance-display').textContent = '$' + (finalBalance/100).toFixed(2);
          if (finalBalance < 0) document.getElementById('balance-display').classList.add('zero');
          refreshTransactions();
        });
      }

      function refreshTransactions() {
        fetch('/api/balance?sid=' + SID)
          .then(function(r) { return r.json(); })
          .then(function(data) {
            var tbody = document.getElementById('tx-body');
            if (data.transactions.length === 0) return;
            var html = '';
            data.transactions.forEach(function(tx) {
              var amt = (Math.abs(tx.amount)/100).toFixed(2);
              var bal = (tx.balance/100).toFixed(2);
              html += '<tr><td>' + tx.time + '</td><td>' + tx.type + '</td><td class="' + (tx.amount<0?'gr-tx-neg':'gr-tx-pos') + '">' + (tx.amount<0?'-':'+') + '$' + amt + '</td><td>$' + bal + '</td></tr>';
            });
            tbody.innerHTML = html;
          });
      }
    </script>
  `);
}

function renderBrowse(sessionId) {
  return shell('Browse Cards', 'browse', sessionId, `
    <div class="gr-card">
      <h2>Browse Gift Cards</h2>
      <h3>Choose a gift card design and amount</h3>
      <div class="gr-browse">
        <div class="gr-browse-card">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ec4899" stroke-width="1.5" style="margin-bottom:8px;"><rect x="3" y="8" width="18" height="14" rx="2"/><path d="M12 8V6a2 2 0 00-2-2H8a2 2 0 00-2 2v2"/><path d="M18 8V6a2 2 0 00-2-2h-2a2 2 0 00-2 2v2"/></svg>
          <div class="gr-browse-card-amount">$25</div>
          <div class="gr-browse-card-label">Birthday Celebration</div>
        </div>
        <div class="gr-browse-card">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ec4899" stroke-width="1.5" style="margin-bottom:8px;"><path d="M20.84 4.61a5.5 5.5 0 00-7.78 0L12 5.67l-1.06-1.06a5.5 5.5 0 00-7.78 7.78l1.06 1.06L12 21.23l7.78-7.78 1.06-1.06a5.5 5.5 0 000-7.78z"/></svg>
          <div class="gr-browse-card-amount">$50</div>
          <div class="gr-browse-card-label">Thank You</div>
        </div>
        <div class="gr-browse-card">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ec4899" stroke-width="1.5" style="margin-bottom:8px;"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
          <div class="gr-browse-card-amount">$100</div>
          <div class="gr-browse-card-label">Premium Rewards</div>
        </div>
        <div class="gr-browse-card">
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="#ec4899" stroke-width="1.5" style="margin-bottom:8px;"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg>
          <div class="gr-browse-card-amount">$200</div>
          <div class="gr-browse-card-label">Special Occasion</div>
        </div>
      </div>
    </div>
  `);
}

function renderHistory(sessionId) {
  const session = getSession(sessionId);
  let txRows = '';
  if (session.transactions.length > 0) {
    session.transactions.forEach(function(tx) {
      const amtStr = (Math.abs(tx.amount) / 100).toFixed(2);
      const balStr = (tx.balance / 100).toFixed(2);
      txRows += `<tr><td>${tx.time}</td><td>${tx.type}</td><td class="${tx.amount < 0 ? 'gr-tx-neg' : 'gr-tx-pos'}">${tx.amount < 0 ? '-' : '+'}$${amtStr}</td><td>$${balStr}</td></tr>`;
    });
  } else {
    txRows = '<tr><td colspan="4" style="color:#6b7280;text-align:center;padding:24px;">No transactions yet</td></tr>';
  }

  return shell('Transaction History', 'history', sessionId, `
    <div class="gr-card">
      <h2>Full Transaction History</h2>
      <h3>All redemptions and purchases for your account</h3>
      <table class="gr-tx-table">
        <thead><tr><th>Time</th><th>Type</th><th>Amount</th><th>Balance</th></tr></thead>
        <tbody>${txRows}</tbody>
      </table>
    </div>
  `);
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    /* ── Rate limiting ── */
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (isRateLimited(ip)) {
      return new Response(rateLimitPage(), {
        status: 429,
        headers: { 'Content-Type': 'text/html; charset=UTF-8', ...corsHeaders },
      });
    }

    /* ── Validation endpoint ── */
    if (url.pathname === '/api/validate' && request.method === 'POST') {
      try {
        const body = await request.json();
        if (body.type === 'race-check') {
          const sessionId = body.sessionId || 'default';
          const session = getSession(sessionId);
          const balance = session.balance;
          const txCount = session.transactions.length;
          const doubleSpend = balance < 0;
          const multipleRedemptions = txCount > 1;

          return new Response(JSON.stringify({
            doubleSpend,
            balance,
            transactionCount: txCount,
            multipleRedemptions,
            exploited: doubleSpend || multipleRedemptions,
          }), {
            status: 200,
            headers: { 'Content-Type': 'application/json', ...corsHeaders },
          });
        }
        return new Response(JSON.stringify({ error: 'Invalid request type' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      } catch (e) {
        return new Response(JSON.stringify({ error: 'Invalid JSON' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json', ...corsHeaders },
        });
      }
    }

    // API endpoints return JSON
    if (url.pathname.startsWith('/api/')) {
      const result = renderApp(request.url, request);
      if (result === null) {
        // Reset — redirect to dashboard
        return new Response(null, { status: 302, headers: { 'Location': '/?sid=' + (url.searchParams.get('sid') || 'default'), ...corsHeaders } });
      }
      return new Response(result, {
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }

    const html = renderApp(request.url, request);
    return new Response(html, {
      status: 200,
      headers: {
        'Content-Type': 'text/html; charset=UTF-8',
        'X-Powered-By': 'Express',
        'X-XSS-Protection': '0',
        ...corsHeaders,
      },
    });
  },
};
