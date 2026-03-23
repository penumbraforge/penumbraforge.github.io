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
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#1a1510; color:#d4c8b0; }

  .gr-header { background:linear-gradient(135deg,#231c12,#2e2418); border-bottom:1px solid #3d3020; padding:14px 32px; display:flex; align-items:center; justify-content:space-between; }
  .gr-logo { font-size:20px; font-weight:700; color:#e8b84d; letter-spacing:-0.5px; text-decoration:none; }
  .gr-logo span { color:#8a7a5a; font-weight:300; }
  .gr-nav { display:flex; gap:20px; }
  .gr-nav a { color:#8a7a5a; text-decoration:none; font-size:13px; }
  .gr-nav a:hover { color:#d4c8b0; }
  .gr-nav a.active { color:#e8b84d; }

  .gr-container { max-width:900px; margin:0 auto; padding:32px; }

  .gr-card { background:#231c12; border:1px solid #3d3020; border-radius:10px; padding:24px; margin-bottom:20px; }
  .gr-card h2 { font-size:16px; color:#d4c8b0; margin-bottom:4px; font-weight:500; }
  .gr-card h3 { font-size:13px; color:#8a7a5a; margin-bottom:16px; font-weight:400; }

  .gr-gift-card {
    background: linear-gradient(135deg, #2e2418, #3d3020);
    border: 1px solid #4d4030;
    border-radius: 16px;
    padding: 32px;
    margin-bottom: 20px;
    position: relative;
    overflow: hidden;
  }
  .gr-gift-card::before {
    content: ''; position: absolute; top: -50%; right: -20%;
    width: 200px; height: 200px; border-radius: 50%;
    background: radial-gradient(circle, rgba(232,184,77,0.08), transparent);
  }
  .gr-gc-label { font-size:10px; color:#8a7a5a; text-transform:uppercase; letter-spacing:1px; margin-bottom:8px; }
  .gr-gc-code { font-family:monospace; font-size:18px; color:#e8b84d; letter-spacing:2px; margin-bottom:16px; }
  .gr-gc-balance-label { font-size:11px; color:#8a7a5a; margin-bottom:4px; }
  .gr-gc-balance { font-size:36px; color:#d4c8b0; font-weight:300; }
  .gr-gc-balance.zero { color:#f85149; }

  .gr-redeem { display:flex; gap:8px; align-items:center; }
  .gr-redeem input { flex:1; padding:10px 14px; background:#1a1510; border:1px solid #3d3020; border-radius:8px; color:#d4c8b0; font-size:14px; outline:none; font-family:monospace; }
  .gr-redeem input:focus { border-color:#e8b84d; }
  .gr-redeem button { padding:10px 20px; background:#b8860b; color:#fff; border:none; border-radius:8px; font-size:13px; font-weight:500; cursor:pointer; white-space:nowrap; }
  .gr-redeem button:hover { background:#d4a017; }

  .gr-race-btn { padding:10px 20px; background:#7c3aed; color:#fff; border:none; border-radius:8px; font-size:13px; font-weight:500; cursor:pointer; margin-left:8px; }
  .gr-race-btn:hover { background:#6d28d9; }

  .gr-tx-table { width:100%; border-collapse:collapse; font-size:13px; }
  .gr-tx-table th { text-align:left; padding:10px 12px; color:#8a7a5a; font-weight:400; border-bottom:1px solid #3d3020; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; }
  .gr-tx-table td { padding:10px 12px; border-bottom:1px solid #2e2418; }
  .gr-tx-neg { color:#f85149; }
  .gr-tx-pos { color:#3fb950; }

  .gr-result { margin-top:12px; padding:12px 16px; border-radius:8px; font-size:13px; }
  .gr-result-ok { background:rgba(63,185,80,0.08); border:1px solid rgba(63,185,80,0.15); color:#3fb950; }
  .gr-result-err { background:rgba(248,81,73,0.08); border:1px solid rgba(248,81,73,0.15); color:#f85149; }
  .gr-result-exploit { background:rgba(124,58,237,0.08); border:1px solid rgba(124,58,237,0.15); color:#a78bfa; }

  .gr-race-log { margin-top:16px; font-family:monospace; font-size:11px; color:#8a7a5a; line-height:1.8; padding:12px; background:#1a1510; border:1px solid #3d3020; border-radius:8px; white-space:pre-wrap; }

  .gr-footer { text-align:center; padding:32px; color:#3d3020; font-size:11px; border-top:1px solid #3d3020; margin-top:48px; }

  .gr-promo { background:linear-gradient(90deg,#b8860b,#d4a017); color:#1a1510; padding:10px 24px; text-align:center; font-size:12px; font-weight:600; }
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

  return renderDashboard(sessionId);
}

function handleRedeem(sessionId, params, request) {
  const session = getSession(sessionId);
  const amount = parseInt(params.get('amount') || '0', 10);

  if (amount <= 0 || amount > 10000) {
    return JSON.stringify({ error: 'Invalid amount', balance: session.balance });
  }

  // ═══════════════════════════════════════════════════
  // ⚠ INTENTIONALLY VULNERABLE — DO NOT FIX
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

function renderDashboard(sessionId) {
  const session = getSession(sessionId);
  const balanceDollars = (session.balance / 100).toFixed(2);
  const isNegative = session.balance < 0;

  let txRows = '';
  if (session.transactions.length > 0) {
    session.transactions.forEach(function(tx) {
      const amtStr = (tx.amount / 100).toFixed(2);
      const balStr = (tx.balance / 100).toFixed(2);
      txRows += `<tr><td>${tx.time}</td><td>${tx.type}</td><td class="${tx.amount < 0 ? 'gr-tx-neg' : 'gr-tx-pos'}">${tx.amount < 0 ? '-' : '+'}$${Math.abs(tx.amount / 100).toFixed(2)}</td><td>$${balStr}</td></tr>`;
    });
  } else {
    txRows = '<tr><td colspan="4" style="color:#8a7a5a;text-align:center;padding:20px;">No transactions yet</td></tr>';
  }

  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>GiftRush — Dashboard</title><style>${STYLES}</style></head>
<body>
  <div class="gr-promo">&#x1f381; GiftRush — Digital Gift Cards & Rewards</div>
  <div class="gr-header">
    <a href="/?sid=${sessionId}" class="gr-logo">Gift<span>Rush</span></a>
    <div class="gr-nav">
      <a href="/?sid=${sessionId}" class="active">Dashboard</a>
      <a href="#">Browse Cards</a>
      <a href="#">Send Gift</a>
      <a href="#">History</a>
      <a href="#">Account</a>
    </div>
  </div>
  <div class="gr-container">
    <div class="gr-gift-card">
      <div class="gr-gc-label">Gift Card</div>
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
        <button class="gr-race-btn" id="btn-race" onclick="raceRedeem()">&#x26a1; Send 5x Concurrent</button>
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
      <a href="/api/reset?sid=${sessionId}" style="font-family:monospace;font-size:11px;color:#8a7a5a;text-decoration:none;border:1px solid #3d3020;padding:6px 14px;border-radius:6px;" onclick="event.preventDefault();fetch('/api/reset?sid=${sessionId}').then(function(){location.reload();});">Reset Balance to $100.00</a>
    </div>
  </div>
  <div class="gr-footer">© 2026 GiftRush Inc. — Digital Gift Card Services<br>All data is simulated. This is a Penumbra Forge Security Lab.</div>

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
            el.innerHTML = '<div class="gr-result gr-result-exploit">&#x26a1; DOUBLE SPEND DETECTED — Balance went negative: $' + (data.balance / 100).toFixed(2) + '</div>';
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

        log.textContent += '\\n───────────────────────────\\n';
        log.textContent += 'Results: ' + successCount + '/5 succeeded\\n';
        log.textContent += 'Total redeemed: $' + (totalRedeemed/100).toFixed(2) + '\\n';
        log.textContent += 'Final balance: $' + (finalBalance/100).toFixed(2) + '\\n';

        if (doubleSpend || successCount > 1) {
          log.textContent += '\\n⚡ RACE CONDITION EXPLOITED — Multiple requests passed the balance check simultaneously';
          document.getElementById('redeem-result').innerHTML = '<div class="gr-result gr-result-exploit">&#x26a1; RACE CONDITION — ' + successCount + ' of 5 requests succeeded. $' + (totalRedeemed/100).toFixed(2) + ' redeemed from a $' + (amount/100).toFixed(2) + ' balance.</div>';
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
            html += '<tr><td>' + tx.time + '</td><td>' + tx.type + '</td><td class="' + (tx.amount<0?'gr-tx-neg':'gr-tx-pos') + '">' + (tx.amount<0?'-':'+'  ) + '$' + amt + '</td><td>$' + bal + '</td></tr>';
          });
          tbody.innerHTML = html;
        });
    }
  </script>
</body></html>`;
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: { 'Access-Control-Allow-Origin': '*' } });
    }

    /* ── Rate limiting ── */
    const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
    if (isRateLimited(ip)) {
      return new Response(rateLimitPage(), {
        status: 429,
        headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
      });
    }

    // API endpoints return JSON
    if (url.pathname.startsWith('/api/')) {
      const result = renderApp(request.url, request);
      if (result === null) {
        // Reset — redirect to dashboard
        return new Response(null, { status: 302, headers: { 'Location': '/?sid=' + (url.searchParams.get('sid') || 'default'), 'Access-Control-Allow-Origin': '*' } });
      }
      return new Response(result, {
        headers: { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' },
      });
    }

    const html = renderApp(request.url, request);
    return new Response(html, {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=UTF-8', 'Access-Control-Allow-Origin': '*' },
    });
  },
};
