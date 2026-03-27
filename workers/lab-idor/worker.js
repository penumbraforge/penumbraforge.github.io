/**
 * MedConnect — Vulnerable Patient Portal
 * Penumbra Forge Security Labs — RED-06
 *
 * INTENTIONALLY VULNERABLE: Patient record endpoints accept an ID
 * parameter without verifying the logged-in user is authorized to
 * access that patient's data. Classic IDOR vulnerability.
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

// Simulated patient database
const PATIENTS = {
  1: {
    id: 1,
    name: 'Sarah Mitchell',
    dob: '1988-04-15',
    ssn: '***-**-4821',
    insurance: 'BlueCross PPO #BC-448821',
    phone: '(503) 555-0142',
    email: 'sarah.mitchell@email.com',
    bloodType: 'A+',
    allergies: ['Penicillin', 'Latex'],
    primaryCare: 'Dr. James Park',
    appointments: [
      { date: '2026-03-28', time: '10:30 AM', doctor: 'Dr. James Park', type: 'Annual Physical', status: 'Scheduled' },
      { date: '2026-02-14', time: '2:00 PM', doctor: 'Dr. Lisa Wong', type: 'Dermatology Follow-up', status: 'Completed' },
      { date: '2026-01-20', time: '9:00 AM', doctor: 'Dr. James Park', type: 'Blood Work Review', status: 'Completed' },
    ],
    records: [
      { date: '2026-02-14', type: 'Lab Results', doctor: 'Dr. Lisa Wong', summary: 'Complete blood count — all values within normal range. Cholesterol 185 mg/dL.' },
      { date: '2026-01-20', type: 'Visit Notes', doctor: 'Dr. James Park', summary: 'Patient reports mild seasonal allergies. Prescribed loratadine 10mg daily. Follow up in 6 months.' },
      { date: '2025-09-10', type: 'Imaging', doctor: 'Dr. Robert Chen', summary: 'Chest X-ray: No abnormalities detected. Lungs clear bilaterally.' },
    ],
    prescriptions: [
      { name: 'Loratadine 10mg', prescriber: 'Dr. James Park', refills: 3, status: 'Active' },
      { name: 'Vitamin D3 2000IU', prescriber: 'Dr. James Park', refills: 5, status: 'Active' },
    ],
    messages: [
      { from: 'Dr. James Park', date: '2026-03-20', subject: 'Upcoming appointment reminder', preview: 'Hi Sarah, just a reminder about your annual physical on March 28th...' },
      { from: 'Lab Services', date: '2026-02-15', subject: 'Lab results available', preview: 'Your recent lab results have been posted to your portal...' },
    ],
  },
  2: {
    id: 2,
    name: 'Marcus Johnson',
    dob: '1975-11-22',
    ssn: '***-**-7733',
    insurance: 'Aetna HMO #AE-992134',
    phone: '(503) 555-0287',
    email: 'marcus.j@email.com',
    bloodType: 'O-',
    allergies: ['Sulfa drugs'],
    primaryCare: 'Dr. Emily Torres',
    appointments: [
      { date: '2026-04-02', time: '11:00 AM', doctor: 'Dr. Emily Torres', type: 'Diabetes Management', status: 'Scheduled' },
    ],
    records: [
      { date: '2026-03-01', type: 'Lab Results', doctor: 'Dr. Emily Torres', summary: 'HbA1c: 7.2% — slightly elevated. Fasting glucose: 142 mg/dL. Recommend dietary adjustments.' },
      { date: '2026-01-15', type: 'Visit Notes', doctor: 'Dr. Emily Torres', summary: 'Type 2 diabetes follow-up. Metformin dosage maintained at 1000mg BID. Weight: 198 lbs.' },
    ],
    prescriptions: [
      { name: 'Metformin 1000mg', prescriber: 'Dr. Emily Torres', refills: 6, status: 'Active' },
      { name: 'Lisinopril 10mg', prescriber: 'Dr. Emily Torres', refills: 4, status: 'Active' },
    ],
    messages: [
      { from: 'Dr. Emily Torres', date: '2026-03-02', subject: 'Lab results review', preview: 'Marcus, your recent HbA1c came back at 7.2%. Let us discuss adjustments...' },
    ],
  },
  3: {
    id: 3,
    name: 'Elena Vasquez',
    dob: '1992-07-08',
    ssn: '***-**-5519',
    insurance: 'United Healthcare #UH-334567',
    phone: '(503) 555-0391',
    email: 'elena.v@email.com',
    bloodType: 'B+',
    allergies: [],
    primaryCare: 'Dr. James Park',
    appointments: [
      { date: '2026-04-10', time: '3:30 PM', doctor: 'Dr. James Park', type: 'Prenatal Checkup', status: 'Scheduled' },
    ],
    records: [
      { date: '2026-03-10', type: 'Lab Results', doctor: 'Dr. James Park', summary: 'Prenatal panel: All values normal. HCG levels consistent with 14-week gestation.' },
      { date: '2026-02-20', type: 'Imaging', doctor: 'Dr. Sarah Kim', summary: 'First trimester ultrasound: Single viable intrauterine pregnancy. EDD July 28, 2026.' },
    ],
    prescriptions: [
      { name: 'Prenatal Vitamins', prescriber: 'Dr. James Park', refills: 9, status: 'Active' },
    ],
    messages: [
      { from: 'Dr. James Park', date: '2026-03-12', subject: 'Prenatal lab results', preview: 'Elena, all your prenatal labs look great. Everything is progressing normally...' },
    ],
  },
  4: {
    id: 4,
    name: 'William Chen',
    dob: '1960-02-28',
    ssn: '***-**-8847',
    insurance: 'Medicare #MC-112890',
    phone: '(503) 555-0445',
    email: 'w.chen@email.com',
    bloodType: 'AB+',
    allergies: ['Aspirin', 'Codeine', 'Shellfish'],
    primaryCare: 'Dr. Robert Chen',
    appointments: [
      { date: '2026-04-05', time: '9:30 AM', doctor: 'Dr. Robert Chen', type: 'Cardiology Follow-up', status: 'Scheduled' },
    ],
    records: [
      { date: '2026-02-28', type: 'Lab Results', doctor: 'Dr. Robert Chen', summary: 'Lipid panel: Total cholesterol 242 mg/dL (HIGH), LDL 158 mg/dL (HIGH). Statin adjustment recommended.' },
      { date: '2026-01-05', type: 'Visit Notes', doctor: 'Dr. Robert Chen', summary: 'Post-cardiac catheterization follow-up. Patient doing well. No chest pain or shortness of breath.' },
    ],
    prescriptions: [
      { name: 'Atorvastatin 40mg', prescriber: 'Dr. Robert Chen', refills: 6, status: 'Active' },
      { name: 'Metoprolol 50mg', prescriber: 'Dr. Robert Chen', refills: 6, status: 'Active' },
      { name: 'Clopidogrel 75mg', prescriber: 'Dr. Robert Chen', refills: 3, status: 'Active' },
    ],
    messages: [
      { from: 'Dr. Robert Chen', date: '2026-03-01', subject: 'Lipid panel results', preview: 'William, your cholesterol levels are still elevated. I would like to increase your statin dosage...' },
    ],
  },
  5: {
    id: 5,
    name: 'Aisha Okafor',
    dob: '1999-12-03',
    ssn: '***-**-2256',
    insurance: 'Kaiser Permanente #KP-778341',
    phone: '(503) 555-0528',
    email: 'aisha.o@email.com',
    bloodType: 'O+',
    allergies: ['Peanuts'],
    primaryCare: 'Dr. Lisa Wong',
    appointments: [
      { date: '2026-04-15', time: '1:00 PM', doctor: 'Dr. Lisa Wong', type: 'Allergy Consultation', status: 'Scheduled' },
    ],
    records: [
      { date: '2026-03-05', type: 'Lab Results', doctor: 'Dr. Lisa Wong', summary: 'Allergy panel: Positive for peanut IgE (Class 4). Negative for tree nuts. EpiPen prescribed.' },
    ],
    prescriptions: [
      { name: 'EpiPen Auto-Injector', prescriber: 'Dr. Lisa Wong', refills: 2, status: 'Active' },
    ],
    messages: [
      { from: 'Dr. Lisa Wong', date: '2026-03-06', subject: 'Allergy test results', preview: 'Aisha, your allergy panel confirmed a significant peanut allergy. I have prescribed...' },
    ],
  },
};

// Current logged-in user is always Patient 1 (Sarah Mitchell)
const CURRENT_USER_ID = 1;

const STYLES = `
  * { margin:0; padding:0; box-sizing:border-box; }
  body { font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif; background:#f0f9ff; color:#1f2937; }

  .mc-topbar { background:#0c4a6e; color:#7dd3fc; padding:8px 32px; font-size:11px; display:flex; justify-content:space-between; align-items:center; }
  .mc-topbar-hipaa { display:flex; align-items:center; gap:6px; }

  .mc-header { background:#fff; border-bottom:1px solid #e0f2fe; padding:0 32px; display:flex; align-items:center; justify-content:space-between; height:64px; position:sticky; top:0; z-index:100; box-shadow:0 1px 3px rgba(0,0,0,0.04); }
  .mc-header-left { display:flex; align-items:center; gap:32px; }
  .mc-logo { display:flex; align-items:center; gap:10px; text-decoration:none; }
  .mc-logo-icon { width:34px; height:34px; border-radius:8px; background:linear-gradient(135deg,#0ea5e9,#38bdf8); display:flex; align-items:center; justify-content:center; }
  .mc-logo-icon svg { width:20px; height:20px; }
  .mc-logo-text { font-size:20px; font-weight:700; color:#0c4a6e; letter-spacing:-0.5px; }
  .mc-logo-text span { color:#0ea5e9; }
  .mc-nav { display:flex; gap:4px; }
  .mc-nav a { color:#6b7280; text-decoration:none; font-size:14px; font-weight:500; padding:8px 14px; border-radius:8px; transition:all 150ms; }
  .mc-nav a:hover { color:#0c4a6e; background:#e0f2fe; }
  .mc-nav a.active { color:#0ea5e9; background:#e0f2fe; }
  .mc-user { display:flex; align-items:center; gap:10px; font-size:13px; color:#6b7280; }
  .mc-user-avatar { width:34px; height:34px; border-radius:50%; background:#e0f2fe; color:#0ea5e9; display:flex; align-items:center; justify-content:center; font-size:12px; font-weight:700; }

  .mc-container { max-width:1060px; margin:0 auto; padding:24px 24px 0; }

  .mc-card { background:#fff; border:1px solid #e0f2fe; border-radius:12px; padding:24px; margin-bottom:20px; box-shadow:0 1px 3px rgba(0,0,0,0.04); }
  .mc-card h2 { font-size:17px; color:#0c4a6e; margin-bottom:4px; font-weight:600; }
  .mc-card h3 { font-size:13px; color:#6b7280; margin-bottom:16px; font-weight:400; }

  .mc-stats { display:flex; gap:16px; margin-bottom:24px; }
  .mc-stat { background:#e0f2fe; border:1px solid #bae6fd; border-radius:10px; padding:18px 20px; flex:1; }
  .mc-stat-num { font-size:26px; color:#0c4a6e; font-weight:700; }
  .mc-stat-label { font-size:11px; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-top:4px; }

  .mc-table { width:100%; border-collapse:collapse; font-size:13px; }
  .mc-table th { text-align:left; padding:10px 12px; color:#6b7280; font-weight:500; border-bottom:2px solid #e0f2fe; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; }
  .mc-table td { padding:10px 12px; border-bottom:1px solid #f0f9ff; color:#1f2937; }
  .mc-table tr:hover { background:#f0f9ff; }

  .mc-badge { display:inline-flex; padding:4px 12px; border-radius:20px; font-size:11px; font-weight:600; }
  .mc-badge-scheduled { color:#f59e0b; background:#fffbeb; }
  .mc-badge-completed { color:#059669; background:#ecfdf5; }
  .mc-badge-active { color:#0ea5e9; background:#e0f2fe; }

  .mc-record { border:1px solid #e0f2fe; border-radius:10px; padding:16px; margin-bottom:10px; transition:all 150ms; }
  .mc-record:hover { background:#f0f9ff; }
  .mc-record-header { display:flex; justify-content:space-between; align-items:center; margin-bottom:6px; }
  .mc-record-type { font-weight:600; font-size:14px; color:#0c4a6e; }
  .mc-record-date { font-size:12px; color:#6b7280; }
  .mc-record-doctor { font-size:12px; color:#6b7280; margin-bottom:6px; }
  .mc-record-summary { font-size:13px; color:#374151; line-height:1.6; }

  .mc-message { border:1px solid #e0f2fe; border-radius:10px; padding:16px; margin-bottom:10px; cursor:pointer; transition:all 150ms; }
  .mc-message:hover { background:#f0f9ff; border-color:#bae6fd; }
  .mc-message-from { font-weight:600; font-size:13px; color:#0c4a6e; }
  .mc-message-subject { font-size:14px; color:#1f2937; margin:4px 0; }
  .mc-message-preview { font-size:12px; color:#6b7280; }
  .mc-message-date { font-size:11px; color:#9ca3af; margin-top:4px; }

  .mc-patient-info { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  .mc-info-item { background:#f0f9ff; border-radius:8px; padding:12px 16px; }
  .mc-info-label { font-size:11px; color:#6b7280; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:4px; }
  .mc-info-value { font-size:14px; color:#1f2937; font-weight:500; }

  .mc-rx { border:1px solid #e0f2fe; border-radius:10px; padding:14px 16px; margin-bottom:8px; display:flex; justify-content:space-between; align-items:center; }
  .mc-rx-name { font-weight:600; font-size:14px; color:#0c4a6e; }
  .mc-rx-detail { font-size:12px; color:#6b7280; }
  .mc-rx-refill { padding:6px 14px; background:#0ea5e9; color:#fff; border:none; border-radius:8px; font-size:12px; font-weight:600; cursor:pointer; }
  .mc-rx-refill:hover { background:#0284c7; }

  .mc-id-nav { display:flex; gap:8px; margin-bottom:16px; }
  .mc-id-nav a { display:inline-flex; align-items:center; gap:6px; padding:8px 16px; background:#f0f9ff; border:1px solid #e0f2fe; border-radius:8px; text-decoration:none; font-size:12px; color:#0ea5e9; font-family:monospace; transition:all 150ms; }
  .mc-id-nav a:hover { background:#e0f2fe; }
  .mc-id-nav a.current { background:#0ea5e9; color:#fff; border-color:#0ea5e9; }

  .mc-warn { background:#fef2f2; border:1px solid #fecaca; border-radius:10px; padding:14px 18px; margin-bottom:16px; font-size:13px; color:#ef4444; display:flex; align-items:center; gap:10px; }

  .mc-footer { text-align:center; padding:32px 24px; color:#9ca3af; font-size:12px; border-top:1px solid #e0f2fe; margin-top:48px; background:#fff; }
`;

function shell(title, activePage, content) {
  const patient = PATIENTS[CURRENT_USER_ID];
  return `<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${title} — MedConnect</title><style>${STYLES}</style></head>
<body>
  <div class="mc-topbar">
    <span>MedConnect Patient Portal v3.1.0</span>
    <div class="mc-topbar-hipaa">
      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>
      HIPAA Compliant &middot; Encrypted Connection
    </div>
  </div>
  <div class="mc-header">
    <div class="mc-header-left">
      <a href="/" class="mc-logo">
        <div class="mc-logo-icon"><svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="2"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg></div>
        <div class="mc-logo-text">Med<span>Connect</span></div>
      </a>
      <div class="mc-nav">
        <a href="/"${activePage==='dashboard'?' class="active"':''}>Dashboard</a>
        <a href="/records?patient_id=1"${activePage==='records'?' class="active"':''}>Records</a>
        <a href="/messages"${activePage==='messages'?' class="active"':''}>Messages</a>
        <a href="/prescriptions"${activePage==='prescriptions'?' class="active"':''}>Prescriptions</a>
      </div>
    </div>
    <div class="mc-user">
      <span>${patient.name}</span>
      <div class="mc-user-avatar">SM</div>
    </div>
  </div>
  <div class="mc-container">${content}</div>
  <div class="mc-footer">
    &copy; 2026 MedConnect Health Systems — HIPAA Compliant
    <div style="margin-top:4px;">All data is simulated. This is a Penumbra Forge Security Lab.</div>
  </div>
  <script>
  document.cookie="session=eyJ1c2VyIjoic2FyYWgubWl0Y2hlbGwiLCJwYXRpZW50X2lkIjoxLCJyb2xlIjoicGF0aWVudCJ9;path=/";

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
    var params = new URLSearchParams(window.location.search);
    window.parent.postMessage({
      type: 'medconnect-nav',
      path: window.location.pathname,
      patientId: params.get('patient_id') || '',
      url: window.location.href
    }, '*');
  } catch(e) {}
  </script>
</body></html>`;
}

function renderApp(url) {
  const urlObj = new URL(url);
  const path = urlObj.pathname;
  const params = urlObj.searchParams;

  // ═══════════════════════════════════════════════════
  // INTENTIONALLY VULNERABLE — DO NOT FIX
  // The patient_id parameter is taken directly from the
  // URL with NO authorization check. Any patient's data
  // can be accessed by changing the ID parameter.
  // The logged-in user is always Patient 1, but endpoints
  // return data for whatever patient_id is requested.
  // ═══════════════════════════════════════════════════

  if (path === '/records' || path === '/records/') {
    const patientId = parseInt(params.get('patient_id') || '1', 10);
    return renderRecords(patientId);
  }
  if (path.match(/^\/api\/patients\/\d+\/records$/)) {
    const patientId = parseInt(path.split('/')[3], 10);
    return handlePatientRecords(patientId);
  }
  if (path.match(/^\/api\/patients\/\d+\/appointments$/)) {
    const patientId = parseInt(path.split('/')[3], 10);
    return handlePatientAppointments(patientId);
  }
  if (path.match(/^\/api\/patients\/\d+\/prescriptions$/)) {
    const patientId = parseInt(path.split('/')[3], 10);
    return handlePatientPrescriptions(patientId);
  }
  if (path.match(/^\/api\/patients\/\d+$/)) {
    const patientId = parseInt(path.split('/')[3], 10);
    return handlePatientInfo(patientId);
  }
  if (path === '/messages' || path === '/messages/') {
    return renderMessages();
  }
  if (path === '/prescriptions' || path === '/prescriptions/') {
    return renderPrescriptions();
  }

  return renderDashboard();
}

function handlePatientRecords(patientId) {
  // VULNERABLE: No authorization check
  const patient = PATIENTS[patientId];
  if (!patient) return JSON.stringify({ error: 'Patient not found' });
  return JSON.stringify({
    patient_id: patient.id,
    name: patient.name,
    records: patient.records,
  });
}

function handlePatientAppointments(patientId) {
  // VULNERABLE: No authorization check
  const patient = PATIENTS[patientId];
  if (!patient) return JSON.stringify({ error: 'Patient not found' });
  return JSON.stringify({
    patient_id: patient.id,
    name: patient.name,
    appointments: patient.appointments,
  });
}

function handlePatientPrescriptions(patientId) {
  // VULNERABLE: No authorization check
  const patient = PATIENTS[patientId];
  if (!patient) return JSON.stringify({ error: 'Patient not found' });
  return JSON.stringify({
    patient_id: patient.id,
    name: patient.name,
    prescriptions: patient.prescriptions,
  });
}

function handlePatientInfo(patientId) {
  // VULNERABLE: No authorization check — returns full patient PII
  const patient = PATIENTS[patientId];
  if (!patient) return JSON.stringify({ error: 'Patient not found' });
  return JSON.stringify({
    patient_id: patient.id,
    name: patient.name,
    dob: patient.dob,
    ssn: patient.ssn,
    insurance: patient.insurance,
    phone: patient.phone,
    email: patient.email,
    bloodType: patient.bloodType,
    allergies: patient.allergies,
    primaryCare: patient.primaryCare,
  });
}

function renderDashboard() {
  const patient = PATIENTS[CURRENT_USER_ID];
  const nextAppt = patient.appointments.find(a => a.status === 'Scheduled');

  return shell('Dashboard', 'dashboard', `
    <div class="mc-stats">
      <div class="mc-stat"><div class="mc-stat-num">${patient.appointments.length}</div><div class="mc-stat-label">Appointments</div></div>
      <div class="mc-stat"><div class="mc-stat-num">${patient.records.length}</div><div class="mc-stat-label">Medical Records</div></div>
      <div class="mc-stat"><div class="mc-stat-num">${patient.prescriptions.length}</div><div class="mc-stat-label">Active Prescriptions</div></div>
      <div class="mc-stat"><div class="mc-stat-num">${patient.messages.length}</div><div class="mc-stat-label">Messages</div></div>
    </div>

    <div class="mc-card">
      <h2>Patient Information</h2>
      <div class="mc-patient-info">
        <div class="mc-info-item"><div class="mc-info-label">Full Name</div><div class="mc-info-value">${patient.name}</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Date of Birth</div><div class="mc-info-value">${patient.dob}</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Blood Type</div><div class="mc-info-value">${patient.bloodType}</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Insurance</div><div class="mc-info-value">${patient.insurance}</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Primary Care</div><div class="mc-info-value">${patient.primaryCare}</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Allergies</div><div class="mc-info-value">${patient.allergies.length > 0 ? patient.allergies.join(', ') : 'None'}</div></div>
      </div>
    </div>

    ${nextAppt ? `
    <div class="mc-card">
      <h2>Next Appointment</h2>
      <div style="display:flex;justify-content:space-between;align-items:center;padding:16px;background:#f0f9ff;border-radius:10px;">
        <div>
          <div style="font-weight:600;font-size:15px;color:#0c4a6e;">${nextAppt.type}</div>
          <div style="font-size:13px;color:#6b7280;margin-top:2px;">${nextAppt.doctor} &middot; ${nextAppt.date} at ${nextAppt.time}</div>
        </div>
        <span class="mc-badge mc-badge-scheduled">${nextAppt.status}</span>
      </div>
    </div>` : ''}

    <div class="mc-card">
      <h2>Recent Messages</h2>
      ${patient.messages.map(m => `
        <div class="mc-message">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div class="mc-message-from">${m.from}</div>
            <div class="mc-message-date">${m.date}</div>
          </div>
          <div class="mc-message-subject">${m.subject}</div>
          <div class="mc-message-preview">${m.preview}</div>
        </div>
      `).join('')}
    </div>

    <div class="mc-card">
      <h2>Quick Actions</h2>
      <div style="display:flex;gap:10px;flex-wrap:wrap;">
        <a href="/records?patient_id=1" style="padding:10px 20px;background:#0ea5e9;color:#fff;border-radius:10px;text-decoration:none;font-size:13px;font-weight:600;">View Medical Records</a>
        <a href="/prescriptions" style="padding:10px 20px;background:#f0f9ff;color:#0ea5e9;border:1px solid #bae6fd;border-radius:10px;text-decoration:none;font-size:13px;font-weight:500;">Refill Prescriptions</a>
        <a href="/messages" style="padding:10px 20px;background:#f0f9ff;color:#0ea5e9;border:1px solid #bae6fd;border-radius:10px;text-decoration:none;font-size:13px;font-weight:500;">Message Doctor</a>
      </div>
    </div>
  `);
}

function renderRecords(patientId) {
  const patient = PATIENTS[patientId];
  const isOwnRecords = patientId === CURRENT_USER_ID;

  if (!patient) {
    return shell('Records — Not Found', 'records', `
      <div class="mc-card">
        <h2>Patient Not Found</h2>
        <p style="font-size:13px;color:#6b7280;">No patient found with ID ${patientId}.</p>
      </div>
    `);
  }

  // Show navigation hint with patient IDs
  const idLinks = [1,2,3,4,5].map(id =>
    `<a href="/records?patient_id=${id}" class="${id === patientId ? 'current' : ''}">Patient #${id}</a>`
  ).join('');

  let warnHtml = '';
  if (!isOwnRecords) {
    warnHtml = `
      <script>
        window.parent.postMessage({
          type: 'idor-result',
          patientId: ${patientId},
          accessedName: ${JSON.stringify(patient.name)},
          isUnauthorized: true,
          currentUserId: ${CURRENT_USER_ID}
        }, '*');
      <\/script>`;
  }

  return shell('Medical Records', 'records', `
    <div class="mc-id-nav">
      ${idLinks}
    </div>
    <div style="font-family:monospace;font-size:11px;color:#6b7280;margin-bottom:16px;padding:10px 14px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;">
      GET /api/patients/<strong style="color:#0ea5e9;">${patientId}</strong>/records &nbsp;&middot;&nbsp; Logged in as: Patient #${CURRENT_USER_ID} (${PATIENTS[CURRENT_USER_ID].name})
    </div>

    ${!isOwnRecords ? `<div class="mc-warn"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>Viewing records for <strong>${escHtml(patient.name)}</strong> (Patient #${patientId}) — You are logged in as Patient #${CURRENT_USER_ID}</div>` : ''}

    <div class="mc-card">
      <h2>Patient Profile — ${escHtml(patient.name)}</h2>
      <div class="mc-patient-info">
        <div class="mc-info-item"><div class="mc-info-label">Full Name</div><div class="mc-info-value">${escHtml(patient.name)}</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Date of Birth</div><div class="mc-info-value">${patient.dob}</div></div>
        <div class="mc-info-item"><div class="mc-info-label">SSN</div><div class="mc-info-value">${patient.ssn}</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Insurance</div><div class="mc-info-value">${patient.insurance}</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Blood Type</div><div class="mc-info-value">${patient.bloodType}</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Allergies</div><div class="mc-info-value">${patient.allergies.length > 0 ? patient.allergies.join(', ') : 'None'}</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Phone</div><div class="mc-info-value">${patient.phone}</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Email</div><div class="mc-info-value">${patient.email}</div></div>
      </div>
    </div>

    <div class="mc-card">
      <h2>Medical Records</h2>
      ${patient.records.map(r => `
        <div class="mc-record">
          <div class="mc-record-header">
            <div class="mc-record-type">${r.type}</div>
            <div class="mc-record-date">${r.date}</div>
          </div>
          <div class="mc-record-doctor">${r.doctor}</div>
          <div class="mc-record-summary">${r.summary}</div>
        </div>
      `).join('')}
    </div>

    <div class="mc-card">
      <h2>Appointments</h2>
      <table class="mc-table">
        <thead><tr><th>Date</th><th>Time</th><th>Doctor</th><th>Type</th><th>Status</th></tr></thead>
        <tbody>
          ${patient.appointments.map(a => `
            <tr>
              <td>${a.date}</td>
              <td>${a.time}</td>
              <td>${a.doctor}</td>
              <td>${a.type}</td>
              <td><span class="mc-badge mc-badge-${a.status.toLowerCase()}">${a.status}</span></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    </div>
    ${warnHtml}
  `);
}

function renderMessages() {
  const patient = PATIENTS[CURRENT_USER_ID];

  return shell('Messages', 'messages', `
    <div class="mc-card">
      <h2>Inbox</h2>
      <h3>${patient.messages.length} messages</h3>
      ${patient.messages.map(m => `
        <div class="mc-message">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <div class="mc-message-from">${m.from}</div>
            <div class="mc-message-date">${m.date}</div>
          </div>
          <div class="mc-message-subject">${m.subject}</div>
          <div class="mc-message-preview">${m.preview}</div>
        </div>
      `).join('')}
    </div>

    <div class="mc-card">
      <h2>Compose Message</h2>
      <div style="margin-bottom:12px;">
        <label style="display:block;font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">To</label>
        <select style="width:100%;padding:10px 14px;border:2px solid #e0f2fe;border-radius:10px;font-size:14px;color:#1f2937;background:#f9fafb;outline:none;">
          <option>${patient.primaryCare}</option>
          <option>Lab Services</option>
          <option>Billing Department</option>
        </select>
      </div>
      <div style="margin-bottom:12px;">
        <label style="display:block;font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Subject</label>
        <input type="text" placeholder="Enter subject..." style="width:100%;padding:10px 14px;border:2px solid #e0f2fe;border-radius:10px;font-size:14px;color:#1f2937;background:#f9fafb;outline:none;">
      </div>
      <div style="margin-bottom:12px;">
        <label style="display:block;font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px;">Message</label>
        <textarea rows="4" placeholder="Type your message..." style="width:100%;padding:10px 14px;border:2px solid #e0f2fe;border-radius:10px;font-size:14px;color:#1f2937;background:#f9fafb;outline:none;resize:vertical;"></textarea>
      </div>
      <button style="padding:10px 24px;background:#0ea5e9;color:#fff;border:none;border-radius:10px;font-size:14px;font-weight:600;cursor:pointer;">Send Message</button>
    </div>
  `);
}

function renderPrescriptions() {
  const patient = PATIENTS[CURRENT_USER_ID];

  return shell('Prescriptions', 'prescriptions', `
    <div class="mc-card">
      <h2>Active Prescriptions</h2>
      <h3>Manage your current medications</h3>
      ${patient.prescriptions.map(rx => `
        <div class="mc-rx">
          <div>
            <div class="mc-rx-name">${rx.name}</div>
            <div class="mc-rx-detail">Prescribed by ${rx.prescriber} &middot; ${rx.refills} refills remaining</div>
          </div>
          <div style="display:flex;align-items:center;gap:10px;">
            <span class="mc-badge mc-badge-active">${rx.status}</span>
            <button class="mc-rx-refill">Request Refill</button>
          </div>
        </div>
      `).join('')}
    </div>

    <div class="mc-card">
      <h2>Pharmacy Information</h2>
      <div class="mc-patient-info">
        <div class="mc-info-item"><div class="mc-info-label">Preferred Pharmacy</div><div class="mc-info-value">Walgreens #4821</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Address</div><div class="mc-info-value">1234 NW 23rd Ave, Portland OR</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Phone</div><div class="mc-info-value">(503) 555-0800</div></div>
        <div class="mc-info-item"><div class="mc-info-label">Hours</div><div class="mc-info-value">Mon-Sat 8AM-10PM, Sun 9AM-6PM</div></div>
      </div>
    </div>
  `);
}

function escHtml(s) {
  return (s || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
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
        if (body.type === 'idor-check') {
          const patientId = parseInt(body.patientId, 10);
          const isUnauthorized = patientId !== CURRENT_USER_ID;
          const patientExists = !!PATIENTS[patientId];
          const patient = PATIENTS[patientId];

          return new Response(JSON.stringify({
            isUnauthorized,
            patientExists,
            accessedName: patient ? patient.name : null,
            currentUserId: CURRENT_USER_ID,
            requestedId: patientId,
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
    if (url.pathname.startsWith('/api/patients/')) {
      const result = renderApp(request.url);
      return new Response(result, {
        headers: { 'Content-Type': 'application/json', ...corsHeaders },
      });
    }

    const html = renderApp(request.url);
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
