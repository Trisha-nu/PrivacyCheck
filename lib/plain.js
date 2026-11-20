'use strict';
/** Plain-language wording for every test case, for non-technical users,
 *  plus formal Software Testing specifications for academic evaluation. */

const GROUPS = [
  {
    id: 'connection',
    title: 'Is your connection private?',
    blurb: 'Whether what you type is scrambled and protected while it travels across the internet to the site.',
    tips: ['Avoid logging in, entering passwords, or entering card details on this site, especially on open or public Wi-Fi.'],
    ids: ['TC01', 'TC02']
  },
  {
    id: 'protection',
    title: 'Does the site protect you from attackers?',
    blurb: 'Built-in security shields against common hacker tricks like fake buttons, injected malicious scripts, and data leakage.',
    tips: ['Be cautious with external links, forms, and file downloads originating from this site.'],
    ids: ['TC03', 'TC04', 'TC05', 'TC06']
  },
  {
    id: 'cookies',
    title: 'Are its cookies handled safely?',
    blurb: 'Cookies are small tokens that remember who you are. If improperly locked, other websites or snoops could misuse your session.',
    tips: ["Always log out when you're finished, and avoid using this site on shared or public computers."],
    ids: ['TC07', 'TC08', 'TC09']
  },
  {
    id: 'info',
    title: 'Does it tell you what it does with your data?',
    blurb: 'Whether the website is transparent about privacy, data collection, and gives you a say over cookies.',
    tips: ["Check for a privacy policy link in the site's footer before registering or sharing sensitive details."],
    ids: ['TC10', 'TC11']
  }
];

const PLAIN = {
  TC01: {
    title: 'Your connection to the site is private (HTTPS)',
    pass: "What you send to this site is encrypted, so other people cannot read it on the way.",
    fail: 'This site uses an unprotected connection. On shared Wi-Fi, someone nearby could see what you type, including passwords.',
    inconclusive: "We couldn't tell how this site connects.",
    why: 'Look for the padlock beside the address in your browser. Without it, passwords and card details can be intercepted.',
    iso25010: 'Confidentiality & Data Encryption',
    technique: 'Equivalence Partitioning (Scheme validation: https vs http)',
    severity: 'High'
  },
  TC02: {
    title: 'Your browser is told to always stay on the safe connection (HSTS)',
    pass: 'The site tells browsers to always use the private connection automatically.',
    fail: "The site does not force browsers to stay on the private connection, so you could be steered onto an unsafe copy of it.",
    inconclusive: "We couldn't check this.",
    why: "It's like a standing instruction: never talk to this site in the open, which prevents SSL-stripping attacks.",
    iso25010: 'Integrity & Non-repudiation',
    technique: 'Boundary Value Analysis (max-age > 0)',
    severity: 'Medium'
  },
  TC03: {
    title: 'Protected against harmful code being slipped in (CSP)',
    pass: 'The site restricts where scripts and resources can load from, making malicious injection attacks difficult.',
    fail: "The site does not restrict where scripts can load from, making it easier for attackers to sneak in harmful scripts.",
    inconclusive: "We couldn't check this.",
    why: 'Harmful code on a page can steal what you type, capture keystrokes, or display fake login forms (Cross-Site Scripting).',
    iso25010: 'Integrity & Code Injection Immunity',
    technique: 'Negative Testing (Report-Only policy rejected; enforced policy required)',
    severity: 'High'
  },
  TC04: {
    title: 'Files are handled safely (nosniff)',
    pass: "Your browser is told not to guess what a file is, which blocks a sneaky file spoofing trick.",
    fail: 'Your browser is allowed to guess what files are, which attackers can sometimes exploit to execute hidden code.',
    inconclusive: "We couldn't check this.",
    why: 'A harmful script can be disguised as a harmless image or text file.',
    iso25010: 'Fault Tolerance & Content Integrity',
    technique: 'Equivalence Partitioning (Exact string match: nosniff)',
    severity: 'Low'
  },
  TC05: {
    title: "Cannot be hidden inside another page (Clickjacking Protection)",
    pass: "Other websites cannot secretly embed this site inside an invisible frame to trick you into clicking buttons.",
    fail: 'Other websites could hide this site inside their own page and trick you into clicking buttons you cannot see.',
    inconclusive: "We couldn't check this.",
    why: "This trick is called clickjacking. You think you're clicking one thing, but you're actually clicking another beneath it.",
    iso25010: 'Authenticity & Interface Security',
    technique: 'Multi-condition Decision Coverage (X-Frame-Options or CSP frame-ancestors)',
    severity: 'Medium'
  },
  TC06: {
    title: "Doesn't reveal where you came from (Referrer Policy)",
    pass: 'The site limits what other websites learn about the specific pages you visit when you click links.',
    fail: 'Sites you click through to may learn more about your browsing path than they need to.',
    inconclusive: "We couldn't check this.",
    why: 'The full address of a web page can contain private details like search queries, reset tokens, or account IDs.',
    iso25010: 'Privacy & Information Leaking Prevention',
    technique: 'Negative Testing (unsafe-url policy marked fail)',
    severity: 'Low'
  },
  TC07: {
    title: 'Cookies only travel over the private connection (Secure)',
    pass: "The site's cookies are strictly sent over the private encrypted connection.",
    fail: 'Some cookies could be sent over an unprotected connection, where network snoopers might steal them.',
    inconclusive: "This site didn't set any cookies on our visit, so there was nothing to check.",
    why: 'If an eavesdropper intercepts your session cookie, they can impersonate you and access your account.',
    iso25010: 'Confidentiality & Session Protection',
    technique: 'Invariant Checking (Every cookie must declare Secure attribute)',
    severity: 'High'
  },
  TC08: {
    title: 'Cookies are hidden from harmful scripts (HttpOnly)',
    pass: "Scripts on the page cannot read the site's cookies, protecting your login from being stolen by malicious code.",
    fail: 'Scripts on the page can read some cookies, which could expose your login if the page is compromised.',
    inconclusive: "This site didn't set any cookies on our visit, so there was nothing to check.",
    why: 'It adds a second barrier: even if an attacker finds a way to run code, they cannot read your session credentials.',
    iso25010: 'Confidentiality & Cross-Site Scripting Mitigation',
    technique: 'Invariant Checking (Every cookie must declare HttpOnly attribute)',
    severity: 'Medium'
  },
  TC09: {
    title: "Cookies cannot be misused by other sites (SameSite)",
    pass: "Cookies are not sent along with unexpected requests started from external websites.",
    fail: 'Cookies may be sent with requests started by other websites, which can be abused to act on your behalf.',
    inconclusive: "This site didn't set any cookies on our visit, so there was nothing to check.",
    why: 'This stops Cross-Site Request Forgery (CSRF), where a rogue site secretly submits forms in your name.',
    iso25010: 'Authenticity & Cross-Origin Request Forgery Prevention',
    technique: 'Equivalence Partitioning (SameSite attribute present)',
    severity: 'Medium'
  },
  TC10: {
    title: 'Has a discoverable privacy policy',
    pass: 'We found a link to a privacy policy, so you can read how your personal information is stored and used.',
    fail: "We couldn't find a privacy policy link on this page. Check the footer yourself in case it is loaded dynamically.",
    inconclusive: "We couldn't read this page's content, so we couldn't look for a privacy policy.",
    why: 'A privacy policy is the official legal commitment explaining what data is gathered, who it is sold to, and your rights.',
    iso25010: 'Regulatory Compliance & User Transparency',
    technique: 'Static HTML Anchor Pattern Matching',
    severity: 'High'
  },
  TC11: {
    title: 'Cookie consent mechanism detected',
    pass: 'We found a cookie consent notice or banner markup, allowing visitors to choose their tracking preferences.',
    fail: "We did not find any cookie consent notice in the static HTML.",
    inconclusive: "No consent markup found in static HTML. Many modern sites inject banners via JavaScript, which requires a full browser to observe.",
    why: 'Privacy regulations (GDPR, CCPA, ePrivacy) require websites to ask before storing non-essential tracking cookies.',
    iso25010: 'Regulatory Compliance & Tri-state Logic Handling',
    technique: 'Static Keyword Pattern Matching with Tri-state Oracle (Pass/Inconclusive)',
    severity: 'Medium'
  }
};

/** Evaluates 5 plain-English questions for non-technical users */
function getPlainChecklist(results) {
  const map = Object.fromEntries(results.map((r) => [r.id, r.status]));
  
  // 1. Can I safely enter passwords / log in?
  let canLogin = { status: 'pass', label: 'Safe to Log In', reason: 'Connection is encrypted and cookies are guarded from interception.' };
  if (map.TC01 === 'fail') {
    canLogin = { status: 'fail', label: 'Do NOT Log In', reason: 'Your connection is unencrypted. Passwords can be intercepted on the network.' };
  } else if (map.TC07 === 'fail') {
    canLogin = { status: 'fail', label: 'High Risk for Logins', reason: 'Session cookies are not marked Secure and can leak over plain HTTP.' };
  } else if (map.TC08 === 'fail') {
    canLogin = { status: 'warn', label: 'Use Caution', reason: 'Cookies lack HttpOnly protection; vulnerable if the site is attacked.' };
  } else if (map.TC01 === 'inconclusive') {
    canLogin = { status: 'inconclusive', label: 'Unknown', reason: 'Could not verify the site connection.' };
  }

  // 2. Can I safely shop or make payments?
  let canPay = { status: 'pass', label: 'Safe for Payments', reason: 'Meets essential transport encryption and frame-defense standards.' };
  if (map.TC01 === 'fail') {
    canPay = { status: 'fail', label: 'Unsafe for Payments', reason: 'Never enter credit card or banking details over unencrypted connections.' };
  } else if (map.TC02 === 'fail' || map.TC05 === 'fail') {
    canPay = { status: 'warn', label: 'Use Caution for Payments', reason: 'Missing either forced HTTPS (HSTS) or Clickjacking defense.' };
  } else if (map.TC01 === 'inconclusive') {
    canPay = { status: 'inconclusive', label: 'Unknown', reason: 'Could not verify site encryption.' };
  }

  // 3. Am I safe on public Wi-Fi?
  let wiFiSafe = { status: 'pass', label: 'Protected on Wi-Fi', reason: 'HTTPS scrambling keeps your browsing private from people sharing your Wi-Fi.' };
  if (map.TC01 === 'fail') {
    wiFiSafe = { status: 'fail', label: 'Vulnerable on Wi-Fi', reason: 'Anyone sharing your Wi-Fi hotspot or router can see what you browse and submit.' };
  } else if (map.TC01 === 'inconclusive') {
    wiFiSafe = { status: 'inconclusive', label: 'Unknown', reason: 'Could not verify Wi-Fi transport safety.' };
  }

  // 4. Attack resistance (Clickjacking & XSS)
  let attackDefense = { status: 'pass', label: 'Shielded from Common Attacks', reason: 'Equipped with Content-Security-Policy and anti-clickjacking headers.' };
  if (map.TC03 === 'fail' && map.TC05 === 'fail') {
    attackDefense = { status: 'fail', label: 'Weak Attack Defenses', reason: 'Missing Content-Security-Policy and Clickjacking protections.' };
  } else if (map.TC03 === 'fail' || map.TC05 === 'fail') {
    attackDefense = { status: 'warn', label: 'Partial Defenses', reason: 'Missing some browser security headers against fake buttons or scripts.' };
  } else if (map.TC03 === 'inconclusive' && map.TC05 === 'inconclusive') {
    attackDefense = { status: 'inconclusive', label: 'Unknown', reason: 'Could not inspect security headers.' };
  }

  // 5. Privacy Policy & Transparency
  let privacyNotice = { status: 'pass', label: 'Privacy Policy Found', reason: 'Discloses how your data is handled with an accessible policy link.' };
  if (map.TC10 === 'fail') {
    privacyNotice = { status: 'warn', label: 'Policy Not Discovered', reason: 'No privacy policy link was detected in the static page layout.' };
  } else if (map.TC10 === 'inconclusive') {
    privacyNotice = { status: 'inconclusive', label: 'Could Not Inspect', reason: 'Page content was not readable or automated access was blocked.' };
  }

  return [
    { id: 'login', title: 'Can I safely log in or enter passwords?', ...canLogin, icon: 'lock' },
    { id: 'pay', title: 'Can I safely make purchases or payments?', ...canPay, icon: 'credit-card' },
    { id: 'wifi', title: 'Am I protected on public or hotel Wi-Fi?', ...wiFiSafe, icon: 'wifi' },
    { id: 'attack', title: 'Is the site protected from malicious trickery?', ...attackDefense, icon: 'shield' },
    { id: 'policy', title: 'Does the site provide a Privacy Policy?', ...privacyNotice, icon: 'file-text' }
  ];
}

/** Generates personalized tips for users */
function getActionTips(results) {
  const map = Object.fromEntries(results.map((r) => [r.id, r.status]));
  const tips = [];

  if (map.TC01 === 'fail') {
    tips.push({
      priority: 'high',
      title: 'Never submit confidential information',
      desc: 'Because this website uses plain HTTP, any password, credit card, or message you submit is readable in clear text across the network.'
    });
  }
  if (map.TC02 === 'fail') {
    tips.push({
      priority: 'medium',
      title: 'Enable HTTPS-Only mode in your browser',
      desc: 'This site does not enforce HSTS. Turn on "Always use secure connections" in Chrome, Firefox, Edge, or Safari to protect yourself.'
    });
  }
  if (map.TC07 === 'fail' || map.TC08 === 'fail') {
    tips.push({
      priority: 'medium',
      title: 'Log out immediately after finishing',
      desc: 'Cookie security flags are missing. Always log out, especially when browsing on shared laptops, school computers, or work terminals.'
    });
  }
  if (map.TC05 === 'fail') {
    tips.push({
      priority: 'low',
      title: 'Watch out for suspicious pop-ups or external links',
      desc: 'The site can be framed inside another webpage. If you arrived via a link in a suspicious email or chat, check the address bar carefully.'
    });
  }
  if (map.TC10 === 'fail') {
    tips.push({
      priority: 'low',
      title: 'Verify company details before sharing personal data',
      desc: 'A privacy policy could not be located in the static page HTML. Check the footer manually to ensure you know who holds your data.'
    });
  }
  if (tips.length === 0) {
    tips.push({
      priority: 'good',
      title: 'Top-tier safety standards detected',
      desc: 'This website implements industry-standard privacy safeguards. You can browse, log in, and use this service with strong confidence.'
    });
  }
  return tips;
}

const QA_METHODOLOGY = {
  title: 'Software Testing Capstone Methodology (CSA3701)',
  overview: 'PrivacyCheck implements an automated black-box test harness combining tri-state test case evaluation, independent expected-results test oracles, and automated regression testing.',
  keyPrinciples: [
    {
      name: 'Specification-Based Black-Box Testing',
      desc: 'Evaluates target web properties strictly from external observations (HTTP response codes, security headers, cookie attributes, and static DOM structure) without internal server instrumentation.'
    },
    {
      name: 'Tri-State Test Case Evaluation (Pass / Fail / Inconclusive)',
      desc: 'In automated privacy verification, absence of evidence is not evidence of absence. When a server blocks automated queries (HTTP 403) or when cookies/DOM are absent, the test returns "inconclusive" rather than inventing a false positive or false negative.'
    },
    {
      name: 'Controlled Test Oracle (Testing Lab)',
      desc: 'Solves the "Test Oracle Problem" by deploying 5 benchmark demo sites with known static configurations and an independent, hand-authored expected results matrix (55 executions = 5 sites x 11 test cases).'
    },
    {
      name: 'Automated Regression Detection',
      desc: 'Maintains historical run snapshots in JSON. When developers modify header/cookie configurations, the regression engine performs state diffing to isolate newly broken defects vs resolved test cases.'
    },
    {
      name: 'SSRF & Boundary Defensive Testing',
      desc: 'Testing fetcher adheres to rigorous security boundaries: blocking loopback (127.0.0.1, ::1), private subnets (RFC 1918), cloud metadata endpoints (169.254.169.254), non-standard ports, and credential injection.'
    }
  ]
};

module.exports = { PLAIN, GROUPS, getPlainChecklist, getActionTips, QA_METHODOLOGY };
