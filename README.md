# SiteAudit Pro

AI-Powered Website Security, UI/UX, and Performance Analysis Tool

LIVE Preview - https://siteaudit-pro-4hhr.onrender.com/

[SiteAudit Pro – Product Video.html](https://github.com/user-attachments/files/33043461/SiteAudit.Pro.Product.Video.html)
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>SiteAudit Pro – Product Video</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Sora:wght@700;800&family=Outfit:wght@500;700&family=Red+Hat+Mono:wght@500&display=swap" rel="stylesheet">
<style>
:root{--page:#E6EEF7;--ink:#0D1321;--mute:#52627F;--line:#C4D2E6;--cy:#22D3EE;--red:#FF4D6D;--org:#FF9F1C;--yel:#FFD166;--grn:#06D6A0;
box-sizing:border-box;padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--page:#070B14;--mute:#8CA0C4;--line:#1E2A47}}
:root[data-theme="dark"]{--page:#070B14;--mute:#8CA0C4;--line:#1E2A47}
*{box-sizing:border-box}
html{scroll-padding-top:env(safe-area-inset-top,0px)}
body{margin:0;background:var(--page);font-family:Outfit,system-ui,sans-serif;min-height:100vh;display:grid;place-items:center;padding:16px}
.wrap{width:100%;max-width:1000px}
.stage{container-type:inline-size;position:relative;aspect-ratio:16/9;border-radius:14px;overflow:hidden;background:#0D1321;box-shadow:0 12px 40px rgba(7,11,20,.4)}
.scene{position:absolute;inset:0;padding:4.5cqw 6cqw;display:flex;flex-direction:column;justify-content:center;opacity:0;visibility:hidden;transition:opacity .35s;color:#fff;
background-color:#0D1321;background-image:linear-gradient(#17213C .12cqw,transparent .12cqw),linear-gradient(90deg,#17213C .12cqw,transparent .12cqw);background-size:3cqw 3cqw}
.scene.active{opacity:1;visibility:visible}
.last{background:#22D3EE;background-image:none;color:#0D1321;align-items:center;text-align:center}
h1,h2,p{margin:0}
h1{font-family:Sora,sans-serif;font-weight:800;font-size:5.6cqw;line-height:1.04;letter-spacing:-.03em;max-width:10em}
h2{font-family:Sora,sans-serif;font-weight:800;font-size:3.6cqw;line-height:1.1;letter-spacing:-.02em;margin-bottom:2.2cqw}
.sub{font-size:2.2cqw;font-weight:500;margin-top:2cqw;max-width:24em;line-height:1.4;color:#B9C7E3}
.rise{opacity:0}
.active .rise{animation:in .5s cubic-bezier(.2,.8,.2,1) both;animation-delay:var(--d,0s)}
@keyframes in{from{opacity:0;transform:translateY(2cqw)}to{opacity:1;transform:none}}
.mono{font-family:"Red Hat Mono",ui-monospace,monospace}
.card{background:#141C33;border:.2cqw solid #25304F;border-radius:1.6cqw}
.tag{display:inline-block;color:#22D3EE;font-weight:700;font-size:1.8cqw;letter-spacing:.12em;text-transform:uppercase;margin-bottom:1.6cqw}
/* radar */
.radar{position:absolute;right:7cqw;top:50%;margin-top:-16cqw;width:32cqw;height:32cqw;border-radius:50%;border:.25cqw solid #22D3EE;background:repeating-radial-gradient(circle,transparent 0 5.2cqw,rgba(34,211,238,.35) 5.3cqw 5.5cqw)}
.radar::before{content:"";position:absolute;inset:0;border-radius:50%;background:conic-gradient(from 0deg,rgba(34,211,238,.55),transparent 28%);animation:spin 3s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.blip{position:absolute;width:2cqw;height:2cqw;border-radius:50%;background:var(--c);box-shadow:0 0 0 0 var(--c);animation:ping 1.8s ease-out infinite;animation-delay:var(--d)}
@keyframes ping{0%{box-shadow:0 0 0 0 var(--c);opacity:1}100%{box-shadow:0 0 0 2.4cqw transparent;opacity:.7}}
/* scan */
.url{display:flex;align-items:center;gap:2cqw;padding:1.6cqw 2.4cqw;width:fit-content;font-size:2.6cqw}
.type{display:inline-block;width:0;overflow:hidden;white-space:nowrap;vertical-align:bottom}
.active .type{animation:tp 1.5s steps(21) .4s forwards}
@keyframes tp{to{width:21ch}}
.go{background:#22D3EE;color:#0D1321;font-weight:700;border-radius:1cqw;padding:.8cqw 2cqw;font-family:Outfit,sans-serif;font-size:2.2cqw}
.chk{display:grid;grid-template-columns:1fr 1fr;gap:1.4cqw 3cqw;margin-top:2.4cqw}
.it{display:flex;align-items:center;gap:1.4cqw;font-size:2.1cqw;font-weight:500}
.it b{flex:none;width:3.2cqw;height:3.2cqw;border-radius:50%;background:#25304F;color:transparent;display:grid;place-items:center;font-size:2cqw}
.active .it b{animation:ok .3s forwards;animation-delay:calc(var(--d) + .6s)}
@keyframes ok{to{background:#06D6A0;color:#0D1321}}
.prog{height:1.2cqw;background:#25304F;border-radius:2cqw;margin-top:2.6cqw;overflow:hidden}
.prog i{display:block;height:100%;width:100%;background:linear-gradient(90deg,#22D3EE,#06D6A0);transform-origin:left;transform:scaleX(0)}
.active .prog i{animation:fill 5s linear 1.4s forwards}
@keyframes fill{to{transform:none}}
/* rings */
.rings{display:grid;grid-template-columns:repeat(3,1fr);gap:2.4cqw}
.pil{padding:2.2cqw;text-align:center}
.ring{position:relative;width:17cqw;height:17cqw;margin:0 auto 1.4cqw}
.ring svg{width:100%;height:100%;transform:rotate(-90deg)}
.ring circle{fill:none;stroke-width:3.4}
.ring .bg{stroke:#25304F}
.ring .fg{stroke:var(--c);stroke-linecap:round;stroke-dasharray:100;stroke-dashoffset:100}
.active .ring .fg{animation:rg 1.6s ease-out forwards;animation-delay:var(--d)}
@keyframes rg{to{stroke-dashoffset:var(--o)}}
.ring span{position:absolute;inset:0;display:grid;place-items:center;font:800 4.6cqw Sora,sans-serif}
.pil b{display:block;font:800 2.5cqw Sora,sans-serif;margin-bottom:.8cqw}
.pil small{font-size:1.7cqw;color:#B9C7E3;line-height:1.4;display:block}
.note{font-size:1.6cqw;color:#8CA0C4;margin-top:1.6cqw}
/* findings */
.rows{display:flex;flex-direction:column;gap:1.1cqw}
.row{display:flex;align-items:center;gap:1.8cqw;padding:1cqw 1.8cqw}
.sev{flex:none;width:11cqw;text-align:center;border-radius:5cqw;padding:.4cqw 0;font-weight:700;font-size:1.5cqw;letter-spacing:.08em;color:#0D1321;background:var(--c)}
.row b{font-size:2.1cqw;font-weight:700;flex:1}
.row span.mono{font-size:1.6cqw;color:#8CA0C4}
/* ai */
.three{display:grid;grid-template-columns:1fr 1.1fr 1fr;gap:2cqw}
.three .card{padding:2cqw}
.three h3{margin:0 0 1.2cqw;font:700 2.2cqw Sora,sans-serif;color:#22D3EE}
.three p{font-size:1.9cqw;line-height:1.45;color:#D6E0F5}
.codeb{background:#070B14;border-radius:1cqw;padding:1.4cqw;font-size:1.45cqw;line-height:1.55;color:#06D6A0;white-space:pre-wrap}
.wk{display:flex;gap:1.2cqw;align-items:center;margin-bottom:1.1cqw;font-size:1.9cqw}
.wk b{flex:none;border-radius:5cqw;padding:.3cqw 1.2cqw;color:#0D1321;font-weight:700;font-size:1.6cqw}
/* benefits */
.who{display:grid;grid-template-columns:1fr 1fr;gap:2cqw}
.who div{border-radius:1.8cqw;padding:2.2cqw 2.6cqw;color:#0D1321;background:var(--c)}
.who b{display:block;font:800 2.8cqw Sora,sans-serif;margin-bottom:.6cqw}
.who span{font-size:2cqw;font-weight:500;line-height:1.35}
/* outro */
.word{font:800 8.6cqw/1 Sora,sans-serif;letter-spacing:-.04em}
.last .sub{color:#0D1321}
.stack{display:flex;gap:1.4cqw;justify-content:center;margin-top:3cqw;flex-wrap:wrap}
.stack span{background:#0D1321;color:#fff;border-radius:5cqw;padding:.9cqw 2.2cqw;font-weight:700;font-size:2cqw}
.bar{display:flex;gap:6px;margin-top:12px}
.seg{flex:1;height:6px;background:var(--line);border-radius:4px;overflow:hidden;cursor:pointer;border:0;padding:0}
.seg i{display:block;height:100%;width:0;background:#22D3EE}
.ctl{display:flex;align-items:center;gap:12px;margin-top:10px;color:var(--mute);font-size:14px}
.ctl button{font:inherit;font-weight:700;background:#0D1321;color:#fff;border:0;border-radius:8px;padding:8px 16px;cursor:pointer}
@media (prefers-color-scheme:dark){.ctl button{background:#22D3EE;color:#0D1321}}
button:focus-visible{outline:3px solid var(--org);outline-offset:2px}
@media (prefers-reduced-motion:reduce){.rise{opacity:1!important}.active .rise,.active .it b,.active .prog i,.active .ring .fg{animation:none!important}.type{width:auto!important;animation:none!important}.radar::before,.blip{animation:none}.it b{background:#06D6A0;color:#0D1321}.prog i{transform:none}.ring .fg{stroke-dashoffset:var(--o)}}
</style>
</head>
<body>
<div class="wrap">
 <div class="stage" aria-label="SiteAudit Pro product video">

  <section class="scene">
   <span class="tag rise">SiteAudit Pro</span>
   <h1 class="rise" style="--d:.2s">Every website has blind spots.</h1>
   <p class="sub rise" style="--d:.6s">SiteAudit Pro finds them. AI explains how to fix them.</p>
   <div class="radar rise" style="--d:.3s">
    <i class="blip" style="--c:#FF4D6D;left:62%;top:24%;--d:.2s"></i>
    <i class="blip" style="--c:#FF9F1C;left:26%;top:34%;--d:1s"></i>
    <i class="blip" style="--c:#FFD166;left:70%;top:62%;--d:1.6s"></i>
    <i class="blip" style="--c:#06D6A0;left:38%;top:72%;--d:.6s"></i>
    <i class="blip" style="--c:#FF4D6D;left:44%;top:46%;--d:1.2s"></i>
   </div>
  </section>

  <section class="scene">
   <h2 class="rise">Paste a URL. Start the scan.</h2>
   <div class="card url mono rise" style="--d:.2s"><span class="type">https://yoursite.com</span><span class="go">Analyze</span></div>
   <div class="chk">
    <div class="it rise" style="--d:1.4s"><b>✓</b>Transport security</div>
    <div class="it rise" style="--d:2.2s"><b>✓</b>Security headers and cookies</div>
    <div class="it rise" style="--d:3s"><b>✓</b>Injection and XSS patterns</div>
    <div class="it rise" style="--d:3.8s"><b>✓</b>Sensitive file exposure</div>
    <div class="it rise" style="--d:4.6s"><b>✓</b>Accessibility and SEO</div>
    <div class="it rise" style="--d:5.4s"><b>✓</b>Performance and caching</div>
   </div>
   <div class="prog"><i></i></div>
  </section>

  <section class="scene">
   <h2 class="rise">One scan. Three scores.</h2>
   <div class="rings">
    <div class="card pil rise" style="--d:.2s"><div class="ring"><svg viewBox="0 0 36 36"><circle class="bg" cx="18" cy="18" r="15.9" pathLength="100"/><circle class="fg" cx="18" cy="18" r="15.9" pathLength="100" style="--c:#FF9F1C;--o:38;--d:.5s"/></svg><span>62</span></div><b>Security</b><small>TLS, headers, cookies, XSS, CSRF, CORS</small></div>
    <div class="card pil rise" style="--d:.4s"><div class="ring"><svg viewBox="0 0 36 36"><circle class="bg" cx="18" cy="18" r="15.9" pathLength="100"/><circle class="fg" cx="18" cy="18" r="15.9" pathLength="100" style="--c:#22D3EE;--o:22;--d:.7s"/></svg><span>78</span></div><b>UI/UX</b><small>Accessibility, SEO, responsive, forms</small></div>
    <div class="card pil rise" style="--d:.6s"><div class="ring"><svg viewBox="0 0 36 36"><circle class="bg" cx="18" cy="18" r="15.9" pathLength="100"/><circle class="fg" cx="18" cy="18" r="15.9" pathLength="100" style="--c:#06D6A0;--o:29;--d:.9s"/></svg><span>71</span></div><b>Performance</b><small>Assets, render path, caching, loading</small></div>
   </div>
   <p class="note rise" style="--d:2s">Sample scores for illustration.</p>
  </section>

  <section class="scene">
   <h2 class="rise">Findings, ranked by severity.</h2>
   <div class="rows">
    <div class="card row rise" style="--d:.3s"><span class="sev" style="--c:#FF4D6D;color:#fff">CRITICAL</span><b>Sensitive file exposed</b><span class="mono">GET /.env → 200</span></div>
    <div class="card row rise" style="--d:.8s"><span class="sev" style="--c:#FF9F1C">HIGH</span><b>No Content-Security-Policy header</b><span class="mono">response headers</span></div>
    <div class="card row rise" style="--d:1.3s"><span class="sev" style="--c:#FF9F1C">HIGH</span><b>Cookie missing HttpOnly flag</b><span class="mono">Set-Cookie: session</span></div>
    <div class="card row rise" style="--d:1.8s"><span class="sev" style="--c:#FFD166">MEDIUM</span><b>Images without alt text</b><span class="mono">&lt;img&gt; ×14</span></div>
    <div class="card row rise" style="--d:2.3s"><span class="sev" style="--c:#FFD166">MEDIUM</span><b>No gzip or brotli compression</b><span class="mono">main.js</span></div>
    <div class="card row rise" style="--d:2.8s"><span class="sev" style="--c:#06D6A0">LOW</span><b>Missing lang attribute</b><span class="mono">&lt;html&gt;</span></div>
   </div>
  </section>

  <section class="scene">
   <h2 class="rise">Not just detection. A way forward.</h2>
   <div class="three">
    <div class="card rise" style="--d:.3s"><h3>Exploit scenario</h3><p>Anyone can download your .env file, read the database password and sign in as your app. Customer data and brand trust are at risk.</p></div>
    <div class="card rise" style="--d:1s"><h3>Remediation</h3><div class="codeb mono"># nginx
location ~ /\.(env|git) { deny all; }
add_header Content-Security-Policy
  "default-src 'self'";</div></div>
    <div class="card rise" style="--d:1.7s"><h3>3-week roadmap</h3>
     <div class="wk"><b style="background:#FF4D6D;color:#fff">Week 1</b>Critical fixes</div>
     <div class="wk"><b style="background:#FF9F1C">Week 2</b>High-severity hardening</div>
     <div class="wk"><b style="background:#06D6A0">Week 3</b>UX and performance</div>
    </div>
   </div>
  </section>

  <section class="scene">
   <h2 class="rise">Built for every team.</h2>
   <div class="who">
    <div class="rise" style="--c:#22D3EE;--d:.3s"><b>Developers</b><span>Catch vulnerabilities before deployment, with specific code fixes.</span></div>
    <div class="rise" style="--c:#FFD166;--d:.8s"><b>Security teams</b><span>Attack-surface mapping in one scan. OWASP Top 10 and beyond.</span></div>
    <div class="rise" style="--c:#FF9F9F;--d:1.3s"><b>Business owners</b><span>Protect customer data and brand. No security expertise needed.</span></div>
    <div class="rise" style="--c:#06D6A0;--d:1.8s"><b>DevOps</b><span>CI/CD-ready via API. Cut manual audit time by 80%+.</span></div>
   </div>
  </section>

  <section class="scene last">
   <div class="word rise">SiteAudit Pro</div>
   <p class="sub rise" style="--d:.4s;max-width:none">Audit smarter. Fix faster.</p>
   <div class="stack rise" style="--d:.8s"><span>Security</span><span>UI/UX</span><span>Performance</span><span>AI Insights</span></div>
  </section>

 </div>
 <div class="bar" id="bar"></div>
 <div class="ctl"><button id="pp" type="button">Pause</button><button id="rs" type="button">Replay</button><span id="time"></span></div>
</div>
<script>
(function(){
var scenes=[].slice.call(document.querySelectorAll('.scene'));
var D=[5000,8500,6000,7000,7000,6000,5000];
var total=D.reduce(function(a,b){return a+b},0);
var reduce=window.matchMedia('(prefers-reduced-motion: reduce)').matches;
var t=0,playing=!reduce,cur=-1,last=performance.now();
var bar=document.getElementById('bar'),segs=[],pp=document.getElementById('pp');
function start(i){return D.slice(0,i).reduce(function(a,b){return a+b},0)}
D.forEach(function(_,i){var b=document.createElement('button');b.className='seg';b.setAttribute('aria-label','Go to scene '+(i+1));b.innerHTML='<i></i>';b.onclick=function(){seek(start(i))};bar.appendChild(b);segs.push(b.firstChild)});
function enter(i){cur=i;scenes.forEach(function(s,k){s.classList.remove('active');if(k===i){void s.offsetWidth;s.classList.add('active')}})}
function idx(){var s=0;for(var i=0;i<D.length;i++){s+=D[i];if(t<s)return i}return D.length-1}
function seek(ms){t=Math.max(0,Math.min(ms,total-1));enter(idx())}
function fmt(ms){var s=Math.floor(ms/1000);return '0:'+(s<10?'0':'')+s}
function tick(now){
 var dt=now-last;last=now;
 if(playing){t+=dt;if(t>=total){t=total-1;playing=false;pp.textContent='Play'}}
 var i=idx();if(i!==cur)enter(i);
 segs.forEach(function(s,k){var f=k<i?1:k>i?0:(t-start(k))/D[k];s.style.width=(f*100)+'%'});
 document.getElementById('time').textContent=fmt(t)+' / '+fmt(total);
 requestAnimationFrame(tick)
}
pp.textContent=playing?'Pause':'Play';
pp.onclick=function(){if(!playing&&t>=total-1){seek(0)}playing=!playing;pp.textContent=playing?'Pause':'Play'};
document.getElementById('rs').onclick=function(){seek(0);playing=true;pp.textContent='Pause'};
enter(0);requestAnimationFrame(tick);
})();
</script>
</body>
</html>


## What is SiteAudit Pro?

SiteAudit Pro is a comprehensive web analysis platform that helps developers, security researchers, and business owners identify vulnerabilities, usability flaws, and performance bottlenecks in any website. By combining static analysis with advanced AI reasoning, it delivers not just detection—but prioritized, actionable remediation guidance.

## Key Features

### Deep Security Auditing
- **Transport Security**: HTTPS enforcement, TLS version checks, HSTS validation, mixed content detection
- **Security Headers**: Validates 9+ headers including CSP, X-Frame-Options, X-Content-Type-Options, COOP, COEP
- **Cookie Security**: Secure, HttpOnly, SameSite flag auditing
- **Injection Detection**: Pattern-based SQL injection, XXE, and SSRF vector identification
- **XSS Protection**: Detects eval(), innerHTML, document.write(), inline event handlers, and dangerous DOM sinks
- **CSRF Validation**: Detects unprotected state-changing forms
- **CORS Analysis**: Flags wildcard origins, credential misconfigurations
- **Sensitive File Exposure**: Checks for 25+ sensitive files (.git, .env, wp-config.php, etc.)
- **Supply Chain Security**: Subresource integrity checks, outdated library detection
- **Clickjacking & MIME Sniffing**: Frame-ancestors and nosniff validation
- **Debug Information**: Detects exposed stack traces, error reporting, and debug flags

### Advanced UI/UX Analysis
- **Responsive Design**: Viewport validation, zoom-accessibility checks
- **Accessibility**: Alt text, heading hierarchy, skip navigation, form labels, ARIA attributes, table headers
- **SEO Fundamentals**: Title/meta description length, H1 structure, charset, language attributes
- **Semantic HTML**: Detects deprecated tags, empty interactive elements, placeholder-only labels
- **Form Usability**: Autocomplete attributes, password field configuration, GET-method sensitive forms

### Performance Engineering
- **Asset Optimization**: Page size, compression (gzip/brotli), image dimensions, modern formats (WebP/AVIF)
- **Render Path**: Render-blocking CSS/JS, DOM size/depth, iframe count, resource hints
- **Caching Strategy**: Cache-Control, ETag/Last-Modified validation
- **Loading Performance**: Lazy loading detection, redirect chains, request count, font loading strategy
- **Code Quality**: Unminified JavaScript detection

### AI-Powered Insights
- **Structured Reports**: Overall health assessment, critical actions, deep dive analysis
- **Exploit Scenarios**: Plain-language explanations of attack vectors and business impact
- **Implementation Roadmap**: 3-week prioritized action plan
- **Remediation Guidance**: Specific code/config examples for each fix

### Professional User Experience
- **Dark Theme UI**: Modern, professional interface optimized for long analysis sessions
- **Real-time Progress**: Animated loading states with step-by-step analysis indicators
- **Interactive Dashboard**: Animated score rings, severity badges, tabbed findings
- **Responsive Design**: Works seamlessly on desktop, tablet, and mobile

## Benefits

### For Developers
- Catch security vulnerabilities before deployment
- Get specific code fixes, not just generic warnings
- Learn security best practices through AI explanations
- Reduce debugging time with prioritized issue lists

### For Security Teams
- Comprehensive attack-surface mapping in one scan
- Covers OWASP Top 10 and beyond
- Evidence-based findings with exact locations
- Compliance-ready reporting format

### For Business Owners
- Protect customer data and brand reputation
- Identify performance issues affecting SEO and conversions
- Get clear ROI-focused remediation roadmaps
- No security expertise required to understand results

### For DevOps/DevSecOps
- Integrate into CI/CD pipelines via API
- Fast, automated security gate checks
- Consistent, repeatable analysis
- Reduce manual audit time by 80%+

## Why Choose SiteAudit Pro?

| Aspect | Traditional Tools | SiteAudit Pro |
|--------|------------------|---------------|
| Analysis Depth | Surface-level checks | 50+ deep checks |
| Output | Generic warnings | Structured, prioritized action plans |
| AI Integration | None | Llama 3.3 70B reasoning |
| Accessibility | Paid tiers | Included |
| Setup | Complex, enterprise-only | 5-minute setup |
| Cost | $100-1000/month | Free (API costs only) |

## Use Cases

1. **Pre-Launch Security Review**: Scan your site before going live
2. **Competitive Analysis**: Compare security posture with competitors
3. **Compliance Auditing**: Identify gaps in security headers and data protection
4. **Performance Optimization**: Find bottlenecks affecting Core Web Vitals
5. **Accessibility Auditing**: Ensure WCAG compliance
6. **Learning Tool**: Understand web security through real-world examples
