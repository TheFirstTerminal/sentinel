// The download page: Free from the public GitHub release, Pro from
// https://dl.tft.markets after the license key is checked. English and Arabic.
"use strict";
(function () {
  const AR = document.documentElement.lang === "ar";
  const T = AR ? {
    loading: "ديجيب آخر نسخة…", failed: "ما گدرنا نجيب قائمة الملفات. نزّل من صفحة الإصدارات بـ GitHub:", releases: "الإصدارات على GitHub",
    version: (v) => "النسخة " + v, foryou: "لجهازك", checking: "ديتحقق من المفتاح…", nokey: "الصق مفتاح الترخيص أول.",
    hello: (c, e) => "أهلاً " + c + ". المفتاح صالح لحد " + e + ". الروابط تشتغل 10 دقايق.", neterr: "ما گدرنا نوصل لخادم التنزيل. جرّب مرة ثانية.",
  } : {
    loading: "Getting the latest version…", failed: "Couldn't load the file list. Download from the GitHub releases page:", releases: "Releases on GitHub",
    version: (v) => "Version " + v, foryou: "For this computer", checking: "Checking your key…", nokey: "Paste your license key first.",
    hello: (c, e) => "Hello " + c + ". Your key is valid until " + e + ". The links work for 10 minutes.", neterr: "Couldn't reach the download server. Try again.",
  };
  const KINDS = [
    [/windows-amd64\.exe$/, "Windows", "x64", "win"],
    [/darwin-arm64$/, "macOS", AR ? "Apple (M1 وأحدث)" : "Apple silicon (M1 and later)", "macarm"],
    [/darwin-amd64$/, "macOS", "Intel", "macintel"],
    [/linux-amd64$/, "Linux", "x64", "linux"],
    [/linux-arm64$/, "Linux", "ARM64", "linuxarm"],
    [/_amd64\.deb$/, AR ? "حزمة Debian / Ubuntu" : "Debian / Ubuntu package", "x64 .deb", "linux"],
    [/_arm64\.deb$/, AR ? "حزمة Debian / Ubuntu" : "Debian / Ubuntu package", "ARM64 .deb", "linuxarm"],
    [/x86_64\.rpm$/, AR ? "حزمة RHEL / Fedora" : "RHEL / Fedora package", "x64 .rpm", "linux"],
    [/aarch64\.rpm$/, AR ? "حزمة RHEL / Fedora" : "RHEL / Fedora package", "ARM64 .rpm", "linuxarm"],
    [/docker-amd64\.tar\.gz$/, AR ? "صورة Docker" : "Docker image", AR ? "x64، تتحمل بـ docker load" : "x64, for docker load", "docker"],
    [/docker-arm64\.tar\.gz$/, AR ? "صورة Docker" : "Docker image", AR ? "ARM64، تتحمل بـ docker load" : "ARM64, for docker load", "docker"],
    [/^checksums\.txt$/, AR ? "قائمة التحقق" : "Checksums", "SHA-256", "extra"],
    [/^checksums\.txt\.sigstore\.json$/, AR ? "توقيع قائمة التحقق" : "Checksums signature", "Sigstore", "extra"],
    [/sbom\.spdx\.json$/, AR ? "قائمة المكونات (SBOM)" : "Software bill of materials", "SPDX", "extra"],
  ];
  function myOS() {
    const ua = navigator.userAgent, p = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || "";
    if (/Win/i.test(p) || /Windows/.test(ua)) return "win";
    if (/Mac/i.test(p) || /Mac OS X/.test(ua)) return "macarm"; // browsers no longer say which Mac; most new ones are Apple silicon
    if (/Linux/i.test(p)) return /aarch64|arm/i.test(ua) ? "linuxarm" : "linux";
    return "";
  }
  const size = (n) => n > 1e6 ? (n / 1e6).toFixed(1) + " MB" : Math.max(1, Math.round(n / 1e3)) + " KB";
  const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  function render(el, files) { // files: [{name, size, url}]
    const os = myOS(), rows = [];
    for (const f of files) {
      const k = KINDS.find((k) => k[0].test(f.name));
      if (!k) continue;
      rows.push({ f, k, mine: k[3] === os && !/\.(deb|rpm)$/.test(f.name) });
    }
    rows.sort((a, b) => (b.mine - a.mine) || (KINDS.indexOf(a.k) - KINDS.indexOf(b.k)));
    el.innerHTML = rows.map(({ f, k, mine }) =>
      '<a class="dl' + (mine ? " mine" : "") + (k[3] === "extra" ? " extra" : "") + '" href="' + esc(f.url) + '" download>' +
      '<b>' + esc(k[1]) + '</b><span>' + esc(k[2]) + (f.size ? " · " + size(f.size) : "") + '</span>' +
      (mine ? '<em class="tft-status live">' + esc(T.foryou) + '</em>' : "") + '<code dir="ltr">' + esc(f.name) + '</code></a>').join("");
  }

  // Free: the newest public release on GitHub.
  const free = document.getElementById("free-files"), freeV = document.getElementById("free-version");
  free.textContent = T.loading;
  fetch("https://api.github.com/repos/TheFirstTerminal/sentinel/releases/latest")
    .then((r) => r.ok ? r.json() : Promise.reject(r.status))
    .then((rel) => {
      freeV.textContent = T.version(rel.tag_name.replace(/^v/, ""));
      render(free, rel.assets.map((a) => ({ name: a.name, size: a.size, url: a.browser_download_url })));
    })
    .catch(() => {
      free.innerHTML = esc(T.failed) + ' <a href="https://github.com/TheFirstTerminal/sentinel/releases/latest">' + esc(T.releases) + "</a>";
    });

  // Pro: the key goes to dl.tft.markets, which answers with short-lived links.
  const form = document.getElementById("pro-form"), msg = document.getElementById("pro-msg"), pro = document.getElementById("pro-files");
  form.onsubmit = async (e) => {
    e.preventDefault();
    const key = document.getElementById("pro-key").value.trim();
    pro.innerHTML = "";
    if (!key) { msg.textContent = T.nokey; return; }
    msg.textContent = T.checking;
    try {
      const r = await fetch("https://dl.tft.markets/sentinel/pro/links", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ key }) });
      const out = await r.json();
      if (!r.ok) { msg.textContent = out.error || ("HTTP " + r.status); return; }
      msg.textContent = T.hello(out.customer, out.expires.slice(0, 10)) + " " + T.version(out.version) + ".";
      render(pro, out.links);
    } catch (x) { msg.textContent = T.neterr; }
  };
})();
