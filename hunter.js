(function() {
    const LOG_STYLE = "background: #d32f2f; color: #fff; font-weight: bold; padding: 2px 5px; border-radius: 3px;";
    const PARAM_STYLE = "color: #fbc02d; font-weight: bold;";
    
    console.log("%c[HUNTER V2] Full-Spectrum Sniffer Active", "color: orange; font-weight: bold; font-size: 12px;");

    // --- CONFIGURATION ---
    // Daftar kata kunci diperluas
    const SUSPICIOUS_KEYS = [
        "sign", "signature", "bogus", "token", "auth", "key", "hash", "md5", "ticket", 
        "csrf", "xsrf", "bearer", "authorization", "client_id", "w_rid", "authenticity"
    ];

    // --- UTILS: Recursive Scanner ---
    // Fungsi untuk mencari jarum di tumpukan jerami (JSON Object yang dalam)
    function scanObject(sourceType, sourceUrl, obj, path = "") {
        if (!obj || typeof obj !== 'object') return;

        for (const key in obj) {
            const value = obj[key];
            const currentPath = path ? `${path}.${key}` : key;
            const lowerKey = key.toLowerCase();

            // Cek apakah Key mencurigakan
            const isSuspiciousKey = SUSPICIOUS_KEYS.some(k => lowerKey.includes(k));
            
            // Cek Value (String panjang acak)
            let isSuspiciousValue = false;
            if (typeof value === 'string') {
                isSuspiciousValue = value.length > 20 && !value.includes(" ") && !value.includes("<html");
            }

            if (isSuspiciousKey || isSuspiciousValue) {
                printDetection(sourceType, sourceUrl, currentPath, value);
            }

            // Jika value adalah object/array, gali lebih dalam (Recursion)
            if (typeof value === 'object') {
                scanObject(sourceType, sourceUrl, value, currentPath);
            }
        }
    }

    function printDetection(type, url, key, value) {
        // Debounce: Jangan spam log untuk value yang sama berulang kali
        const cacheKey = `${url}-${key}`;
        if (window._hunterCache && window._hunterCache.has(cacheKey)) return;
        if (!window._hunterCache) window._hunterCache = new Set();
        window._hunterCache.add(cacheKey);

        console.groupCollapsed(`%c[HUNTER] 🎯 ${type}: ${key}`, LOG_STYLE);
        console.log(`%cURL:`, "font-weight:bold", url);
        console.log(`%cValue:`, PARAM_STYLE, value);
        console.warn("STACK TRACE (Siapa pelakunya?):");
        console.trace(); 
        console.groupEnd();
    }

    // --- 1. HOOK FETCH (URL + BODY + HEADERS) ---
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        const url = args[0] instanceof Request ? args[0].url : args[0];
        const options = args[1];

        // A. Cek URL Params
        analyzeUrl("FETCH (URL)", url);

        // B. Cek Body (JSON Payload)
        if (options && options.body) {
            try {
                const jsonBody = JSON.parse(options.body);
                scanObject("FETCH (BODY)", url, jsonBody);
            } catch (e) { /* Not JSON */ }
        }

        // C. Cek Headers
        if (options && options.headers) {
            // Headers bisa berupa Object atau Headers object
            const headers = options.headers instanceof Headers ? Object.fromEntries(options.headers.entries()) : options.headers;
            scanObject("FETCH (HEADER)", url, headers);
        }

        return originalFetch.apply(this, args);
    };

    // --- 2. HOOK XHR (AJAX LAMA) ---
    const originalXHROpen = window.XMLHttpRequest.prototype.open;
    const originalXHRSend = window.XMLHttpRequest.prototype.send;
    const originalXHRSetHeader = window.XMLHttpRequest.prototype.setRequestHeader;

    // Hook Open (Untuk URL)
    window.XMLHttpRequest.prototype.open = function(method, url, ...rest) {
        this._hunterUrl = url; // Simpan URL untuk dipakai di send()
        analyzeUrl("XHR (URL)", url);
        return originalXHROpen.call(this, method, url, ...rest);
    };

    // Hook SetRequestHeader (Untuk Header)
    window.XMLHttpRequest.prototype.setRequestHeader = function(header, value) {
        scanObject("XHR (HEADER)", this._hunterUrl, { [header]: value });
        return originalXHRSetHeader.call(this, header, value);
    };

    // Hook Send (Untuk Body)
    window.XMLHttpRequest.prototype.send = function(body) {
        if (body && typeof body === 'string') {
            try {
                const jsonBody = JSON.parse(body);
                scanObject("XHR (BODY)", this._hunterUrl, jsonBody);
            } catch (e) { /* Not JSON */ }
        }
        return originalXHRSend.call(this, body);
    };

    // --- 3. URL ANALYZER (Legacy) ---
    function analyzeUrl(type, urlString) {
        try {
            if (urlString.match(/\.(png|jpg|css|js|svg|woff)/)) return;
            const url = new URL(urlString, window.location.origin);
            const params = new URLSearchParams(url.search);
            const paramsObj = {};
            params.forEach((v, k) => paramsObj[k] = v);
            scanObject(type, urlString, paramsObj);
        } catch (e) {}
    }

})();