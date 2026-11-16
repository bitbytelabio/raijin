/* ==============================================================
   Raijin Dashboard v2.0 - Interactive Bug Bounty Dashboard
   ============================================================== */

// ---- Noise filtering ----
var NOISE_DOMAINS = ['googleapis.com','gstatic.com','google.com/gen_204','generate_204',
    'detectportal','captive.apple','msftconnecttest','connectivity','ocsp.','crl.',
    'safebrowsing','update.googleapis','chrome-devtools','accounts.google','clients1.google',
    'play.google','fonts.googleapis','ajax.googleapis','maps.googleapis','translate.google',
    'ssl.gstatic','encrypted-tbn','beacons','analytics','doubleclick','googlesyndication',
    'googletagmanager','facebook.com/tr','bat.bing','clarity.ms'];

function isNoise(url) {
    if (!url) return false;
    var lower = url.toLowerCase();
    for (var i = 0; i < NOISE_DOMAINS.length; i++) {
        if (lower.indexOf(NOISE_DOMAINS[i]) !== -1) return true;
    }
    return false;
}

// ---- Attack vector detection ----
function detectVectors(url, method, contentType, statusCode, headers) {
    var vectors = [];
    var u = (url || '').toLowerCase();
    var ct = (contentType || '').toLowerCase();
    var m = (method || '').toUpperCase();
    var hdrs = (headers || '').toLowerCase();

    // AUTH
    if (/\/(login|auth|oauth|token|session|signin|signup|register|logout|password|reset|sso|saml|jwt|api-key|apikey)/.test(u)
        || hdrs.indexOf('authorization') !== -1 || hdrs.indexOf('x-api-key') !== -1
        || hdrs.indexOf('x-auth-token') !== -1) {
        vectors.push('auth');
    }
    // API
    if (/\/(api|v[0-9]+|graphql|rest|jsonrpc|grpc|webhook)[\/?]/.test(u)
        || ct.indexOf('application/json') !== -1 || ct.indexOf('application/graphql') !== -1
        || ct.indexOf('application/xml') !== -1) {
        vectors.push('api');
    }
    // PARAMS
    if (u.indexOf('?') !== -1 || (m === 'POST' || m === 'PUT' || m === 'PATCH')) {
        vectors.push('params');
    }
    // UPLOAD
    if (ct.indexOf('multipart/form-data') !== -1 || /\/(upload|import|attach|file)/.test(u)) {
        vectors.push('upload');
    }
    // ADMIN
    if (/\/(admin|manage|dashboard|console|debug|config|settings|internal|_admin|phpmy|phpmyadmin|wp-admin|cpanel)/.test(u)) {
        vectors.push('admin');
    }
    // DATA
    if (/\/(export|download|backup|dump|report|csv|xlsx)/.test(u)
        || /\.(sql|csv|json|xml|xlsx|xls|bak|zip|tar|gz|dump)(\?|$)/.test(u)) {
        vectors.push('data');
    }
    return vectors;
}

// ---- State ----
var events = [];
var MAX_EVENTS = 1000;
var noiseHidden = localStorage.getItem('raijin_noise') !== 'show';
var activeFilter = 'all';
var searchQuery = '';
var selectedEventId = null;
var counters = {events:0,scope:0,api:0,auth:0,params:0,upload:0,admin:0,data:0,findings:0,hidden:0,toolCalls:0};
var knownHosts = {};

// ---- DOM refs ----
var elList = document.getElementById('activityList');
var elDetail = document.getElementById('detailPanel');
var elDetailInner = document.getElementById('detailInner');
var elSearch = document.getElementById('searchBox');
var elToast = document.getElementById('toast');

// ---- Noise toggle ----
function toggleNoise() {
    noiseHidden = !noiseHidden;
    localStorage.setItem('raijin_noise', noiseHidden ? 'hide' : 'show');
    var btn = document.getElementById('noiseToggle');
    if (noiseHidden) btn.classList.add('active'); else btn.classList.remove('active');
    renderList();
}
document.getElementById('noiseToggle').classList.toggle('active', noiseHidden);

// ---- Tab switching ----
document.getElementById('tabNav').addEventListener('click', function(e) {
    var btn = e.target.closest('.filter-btn');
    if (!btn) return;
    var tab = btn.dataset.tab;
    document.querySelectorAll('#tabNav .filter-btn').forEach(function(b){b.classList.remove('active');});
    btn.classList.add('active');
    document.querySelectorAll('.tab-panel').forEach(function(p){p.classList.remove('active');});
    var panel = document.getElementById('panel-' + tab);
    if (panel) panel.classList.add('active');
    if (tab === 'rules') fetchRules();
});

// ---- Type filter ----
document.getElementById('typeFilter').addEventListener('click', function(e) {
    var btn = e.target.closest('.filter-btn');
    if (!btn) return;
    activeFilter = btn.dataset.filter;
    document.querySelectorAll('#typeFilter .filter-btn').forEach(function(b){b.classList.remove('active');});
    btn.classList.add('active');
    renderList();
});

// ---- Search ----
var searchTimer = null;
elSearch.addEventListener('input', function() {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(function() {
        searchQuery = elSearch.value.toLowerCase().trim();
        renderList();
    }, 150);
});

// ---- Add event ----
function addEvent(type, data, timestamp) {
    var ts = timestamp || new Date().toISOString();
    var time = new Date(ts);
    var timeStr = time.toLocaleTimeString('en-US', {hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});

    var url = '', method = '', host = '', statusCode = 0, contentType = '', headersStr = '';
    var inScope = false, messageId = 0, mimeType = '';

    if (typeof data === 'object' && data !== null) {
        url = data.url || '';
        method = data.method || '';
        host = data.host || '';
        statusCode = data.status_code || 0;
        contentType = data.content_type || data.mime_type || mimeType || '';
        inScope = data.in_scope || false;
        messageId = data.message_id || 0;
        mimeType = data.mime_type || '';

        // For tool.called events, extract tool name as method-like display
        if (type === 'tool.called') {
            var toolName = data.tool_name || '';
            if (!method) method = toolName;
            if (!url && data.arguments) {
                url = data.arguments.url || data.arguments.raw_request || '';
                if (url.length > 100) url = url.substring(0, 100) + '...';
            }
            if (!host && data.arguments && data.arguments.host) host = data.arguments.host;
        }
    }

    var isNoisy = isNoise(url);
    var cat = mapTypeToCategory(type);
    var vectors = (cat === 'proxy' || cat === 'tool') ? detectVectors(url, method, contentType, statusCode, headersStr) : [];

    // Extract path
    var pathDisplay = url;
    try {
        if (url.indexOf('://') !== -1) {
            var u = new URL(url);
            pathDisplay = u.pathname + u.search;
            if (!host) host = u.hostname;
        }
    } catch(ex) {}

    // Build label for non-proxy events
    var label = '';
    if (cat === 'scanner') {
        label = (data && data.name) ? data.name : type;
        if (data && data.severity) label += ' [' + data.severity.toUpperCase() + ']';
        vectors = ['scanner'];
    } else if (cat === 'scope') {
        label = (data && typeof data === 'object') ? JSON.stringify(data).substring(0, 100) : String(data || type);
        vectors = ['scope'];
    } else if (cat === 'collab') {
        label = (data && data.type) ? data.type : 'Interaction';
        vectors = ['collab'];
    } else if (cat === 'websocket') {
        label = (data && data.url) ? data.url : type;
        vectors = ['ws'];
    } else if (type === 'tool.called' && data) {
        var tn = data.tool_name || 'unknown';
        var dur = data.duration_ms || 0;
        var isErr = data.is_error || false;
        label = tn + ' (' + dur + 'ms)' + (isErr ? ' ERROR' : '');
        vectors = ['tool'];
        // Use URL/method/status from the tool event data if available
        if (data.url) url = data.url;
        if (data.method && data.method !== tn) method = data.method;
        if (data.host) host = data.host;
        if (data.status_code) statusCode = data.status_code;
    } else if (!url && typeof data === 'object') {
        label = JSON.stringify(data).substring(0, 120);
    }

    var evt = {
        id: ++counters.events,
        type: type,
        category: cat,
        time: timeStr,
        timestamp: ts,
        method: method,
        url: url,
        path: pathDisplay,
        host: host,
        statusCode: statusCode,
        contentType: contentType,
        vectors: vectors,
        isNoise: isNoisy,
        inScope: inScope,
        messageId: messageId,
        label: label,
        raw: data
    };

    events.unshift(evt);
    if (events.length > MAX_EVENTS) events.length = MAX_EVENTS;

    // Update counters
    if (isNoisy) counters.hidden++;
    if (inScope) { counters.scope++; knownHosts[host] = true; }
    if (host && !knownHosts[host]) { knownHosts[host] = !isNoisy; if (!isNoisy) counters.scope++; }
    vectors.forEach(function(v) { if (counters[v] !== undefined) counters[v]++; });
    if (cat === 'scanner') counters.findings++;
    if (type === 'tool.called') counters.toolCalls++;

    updateCounterDisplay();

    // Append to DOM directly for performance (if passes filter)
    if (passesFilter(evt)) {
        prependEventDOM(evt);
    }
}

function mapTypeToCategory(type) {
    if (type === 'tool.called') return 'tool';
    if (type.indexOf('proxy') !== -1) return 'proxy';
    if (type.indexOf('scanner') !== -1) return 'scanner';
    if (type.indexOf('scope') !== -1) return 'scope';
    if (type.indexOf('collaborator') !== -1 || type.indexOf('collab') !== -1) return 'collab';
    if (type.indexOf('websocket') !== -1) return 'websocket';
    return 'tool';
}

function passesFilter(evt) {
    if (noiseHidden && evt.isNoise) return false;
    if (activeFilter !== 'all' && evt.category !== activeFilter) return false;
    if (searchQuery) {
        var haystack = (evt.url + ' ' + evt.host + ' ' + evt.method + ' ' + evt.label).toLowerCase();
        if (haystack.indexOf(searchQuery) === -1) return false;
    }
    return true;
}

function updateCounterDisplay() {
    document.getElementById('sEvents').textContent = counters.events;
    document.getElementById('sScope').textContent = Object.keys(knownHosts).filter(function(h){return knownHosts[h];}).length;
    document.getElementById('sApi').textContent = counters.api;
    document.getElementById('sAuth').textContent = counters.auth;
    document.getElementById('sParams').textContent = counters.params;
    document.getElementById('sUpload').textContent = counters.upload;
    document.getElementById('sAdmin').textContent = counters.admin;
    document.getElementById('sData').textContent = counters.data;
    document.getElementById('sFindings').textContent = counters.findings;
    document.getElementById('sHidden').textContent = counters.hidden;
    document.getElementById('sToolCalls').textContent = counters.toolCalls;
}

// ---- Render full list (for filter changes) ----
function renderList() {
    while (elList.firstChild) elList.removeChild(elList.firstChild);
    var shown = 0;
    for (var i = 0; i < events.length; i++) {
        if (passesFilter(events[i])) {
            elList.appendChild(buildEventRow(events[i]));
            shown++;
            if (shown > 500) break;
        }
    }
    if (shown === 0) {
        var empty = document.createElement('div');
        empty.className = 'empty-state';
        empty.textContent = events.length === 0 ? 'Waiting for events from Burp Suite proxy...' : 'No events match current filters';
        elList.appendChild(empty);
    }
}

function prependEventDOM(evt) {
    var empty = elList.querySelector('.empty-state');
    if (empty) empty.remove();
    elList.insertBefore(buildEventRow(evt), elList.firstChild);
    while (elList.children.length > 500) elList.removeChild(elList.lastChild);
}

function buildEventRow(evt) {
    var row = document.createElement('div');
    row.className = 'activity-item' + (evt.isNoise && !noiseHidden ? ' noise' : '') + (evt.id === selectedEventId ? ' selected' : '');
    row.dataset.eid = evt.id;
    row.onclick = function() { selectEvent(evt.id); };

    // Time
    var t = document.createElement('span');
    t.className = 'activity-time';
    t.textContent = evt.time;
    row.appendChild(t);

    // Badges
    var badges = document.createElement('span');
    badges.className = 'activity-badges';
    evt.vectors.forEach(function(v) {
        var b = document.createElement('span');
        b.className = 'badge badge-' + v;
        b.textContent = v.toUpperCase();
        badges.appendChild(b);
    });
    if (evt.vectors.length === 0) {
        var b = document.createElement('span');
        b.className = 'badge badge-' + evt.category;
        b.textContent = evt.category.toUpperCase();
        badges.appendChild(b);
    }
    row.appendChild(badges);

    // URL/label area
    var urlArea = document.createElement('span');
    urlArea.className = 'activity-url';
    if (evt.method && (evt.url || evt.category === 'tool')) {
        // Method badge — for tool events, show tool name
        var mb = document.createElement('span');
        var isToolEvt = evt.category === 'tool' && evt.type === 'tool.called';
        mb.className = isToolEvt ? 'method-badge method-tool' : ('method-badge method-' + evt.method);
        mb.textContent = evt.method;
        urlArea.appendChild(mb);
        urlArea.appendChild(document.createTextNode(' '));

        // Status if available
        if (evt.statusCode) {
            var sc = document.createElement('span');
            var scCls = evt.statusCode < 300 ? '2xx' : evt.statusCode < 400 ? '3xx' : evt.statusCode < 500 ? '4xx' : '5xx';
            sc.className = 'status-code status-' + scCls;
            sc.textContent = evt.statusCode;
            urlArea.appendChild(sc);
            urlArea.appendChild(document.createTextNode(' '));
        }

        // Path
        var pathParts = evt.path.split('?');
        var ps = document.createElement('span');
        ps.className = 'path';
        ps.textContent = pathParts[0];
        urlArea.appendChild(ps);
        if (pathParts[1]) {
            var qs = document.createElement('span');
            qs.className = 'query';
            qs.textContent = '?' + pathParts[1].substring(0, 60);
            urlArea.appendChild(qs);
        }

        // Host
        if (evt.host) {
            var hs = document.createElement('span');
            hs.className = 'host';
            hs.textContent = evt.host;
            urlArea.appendChild(hs);
        }
    } else {
        urlArea.textContent = evt.label || evt.type;
    }
    row.appendChild(urlArea);

    // Host column
    var hostCol = document.createElement('span');
    hostCol.style.cssText = 'color:var(--text-muted);font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;max-width:120px;';
    hostCol.textContent = evt.host || '';
    row.appendChild(hostCol);

    // Expand
    var exp = document.createElement('span');
    exp.className = 'expand-icon';
    exp.textContent = '\u25BC';
    row.appendChild(exp);

    return row;
}

// ---- MCP command helpers ----
function mcpCommand(tool, args) {
    return JSON.stringify({tool: tool, arguments: args});
}

function escapeRegex(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function parseUrl(url) {
    if (!url || url.indexOf('://') === -1) return null;
    try { return new URL(url); } catch (ex) { return null; }
}

// send_to_tool(action="repeater") needs a raw request: rebuild a minimal one from the event URL.
function repeaterArguments(evt, u) {
    if (!u || (u.protocol !== 'http:' && u.protocol !== 'https:')) return null;
    var tls = u.protocol === 'https:';
    var method = /^[A-Z]+$/.test(evt.method || '') ? evt.method : 'GET';
    var host = u.hostname.replace(/^\[|\]$/g, '');
    return {
        action: 'repeater',
        request: method + ' ' + u.pathname + u.search + ' HTTP/1.1\r\nHost: ' + u.host + '\r\n\r\n',
        host: host,
        port: u.port ? parseInt(u.port, 10) : (tls ? 443 : 80),
        use_tls: tls,
        tab_name: 'Dashboard-' + host
    };
}

// ---- Select / Detail Panel ----
function selectEvent(eid) {
    if (selectedEventId === eid) {
        closeDetail();
        return;
    }
    selectedEventId = eid;

    // Update row highlights
    elList.querySelectorAll('.activity-item').forEach(function(r) {
        r.classList.toggle('selected', parseInt(r.dataset.eid) === eid);
    });

    var evt = events.find(function(e) { return e.id === eid; });
    if (!evt) return;

    // Build detail content
    while (elDetailInner.firstChild) elDetailInner.removeChild(elDetailInner.firstChild);

    // Left: request info
    var left = document.createElement('div');
    var h4L = document.createElement('h4');
    h4L.className = 'detail-section';
    h4L.textContent = 'REQUEST DETAILS';
    left.appendChild(h4L);

    var rows = [];
    if (evt.method) rows.push(['Method', evt.method]);
    if (evt.url) rows.push(['URL', evt.url]);
    if (evt.host) rows.push(['Host', evt.host]);
    if (evt.statusCode) rows.push(['Status', evt.statusCode + (evt.statusCode < 300 ? ' OK' : evt.statusCode < 400 ? ' Redirect' : evt.statusCode < 500 ? ' Client Error' : ' Server Error')]);
    if (evt.contentType) rows.push(['MIME', evt.contentType]);
    if (evt.messageId) rows.push(['Msg ID', '#' + evt.messageId]);
    if (evt.vectors.length) rows.push(['Vectors', evt.vectors.map(function(v){return v.toUpperCase();}).join(', ')]);
    rows.push(['Time', evt.time]);
    if (evt.inScope) rows.push(['Scope', 'In-scope']);

    rows.forEach(function(r) {
        var dr = document.createElement('div');
        dr.className = 'detail-row';
        var dl = document.createElement('span');
        dl.className = 'dl';
        dl.textContent = r[0];
        var dv = document.createElement('span');
        dv.className = 'dv';
        dv.textContent = r[1];
        dr.appendChild(dl);
        dr.appendChild(dv);
        left.appendChild(dr);
    });

    // Right: MCP tool actions
    var right = document.createElement('div');
    var h4R = document.createElement('h4');
    h4R.className = 'detail-section';
    h4R.textContent = 'MCP TOOL COMMANDS';
    right.appendChild(h4R);

    var hint = document.createElement('div');
    hint.className = 'detail-hint';
    hint.textContent = 'Click any command below to copy it. Paste and run in your MCP client.';
    right.appendChild(hint);

    // Tool commands (current consolidated tool names; arguments always serialised by JSON.stringify)
    var cmds = [];
    var parsedUrl = parseUrl(evt.url);
    if (evt.url) {
        var repeater = repeaterArguments(evt, parsedUrl);
        if (repeater) {
            cmds.push({label: 'Send to Repeater', cmd: mcpCommand('send_to_tool', repeater)});
        }
        cmds.push({label: 'Active Scan', cmd: mcpCommand('scanner', {action: 'start_audit', urls: [evt.url]})});
        if (evt.host || parsedUrl) {
            cmds.push({
                label: 'Add Host to Scope',
                cmd: mcpCommand('scope', {action: 'include', url: parsedUrl ? parsedUrl.origin : 'https://' + evt.host})
            });
        }
        if (evt.host) {
            cmds.push({
                label: 'Search Proxy History',
                cmd: mcpCommand('proxy_history_search', {pattern: escapeRegex(evt.host), search_in: 'url', max_results: 20})
            });
        }
        cmds.push({
            label: 'Get Full Request',
            cmd: mcpCommand('proxy_history_search', {
                pattern: '^' + escapeRegex(evt.url) + '$',
                search_in: 'url',
                max_results: 5,
                include_request: true,
                include_response: true
            })
        });
    }
    if (evt.category === 'scanner' && evt.raw) {
        var issueArgs = {action: 'get_all_issues'};
        if (evt.url) issueArgs.url_prefix = evt.url;
        cmds.push({label: 'View Issue Detail', cmd: mcpCommand('scanner', issueArgs)});
    }

    // Action buttons
    var actions = document.createElement('div');
    actions.className = 'detail-actions';
    cmds.forEach(function(c) {
        var btn = document.createElement('button');
        btn.className = 'detail-btn';
        btn.textContent = c.label;
        btn.onclick = function(e) {
            e.stopPropagation();
            copyText(c.cmd);
            btn.classList.add('copied');
            btn.textContent = 'Copied!';
            setTimeout(function(){ btn.classList.remove('copied'); btn.textContent = c.label; }, 1500);
        };
        actions.appendChild(btn);
    });
    right.appendChild(actions);

    // Show first command as preview
    if (cmds.length > 0) {
        var pre = document.createElement('div');
        pre.className = 'detail-mcp';
        pre.textContent = cmds[0].cmd;
        pre.title = 'Click to copy';
        pre.onclick = function(e) {
            e.stopPropagation();
            copyText(cmds[0].cmd);
            showToast('Copied to clipboard');
        };
        right.appendChild(pre);
    }

    elDetailInner.appendChild(left);
    elDetailInner.appendChild(right);
    elDetail.classList.add('open');
}

function closeDetail() {
    selectedEventId = null;
    elDetail.classList.remove('open');
    elList.querySelectorAll('.activity-item.selected').forEach(function(r) { r.classList.remove('selected'); });
}

function copyText(text) {
    if (navigator.clipboard) {
        navigator.clipboard.writeText(text).catch(function(){});
    } else {
        var ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
    }
    showToast('Copied to clipboard');
}

function showToast(msg) {
    elToast.textContent = msg;
    elToast.classList.add('show');
    setTimeout(function(){ elToast.classList.remove('show'); }, 2000);
}

function clearAll() {
    events = [];
    counters = {events:0,scope:0,api:0,auth:0,params:0,upload:0,admin:0,data:0,findings:0,hidden:0,toolCalls:0};
    knownHosts = {};
    updateCounterDisplay();
    closeDetail();
    renderList();
}

// ---- Event bus: initial history + live SSE ----
var EVENT_TYPES = ['proxy.request','proxy.response','scanner.issue','scanner.task.status',
    'scope.changed','collaborator.interaction','websocket.created','websocket.message',
    'websocket.closed','http.request','http.response','proxy.intercept','proxy.rule.applied',
    'tool.called'];
var HISTORY_EVENT_LIMIT = 300;
var HISTORY_PROXY_LIMIT = 100;
var HISTORY_TIMEOUT_MS = 10000;

// Live events that arrive while the history is loading are held back and replayed after it,
// skipping any the history already contained (same event-bus id).
var historyLoaded = false;
var pendingLive = [];
var historyEventIds = {};

function onBusEvent(type, parsed) {
    if (!historyLoaded) {
        pendingLive.push([type, parsed]);
        return;
    }
    addEvent(type, parsed.data || parsed, parsed.timestamp);
}

function fetchJson(path) {
    return fetch(path, {credentials: 'same-origin'}).then(function(r) {
        if (!r.ok) throw new Error('HTTP ' + r.status);
        return r.json();
    });
}

function timeOf(ts) {
    var t = Date.parse(ts || '');
    return isNaN(t) ? null : t;
}

function finishHistory(entries) {
    if (historyLoaded) return;
    historyLoaded = true;
    entries.sort(function(a, b) { return (timeOf(a.timestamp) || 0) - (timeOf(b.timestamp) || 0); });
    entries.forEach(function(e) { addEvent(e.type, e.data, e.timestamp); });
    pendingLive.forEach(function(p) {
        var parsed = p[1];
        if (parsed && parsed.id !== undefined && historyEventIds[parsed.id]) return;
        addEvent(p[0], parsed.data || parsed, parsed.timestamp);
    });
    pendingLive = [];
    historyEventIds = {};
}

// Recent event-bus events, plus proxy history older than the oldest of them (traffic from
// before the extension loaded, or past the event window), merged in chronological order.
function loadHistory() {
    setTimeout(function() { finishHistory([]); }, HISTORY_TIMEOUT_MS);
    Promise.all([
        fetchJson('api/events/recent?limit=' + HISTORY_EVENT_LIMIT).catch(function() { return []; }),
        fetchJson('api/proxy/recent?limit=' + HISTORY_PROXY_LIMIT).catch(function() { return {}; })
    ]).then(function(res) {
        var busEvents = Array.isArray(res[0]) ? res[0] : [];
        var proxyItems = (res[1] && Array.isArray(res[1].items)) ? res[1].items : [];
        var entries = [];
        var oldest = null;
        busEvents.forEach(function(e) {
            var t = timeOf(e.timestamp);
            if (t !== null && (oldest === null || t < oldest)) oldest = t;
            if (EVENT_TYPES.indexOf(e.type) === -1) return;
            historyEventIds[e.id] = true;
            entries.push({type: e.type, data: e.data || {}, timestamp: e.timestamp});
        });
        proxyItems.forEach(function(item) {
            var t = timeOf(item.time);
            if (oldest !== null && t !== null && t >= oldest) return;
            entries.push({
                type: 'proxy.response',
                data: {
                    url: item.url || '',
                    method: item.method || '',
                    host: item.host || '',
                    status_code: item.status_code || 0,
                    mime_type: item.response_mime_type || item.mime_type || '',
                    in_scope: false,
                    message_id: item.index || 0
                },
                timestamp: item.time
            });
        });
        finishHistory(entries);
    });
}

function connectSSE() {
    var es = new EventSource('events');
    es.onopen = function() {
        document.getElementById('statusDot').classList.remove('disconnected');
        document.getElementById('statusText').textContent = 'Connected';
    };
    es.onerror = function() {
        document.getElementById('statusDot').classList.add('disconnected');
        document.getElementById('statusText').textContent = 'Reconnecting...';
    };

    EVENT_TYPES.forEach(function(evtType) {
        es.addEventListener(evtType, function(e) {
            try {
                onBusEvent(evtType, JSON.parse(e.data));
            } catch(ex) {}
        });
    });

    es.onmessage = function(e) {
        try {
            var d = JSON.parse(e.data);
            onBusEvent(d.type || 'event', d);
        } catch(ex) {}
    };
}

// ---- Connection details (real host and ports, from the server) ----
function fetchInfo() {
    fetchJson('api/info').then(function(d) {
        if (d.version) document.getElementById('versionText').textContent = 'v' + d.version;
        document.getElementById('connPrimary').textContent = d.primary_mcp_url || '';
        document.getElementById('connSecondary').textContent = d.secondary_mcp_url || '';
        document.getElementById('connDashboard').textContent = d.dashboard_url || location.origin;
        document.getElementById('connProxyHistory').textContent = d.proxy_history_url || '';
        document.getElementById('connClientConfig').textContent = d.mcp_client_config ? JSON.stringify(d.mcp_client_config) : '';
        document.getElementById('connClaudeCode').textContent = d.claude_code_command || '';
    }).catch(function(){});
}

// ---- Fetch stats ----
function fetchStats() {
    fetchJson('api/stats').then(function(d) {
        var s = d.uptime_seconds || 0;
        var h = Math.floor(s/3600), m = Math.floor((s%3600)/60), sec = s%60;
        document.getElementById('uptimeText').textContent =
            String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(sec).padStart(2,'0');
        document.getElementById('statUptime').textContent =
            (h>0?h+'h ':'') + (m>0?m+'m ':'') + sec + 's uptime';
    }).catch(function(){});
}

// ---- Fetch rules ----
function fetchRules() {
    fetchJson('api/rules').then(function(d) {
        ['proxy','traffic','session'].forEach(function(type) {
            var key = type + '_rules';
            var el = document.getElementById(type + 'RulesList');
            var rules = d[key] || [];
            while (el.firstChild) el.removeChild(el.firstChild);
            if (rules.length === 0) {
                var empty = document.createElement('div');
                empty.className = 'empty-state';
                empty.textContent = 'No ' + type + ' rules active';
                el.appendChild(empty);
            } else {
                rules.forEach(function(r) {
                    var item = document.createElement('div');
                    item.className = 'rule-item';
                    var nameSpan = document.createElement('span');
                    nameSpan.textContent = r.id || r.name || 'unnamed';
                    item.appendChild(nameSpan);
                    var badge = document.createElement('span');
                    badge.className = 'rule-badge ' + (r.enabled ? 'active' : 'inactive');
                    badge.textContent = r.enabled ? 'ACTIVE' : 'OFF';
                    item.appendChild(badge);
                    el.appendChild(item);
                });
            }
        });
    }).catch(function(){});
}

// ---- Keyboard shortcuts ----
document.addEventListener('keydown', function(e) {
    if (e.key === 'Escape') closeDetail();
    if (e.key === '/' && document.activeElement !== elSearch) {
        e.preventDefault();
        elSearch.focus();
    }
});

// ---- Theme: follow the colours of the Burp window ----
function shade(hex, amt) {
    var n = parseInt(hex.slice(1), 16), r = n >> 16, g = (n >> 8) & 255, b = n & 255;
    function ch(v) { return Math.max(0, Math.min(255, Math.round(v + amt))); }
    return '#' + [ch(r), ch(g), ch(b)].map(function(v){ return ('0' + v.toString(16)).slice(-2); }).join('');
}
function applyTheme(t) {
    var s = document.documentElement.style, dir = t.dark ? 1 : -1;
    s.setProperty('--bg-primary', t.background);
    s.setProperty('--bg-secondary', shade(t.background, 10 * dir));
    s.setProperty('--bg-card', shade(t.background, 20 * dir));
    s.setProperty('--bg-card-hover', shade(t.background, 30 * dir));
    s.setProperty('--bg-detail', shade(t.background, 10 * dir));
    s.setProperty('--text-primary', t.foreground);
    s.setProperty('--text-secondary', t.muted);
    s.setProperty('--text-muted', shade(t.muted, -40 * dir));
    s.setProperty('--border', t.border);
    s.setProperty('--border-bright', shade(t.border, 25 * dir));
    s.setProperty('--accent', t.accent);
    s.setProperty('--accent-green', t.success);
    s.setProperty('--accent-orange', t.warning);
    s.setProperty('--accent-red', t.error);
    s.setProperty('--accent-blue', t.info);
    s.setProperty('--accent-purple', t.purple);
    s.setProperty('color-scheme', t.dark ? 'dark' : 'light');
}
function fetchTheme() {
    fetchJson('api/theme').then(applyTheme).catch(function(){});
}
fetchTheme();
setInterval(fetchTheme, 5000);

// ---- Initialize ----
connectSSE();
loadHistory();
fetchInfo();
fetchStats();
fetchRules();
setInterval(fetchStats, 2000);
setInterval(fetchRules, 10000);
