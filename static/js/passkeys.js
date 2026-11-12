/* Passkeys (WebAuthn) helpers shared by the Settings page and the two-factor sign-in page.
   Kept out of csfv2.js because the sign-in page loads neither jQuery nor csfv2.js. */
(function () {
    'use strict';

    function b64uToBuf(s) {
        s = String(s).replace(/-/g, '+').replace(/_/g, '/');
        while (s.length % 4) s += '=';
        var bin = atob(s), a = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
        return a.buffer;
    }

    function bufToB64u(buf) {
        var b = new Uint8Array(buf), s = '';
        for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
        return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    function post(url, csrf, body) {
        return fetch(url, {
            method: 'POST', credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-CSRFToken': csrf, 'X-Requested-With': 'XMLHttpRequest' },
            body: JSON.stringify(body || {})
        }).then(function (r) {
            return r.json().catch(function () { return {}; }).then(function (j) {
                if (!r.ok || j.success === false) throw new Error(j.error || ('Server error ' + r.status));
                return j;
            });
        });
    }

    function supported() {
        return !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
    }

    function decodeCreate(o) {
        o.challenge = b64uToBuf(o.challenge);
        o.user.id = b64uToBuf(o.user.id);
        (o.excludeCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
        return o;
    }

    function decodeGet(o) {
        o.challenge = b64uToBuf(o.challenge);
        (o.allowCredentials || []).forEach(function (c) { c.id = b64uToBuf(c.id); });
        return o;
    }

    function encodeCred(c) {
        var r = c.response;
        var out = { id: c.id, rawId: bufToB64u(c.rawId), type: c.type,
                    response: { clientDataJSON: bufToB64u(r.clientDataJSON) } };
        if (r.attestationObject) {
            out.response.attestationObject = bufToB64u(r.attestationObject);
            if (typeof r.getTransports === 'function') {
                try { out.response.transports = r.getTransports(); } catch (e) { /* older browsers */ }
            }
        }
        if (r.authenticatorData) {
            out.response.authenticatorData = bufToB64u(r.authenticatorData);
            out.response.signature = bufToB64u(r.signature);
            if (r.userHandle) out.response.userHandle = bufToB64u(r.userHandle);
        }
        if (c.authenticatorAttachment) out.authenticatorAttachment = c.authenticatorAttachment;
        if (typeof c.getClientExtensionResults === 'function') {
            try { out.clientExtensionResults = c.getClientExtensionResults(); } catch (e) { /* ignore */ }
        }
        return out;
    }

    function friendly(err) {
        var name = err && err.name;
        if (name === 'NotAllowedError') return 'The passkey prompt was cancelled or timed out.';
        if (name === 'SecurityError') return 'The browser refused: passkeys need a trusted HTTPS certificate and a hostname, not an IP address.';
        if (name === 'InvalidStateError') return 'This device already holds a passkey for this account.';
        if (name === 'NotSupportedError') return 'This device has no passkey support.';
        return (err && err.message) || String(err);
    }

    window.csfPasskeys = {
        supported: supported,
        /* Register a new passkey for the signed-in user. Resolves with {name, recovery_codes}. */
        register: function (name, csrf) {
            if (!supported()) return Promise.reject(new Error('This browser does not support passkeys.'));
            return post('/api/passkeys/register/options', csrf)
                .then(function (j) { return navigator.credentials.create({ publicKey: decodeCreate(j.options) }); })
                .then(function (cred) { return post('/api/passkeys/register/verify', csrf, { credential: encodeCred(cred), name: name }); })
                .catch(function (e) { throw new Error(friendly(e)); });
        },
        /* Finish a pending two-factor sign-in with a passkey. Resolves with {redirect}. */
        login: function (csrf) {
            if (!supported()) return Promise.reject(new Error('This browser does not support passkeys.'));
            return post('/api/passkeys/login/options', csrf)
                .then(function (j) { return navigator.credentials.get({ publicKey: decodeGet(j.options) }); })
                .then(function (cred) { return post('/api/passkeys/login/verify', csrf, { credential: encodeCred(cred) }); })
                .catch(function (e) { throw new Error(friendly(e)); });
        }
    };
})();
