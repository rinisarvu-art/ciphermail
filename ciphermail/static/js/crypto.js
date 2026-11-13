/**
 * CipherMail - Client-Side Cryptographic Engine
 * Built strictly on W3C standard WebCrypto API (window.crypto.subtle)
 * Zero Plaintext leaves the browser!
 */

const CipherCrypto = {
    // Utility helpers for Base64 and ArrayBuffer conversions
    arrayBufferToBase64(buffer) {
        let binary = '';
        const bytes = new Uint8Array(buffer);
        const len = bytes.byteLength;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return window.btoa(binary);
    },

    base64ToArrayBuffer(base64) {
        const binary_string = window.atob(base64);
        const len = binary_string.length;
        const bytes = new Uint8Array(len);
        for (let i = 0; i < len; i++) {
            bytes[i] = binary_string.charCodeAt(i);
        }
        return bytes.buffer;
    },

    getRandomSalt(length = 16) {
        const array = new Uint8Array(length);
        window.crypto.getRandomValues(array);
        return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
    },

    // 1. In-Browser Keypair Generation (RSA-OAEP for Encryption + ECDSA for Signatures)
    async generateUserKeys() {
        // Asymmetric Encryption Keypair: RSA-OAEP 2048-bit, SHA-256
        const rsaPair = await window.crypto.subtle.generateKey(
            {
                name: "RSA-OAEP",
                modulusLength: 2048,
                publicExponent: new Uint8Array([1, 0, 1]),
                hash: "SHA-256",
            },
            true,
            ["encrypt", "decrypt"]
        );

        // Digital Signature Keypair: ECDSA (P-256, SHA-256) for Non-Repudiation
        const ecdsaPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDSA",
                namedCurve: "P-256"
            },
            true,
            ["sign", "verify"]
        );

        const rsaPublicKeyJwk = await window.crypto.subtle.exportKey("jwk", rsaPair.publicKey);
        const rsaPrivateKeyJwk = await window.crypto.subtle.exportKey("jwk", rsaPair.privateKey);
        const ecdsaPublicKeyJwk = await window.crypto.subtle.exportKey("jwk", ecdsaPair.publicKey);
        const ecdsaPrivateKeyJwk = await window.crypto.subtle.exportKey("jwk", ecdsaPair.privateKey);

        return {
            publicKeys: {
                rsa: rsaPublicKeyJwk,
                ecdsa: ecdsaPublicKeyJwk
            },
            privateKeys: {
                rsa: rsaPrivateKeyJwk,
                ecdsa: ecdsaPrivateKeyJwk
            }
        };
    },

    // 2. Master Key Derivation (PBKDF2 with 100,000 rounds of SHA-256)
    async deriveMasterKey(password, saltHex) {
        const enc = new TextEncoder();
        const baseKey = await window.crypto.subtle.importKey(
            "raw",
            enc.encode(password),
            "PBKDF2",
            false,
            ["deriveKey"]
        );

        // Convert hex salt to Uint8Array
        const saltBytes = new Uint8Array(saltHex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));

        const masterKey = await window.crypto.subtle.deriveKey(
            {
                name: "PBKDF2",
                salt: saltBytes,
                iterations: 100000,
                hash: "SHA-256"
            },
            baseKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt", "decrypt"]
        );

        return masterKey;
    },

    // 3. Encrypt Private Keys for Zero-Knowledge Storage on Server
    async encryptPrivateKeyVault(privateKeysObject, masterKey) {
        const enc = new TextEncoder();
        const payload = JSON.stringify(privateKeysObject);
        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        const encryptedBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            masterKey,
            enc.encode(payload)
        );

        return {
            iv: this.arrayBufferToBase64(iv),
            ciphertext: this.arrayBufferToBase64(encryptedBuffer)
        };
    },

    // 4. Decrypt Private Keys locally in browser
    async decryptPrivateKeyVault(encryptedVault, masterKey) {
        const iv = this.base64ToArrayBuffer(encryptedVault.iv);
        const ciphertext = this.base64ToArrayBuffer(encryptedVault.ciphertext);

        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: new Uint8Array(iv) },
            masterKey,
            ciphertext
        );

        const dec = new TextDecoder();
        const jsonStr = dec.decode(decryptedBuffer);
        const privateKeysJwk = JSON.parse(jsonStr);

        // Import keys back as CryptoKey objects
        const rsaPrivateKey = await window.crypto.subtle.importKey(
            "jwk",
            privateKeysJwk.rsa,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["decrypt"]
        );

        const ecdsaPrivateKey = await window.crypto.subtle.importKey(
            "jwk",
            privateKeysJwk.ecdsa,
            { name: "ECDSA", namedCurve: "P-256" },
            false,
            ["sign"]
        );

        return {
            rsaPrivateKey,
            ecdsaPrivateKey,
            rawJwk: privateKeysJwk
        };
    },

    // 5. Envelope Encryption: Hybrid AES-256-GCM + RSA-OAEP + ECDSA Signature
    async encryptEmail(subject, body, recipientRsaPubJwk, senderRsaPubJwk, senderEcdsaPrivKey) {
        const enc = new TextEncoder();

        // Step A: Generate random one-time 256-bit AES-GCM Session Key
        const sessionKey = await window.crypto.subtle.generateKey(
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );

        const iv = window.crypto.getRandomValues(new Uint8Array(12));

        // Step B: Encrypt Subject & Body with AES-GCM
        const encryptedSubjectBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            sessionKey,
            enc.encode(subject)
        );

        const encryptedBodyBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            sessionKey,
            enc.encode(body)
        );

        // Step C: Export raw Session Key
        const rawSessionKey = await window.crypto.subtle.exportKey("raw", sessionKey);

        // Step D: Import Recipient's RSA Public Key and Encrypt Session Key for Recipient
        const recipientRsaKey = await window.crypto.subtle.importKey(
            "jwk",
            recipientRsaPubJwk,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"]
        );

        const encryptedKeyRecipientBuffer = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            recipientRsaKey,
            rawSessionKey
        );

        // Step E: Encrypt Session Key for Sender (so Sender can decrypt in their Sent box)
        const senderRsaKey = await window.crypto.subtle.importKey(
            "jwk",
            senderRsaPubJwk,
            { name: "RSA-OAEP", hash: "SHA-256" },
            false,
            ["encrypt"]
        );

        const encryptedKeySenderBuffer = await window.crypto.subtle.encrypt(
            { name: "RSA-OAEP" },
            senderRsaKey,
            rawSessionKey
        );

        // Step F: Digital Signature: Sign the ciphertext with Sender's ECDSA Private Key
        const signatureBuffer = await window.crypto.subtle.sign(
            { name: "ECDSA", hash: { name: "SHA-256" } },
            senderEcdsaPrivKey,
            encryptedBodyBuffer
        );

        return {
            encryptedSubject: this.arrayBufferToBase64(encryptedSubjectBuffer),
            encryptedBody: this.arrayBufferToBase64(encryptedBodyBuffer),
            encryptedKeyRecipient: this.arrayBufferToBase64(encryptedKeyRecipientBuffer),
            encryptedKeySender: this.arrayBufferToBase64(encryptedKeySenderBuffer),
            iv: this.arrayBufferToBase64(iv),
            signature: this.arrayBufferToBase64(signatureBuffer),
            rawSessionKeyBuffer: rawSessionKey // for encrypting attachments if any
        };
    },

    // 6. Decrypt Email Message with Verification
    async decryptEmail(encSubject, encBody, encKey, ivBase64, sigBase64, userRsaPrivateKey, senderEcdsaPubJwk) {
        const dec = new TextDecoder();
        const iv = new Uint8Array(this.base64ToArrayBuffer(ivBase64));
        const encryptedKeyBuffer = this.base64ToArrayBuffer(encKey);
        const encryptedBodyBuffer = this.base64ToArrayBuffer(encBody);
        const encryptedSubjectBuffer = this.base64ToArrayBuffer(encSubject);

        // Step A: Decrypt the AES Session Key using User's RSA Private Key
        const rawSessionKey = await window.crypto.subtle.decrypt(
            { name: "RSA-OAEP" },
            userRsaPrivateKey,
            encryptedKeyBuffer
        );

        const sessionKey = await window.crypto.subtle.importKey(
            "raw",
            rawSessionKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["decrypt"]
        );

        // Step B: Verify Digital Signature if sender public key and signature provided
        let isVerified = false;
        if (senderEcdsaPubJwk && sigBase64) {
            try {
                const senderEcdsaKey = await window.crypto.subtle.importKey(
                    "jwk",
                    senderEcdsaPubJwk,
                    { name: "ECDSA", namedCurve: "P-256" },
                    false,
                    ["verify"]
                );

                const sigBuffer = this.base64ToArrayBuffer(sigBase64);
                isVerified = await window.crypto.subtle.verify(
                    { name: "ECDSA", hash: { name: "SHA-256" } },
                    senderEcdsaKey,
                    sigBuffer,
                    encryptedBodyBuffer
                );
            } catch (err) {
                console.warn("Signature verification failed:", err);
                isVerified = false;
            }
        }

        // Step C: Decrypt Subject & Body with Session Key
        const decryptedSubjectBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            sessionKey,
            encryptedSubjectBuffer
        );

        const decryptedBodyBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            sessionKey,
            encryptedBodyBuffer
        );

        return {
            subject: dec.decode(decryptedSubjectBuffer),
            body: dec.decode(decryptedBodyBuffer),
            isVerified: isVerified,
            sessionKey: sessionKey
        };
    },

    // 7. Client-Side File Attachment Encryption (In-Memory)
    async encryptAttachment(fileBuffer, rawSessionKey, ivBytes) {
        const sessionKey = await window.crypto.subtle.importKey(
            "raw",
            rawSessionKey,
            { name: "AES-GCM", length: 256 },
            false,
            ["encrypt"]
        );

        const encryptedDataBuffer = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: ivBytes },
            sessionKey,
            fileBuffer
        );

        return this.arrayBufferToBase64(encryptedDataBuffer);
    },

    // 8. Client-Side File Attachment Decryption (In-Memory Blob)
    async decryptAttachment(encryptedBase64, ivBytes, sessionKey, mimeType) {
        const encryptedDataBuffer = this.base64ToArrayBuffer(encryptedBase64);
        const decryptedBuffer = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivBytes },
            sessionKey,
            encryptedDataBuffer
        );

        const blob = new Blob([decryptedBuffer], { type: mimeType || 'application/octet-stream' });
        return URL.createObjectURL(blob);
    },

    // 9. Examiner Demonstration Feature: Shannon Entropy Calculation
    calculateEntropy(str) {
        if (!str) return 0;
        const len = str.length;
        const frequencies = {};
        for (let i = 0; i < len; i++) {
            const char = str[i];
            frequencies[char] = (frequencies[char] || 0) + 1;
        }
        let entropy = 0;
        for (const char in frequencies) {
            const p = frequencies[char] / len;
            entropy -= p * Math.log2(p);
        }
        return entropy.toFixed(3); // Ideal random ciphertext is close to 8.0 bits/byte
    },

    // 10. Dynamic Anti-Leak Canvas Watermark
    generateWatermarkPattern(email, ip = '127.0.0.1') {
        const canvas = document.createElement('canvas');
        canvas.width = 360;
        canvas.height = 140;
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        
        ctx.rotate(-20 * Math.PI / 180);
        ctx.font = '12px "Segoe UI", Roboto, sans-serif';
        ctx.fillStyle = 'rgba(239, 68, 68, 0.12)'; // faint red watermark
        
        const timestamp = new Date().toLocaleString();
        const watermarkText = `CONFIDENTIAL • ${email} • ${timestamp}`;
        ctx.fillText(watermarkText, -50, 80);
        ctx.fillText(`IP: ${ip} • UNLAWFUL DISTRIBUTION PROHIBITED`, -50, 105);

        return canvas.toDataURL('image/png');
    }
};

window.CipherCrypto = CipherCrypto;
