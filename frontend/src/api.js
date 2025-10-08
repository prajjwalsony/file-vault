import CryptoJS from 'crypto-js';
import forge from 'node-forge';

export const BASE_URL = process.env.REACT_APP_BACKEND_URL || "http://localhost:3000";

let JWT_TOKEN = null;
let SESSION_KEY_B64 = null;

export function getAuthState() {
  // Try to restore tokens from sessionStorage if not in memory
  if (!JWT_TOKEN) {
    JWT_TOKEN = sessionStorage.getItem('jwt_token') || null;
  }
  
  if (!SESSION_KEY_B64) {
    SESSION_KEY_B64 = sessionStorage.getItem('session_key') || null;
  }
  
  const state = {
    loggedIn: !!(JWT_TOKEN && SESSION_KEY_B64),
    JWT: JWT_TOKEN,
    sessionKey: SESSION_KEY_B64
  };
  
  // console.log('getAuthState called, JWT present:', !!state.JWT);
  // console.log('getAuthState called, session key present:', !!state.sessionKey);
  // console.log('getAuthState called, loggedIn:', state.loggedIn);
  
  return state;
}

function encryptMessage(plaintext, base64SessionKey) {
  const sessionKey = CryptoJS.enc.Base64.parse(base64SessionKey);
  const iv = CryptoJS.lib.WordArray.random(16);
  const encrypted = CryptoJS.AES.encrypt(plaintext, sessionKey, {
    iv,
    mode: CryptoJS.mode.CFB,
    padding: CryptoJS.pad.NoPadding
  });
  const ivAndCiphertext = iv.clone().concat(encrypted.ciphertext);
  return ivAndCiphertext.toString(CryptoJS.enc.Base64);
}

function decryptMessage(base64MessageEncrypted, base64SessionKey) {
  const decodedToken = CryptoJS.enc.Base64.parse(base64MessageEncrypted);
  const sessionKey = CryptoJS.enc.Base64.parse(base64SessionKey);
  const iv = CryptoJS.lib.WordArray.create(decodedToken.words.slice(0, 4));
  const ciphertext = CryptoJS.lib.WordArray.create(decodedToken.words.slice(4));
  const decrypted = CryptoJS.AES.decrypt({ ciphertext }, sessionKey, {
    iv,
    mode: CryptoJS.mode.CFB,
    padding: CryptoJS.pad.NoPadding
  });
  return decrypted.toString(CryptoJS.enc.Utf8);
}

function decryptUserToken(base64MessageEncrypted, pwd) {
  const decodedToken = CryptoJS.enc.Base64.parse(base64MessageEncrypted);
  const decryptionKey = CryptoJS.SHA256(pwd);
  const iv = CryptoJS.lib.WordArray.create(decodedToken.words.slice(0, 4));
  const ciphertext = CryptoJS.lib.WordArray.create(decodedToken.words.slice(4));
  const decrypted = CryptoJS.AES.decrypt({ ciphertext }, decryptionKey, {
    iv,
    mode: CryptoJS.mode.CFB,
    padding: CryptoJS.pad.NoPadding
  });
  return decrypted.toString(CryptoJS.enc.Base64);
}

async function getPublicKey() {
  const res = await fetch(`${BASE_URL}/getPublicKey`);
  if (!res.ok) throw new Error('Failed to fetch public key');
  return res.text();
}

export async function register(id, pwd) {
  try {
    const RSA_PUBLIC_KEY = await getPublicKey();
    let publicKey;
    try {
      publicKey = forge.pki.publicKeyFromPem(RSA_PUBLIC_KEY);
    } catch (e) {
      return [false, 'Invalid RSA public key'];
    }
    const message = JSON.stringify({ id, pwd });
    const encryptedBytes = publicKey.encrypt(message, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
      mgf1: { md: forge.md.sha256.create() }
    });
    const encryptedBase64 = forge.util.encode64(encryptedBytes);

    const response = await fetch(`${BASE_URL}/createAccount`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      body: encryptedBase64
    });

    if (response.status !== 200) {
      return [false, await response.text()];
    }
    const result = await response.json();
    return [result.ERROR === '', result.ERROR || ''];
  } catch (e) {
    return [false, e.message];
  }
}

export async function login(id, pwd) {
  try {
    console.log('=== Starting login process ===');
    console.log('Username:', id);
    
    const RSA_PUBLIC_KEY = await getPublicKey();
    console.log('Got public key');
    
    const publicKey = forge.pki.publicKeyFromPem(RSA_PUBLIC_KEY);
    const message = JSON.stringify({ id, pwd });
    const encryptedBytes = publicKey.encrypt(message, 'RSA-OAEP', {
      md: forge.md.sha256.create(),
      mgf1: { md: forge.md.sha256.create() }
    });
    const encryptedBase64 = forge.util.encode64(encryptedBytes);

    console.log('Sending login request to server...');
    const response = await fetch(`${BASE_URL}/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'text/plain; charset=utf-8' },
      body: encryptedBase64
    });

    console.log('Login response status:', response.status);
    
    if (response.status !== 200) {
      const errorText = await response.text();
      console.error('Login failed:', errorText);
      return [false, errorText];
    }

    const userToken = await response.text();
    JWT_TOKEN = response.headers.get('Authorization');
    
    if (!JWT_TOKEN) {
      console.error('No JWT token received in Authorization header!');
      return [false, 'No JWT token received from server'];
    }
    
    SESSION_KEY_B64 = decryptUserToken(userToken, pwd);
    
    if (!SESSION_KEY_B64) {
      console.error('Failed to decrypt session key!');
      return [false, 'Failed to decrypt session key'];
    }
    
    console.log('=== Login successful! ===');
    console.log('JWT_TOKEN present:', !!JWT_TOKEN);
    console.log('SESSION_KEY_B64 present:', !!SESSION_KEY_B64);
    
    try {
      sessionStorage.setItem('jwt_token', JWT_TOKEN);
      sessionStorage.setItem('session_key', SESSION_KEY_B64);
    } catch (e) {
      console.warn('Failed to store auth tokens in sessionStorage:', e);
    }
    
    return [true, ''];
  } catch (e) {
    console.error('Login error:', e);
    return [false, e.message];
  }
}

export async function ChangeAccess(fileId, newAccess) {
  try {
    if (!JWT_TOKEN || !SESSION_KEY_B64) {
      return [false, 'Session Expired'];
    }
    const payload = JSON.stringify({ fileId, newAccess });
    const encrypted = encryptMessage(payload, SESSION_KEY_B64);

    const response = await fetch(`${BASE_URL}/changeAccess`, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'Authorization': JWT_TOKEN
      },
      body: encrypted
    });

    const res = await response.json();
    if (response.status !== 200) return [false, res.ERROR || 'Request failed'];
    return [res.ERROR === '', res.ERROR || ''];
  } catch (e) {
    return [false, e.message];
  }
}

export async function getFileList() {
  try {
    if (!JWT_TOKEN || !SESSION_KEY_B64) {
      return [false, 'Session Expired'];
    }

    console.log('Making getFileList request with JWT:', JWT_TOKEN ? 'Present' : 'Missing');
    
    const response = await fetch(`${BASE_URL}/getFileList`, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'Authorization': JWT_TOKEN
      }
    });

    if (response.status !== 200) {
      const errorText = await response.text();
      console.error('getFileList error response:', errorText);
      try {
        const errorObj = JSON.parse(errorText);
        return [false, errorObj.ERROR || 'Request failed'];
      } catch {
        return [false, errorText || 'Request failed'];
      }
    }

    const res = await response.json();
    let result = null;
    if (res.data) result = JSON.parse(res.data);
    return [res.ERROR === '', res.ERROR ? res.ERROR : result];
  } catch (e) {
    console.error('getFileList client error:', e);
    return [false, e.message];
  }
}

function wordArrayToUint8Array(wordArray) {
  const { words, sigBytes } = wordArray;
  const u8 = new Uint8Array(sigBytes);
  for (let i = 0; i < sigBytes; i++) {
    u8[i] = (words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff;
  }
  return u8;
}

async function encryptFileArrayBuffer(arrayBuffer, base64SessionKey) {
  const sessionKey = CryptoJS.enc.Base64.parse(base64SessionKey);
  const iv = CryptoJS.lib.WordArray.random(16);
  const plaintext = CryptoJS.lib.WordArray.create(arrayBuffer);
  const encrypted = CryptoJS.AES.encrypt(plaintext, sessionKey, {
    iv,
    mode: CryptoJS.mode.CFB,
    padding: CryptoJS.pad.NoPadding
  });
  const ivAndCiphertext = iv.clone().concat(encrypted.ciphertext);
  return wordArrayToUint8Array(ivAndCiphertext);
}

export async function uploadFile(file) {
  try {
    if (!JWT_TOKEN || !SESSION_KEY_B64) {
      return [false, 'Session Expired'];
    }

    if (file.size > (10*1025*1024)) {
      return [false, 'File size exceeds 10MB limit'];
    }

    const fileBuffer = await file.arrayBuffer();
    
    const encryptedFileBytes = await encryptFileArrayBuffer(fileBuffer, SESSION_KEY_B64);
    const encryptedBlob = new Blob([fileBuffer], { type: file.type });
    
    const formData = new FormData();
    formData.append('file', encryptedBlob, file.name);

    const response = await fetch(`${BASE_URL}/uploadFile`, {
      method: 'POST',
      headers: { 'Authorization': JWT_TOKEN },
      body: formData
    });

    if (response.ok) return [true, ''];
    
    let errorText = await response.text();
    try {
      const errorJson = JSON.parse(errorText);
      return [false, errorJson.ERROR || errorText];
    } catch {
      return [false, errorText];
    }
  } catch (e) {
    console.error('Upload error:', e);
    return [false, e.message];
  }
}

export async function getFile(fileId, action = 'view') {
  try {
    if (!JWT_TOKEN || !SESSION_KEY_B64) {
      return [false, 'Session Expired'];
    }

    console.log('JWT_TOKEN:', JWT_TOKEN ? JWT_TOKEN.substring(0, 20) + '...' : 'null');
    console.log('SESSION_KEY_B64:', SESSION_KEY_B64 ? SESSION_KEY_B64.substring(0, 20) + '...' : 'null');

    const payload = JSON.stringify({ fileId: parseInt(fileId, 10), action });
    const encrypted = encryptMessage(payload, SESSION_KEY_B64);

    const response = await fetch(`${BASE_URL}/getFile`, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain; charset=utf-8',
        'Authorization': JWT_TOKEN
      },
      body: encrypted
    });

    if (!response.ok) {
      const errorText = await response.text();
      console.error('Server error response:', errorText);
      try {
        const err = JSON.parse(errorText);
        return [false, err.ERROR || `Server error: ${response.statusText}`];
      } catch {
        return [false, errorText || `Server error: ${response.statusText}`];
      }
    }

    const arrBuf = await response.arrayBuffer();
    const bytes = new Uint8Array(arrBuf);

    const disposition = response.headers.get("content-disposition") || "";
    let fileName = "download.bin";

    const match = disposition.match(/filename="?([^"]+)"?/i);
    if (match) fileName = match[1];

    // console.log("fileName:", match[1]);


    const contentType = response.headers.get('content-type') || 'application/octet-stream';
    const blob = new Blob([bytes], { type: contentType });
    const blobUrl = URL.createObjectURL(blob);

    if (action === 'view') {
      window.open(blobUrl, '_blank');
    } else if (action === 'download') {
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = fileName;
      a.style.display = 'none';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      setTimeout(() => URL.revokeObjectURL(blobUrl), 100);
    }
    return [true, ''];
  } catch (e) {
    console.error('getFile error:', e);
    return [false, e.message];
  }
}

export function logout() {
  JWT_TOKEN = null;
  SESSION_KEY_B64 = null;
}

export function isLoggedIn() {
  return !!(JWT_TOKEN && SESSION_KEY_B64);
}

export async function getUserInfo() {
  if (!JWT_TOKEN) return [false, 'Session Expired'];
  try {
    const response = await fetch(`${BASE_URL}/getUserInfo`, {
      method: 'POST',
      headers: {
        'Authorization': JWT_TOKEN,
        'Content-Type': 'application/json'
      }
    });
    const result = await response.json();
    if (response.ok && result.ERROR === '') {
      const { ERROR, ...userInfo } = result;
      return [true, userInfo];
    }
    return [false, result.ERROR || 'Server error'];
  } catch (e) {
    return [false, e.message];
  }
}

export function clearAuth() {
  console.log('=== Clearing authentication state ===');
  JWT_TOKEN = null;
  SESSION_KEY_B64 = null;
  
  try {
    sessionStorage.removeItem('jwt_token');
    sessionStorage.removeItem('session_key');
  } catch (e) {
    console.warn('Failed to clear auth tokens from sessionStorage:', e);
  }
  
  console.log('Auth state after clearing:', getAuthState());
}

// Add this function to your src/api.js file

export async function deleteFile(fileId) {
  try {
    // Re-check authentication state from session storage if needed
    const authState = getAuthState();
    if (!authState.loggedIn) {
      return [false, 'Not logged in'];
    }

    const payload = JSON.stringify({ fileId: parseInt(fileId, 10) });
    const encrypted = encryptMessage(payload, authState.sessionKey);

    const response = await fetch(`${BASE_URL}/deleteFile`, {
      method: 'POST',
      headers: {
        'Content-Type': 'text/plain',
        'Authorization': authState.JWT, // Use the token from the auth state
      },
      body: encrypted,
    });

    const res = await response.json();
    if (!response.ok) {
      return [false, res.ERROR || 'Request failed'];
    }
    
    // Check for a specific error message from the backend
    if (res.ERROR && res.ERROR !== "") {
        return [false, res.ERROR];
    }

    return [true, ''];

  } catch (e) {
    return [false, e.message];
  }
}