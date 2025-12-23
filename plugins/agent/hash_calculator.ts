/**
 * Hash Calculator Tool
 * 
 * @plugin hash_calculator
 * @name Hash Calculator
 * @version 2.0.0
 * @author Sentinel Team
 * @category utility
 * @default_severity info
 * @tags hash, crypto, md5, sha256, security
 * @description Calculate cryptographic hashes for text or data using various algorithms
 */

/**
 * Tool input parameters
 */
interface ToolInput {
  /**
   * The text to hash
   * @example "password123"
   */
  text: string;
  
  /**
   * Hash algorithm to use
   * @default "sha256"
   */
  algorithm?: "md5" | "sha1" | "sha256" | "sha384" | "sha512";
  
  /**
   * Output format for the hash
   * @default "hex"
   */
  format?: "hex" | "base64";
  
  /**
   * Calculate HMAC with this key (optional)
   */
  hmacKey?: string;
}

interface ToolOutput {
  success: boolean;
  data?: {
    input: string;
    hash: string;
    algorithm: string;
    format: string;
    isHmac: boolean;
  };
  error?: string;
}

/**
 * Convert ArrayBuffer to hex string
 */
function bufferToHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * Convert ArrayBuffer to base64 string
 */
function bufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

/**
 * Map algorithm name to Web Crypto API name
 */
function getAlgorithmName(algo: string): string {
  const mapping: Record<string, string> = {
    'md5': 'MD5',
    'sha1': 'SHA-1',
    'sha256': 'SHA-256',
    'sha384': 'SHA-384',
    'sha512': 'SHA-512',
  };
  return mapping[algo.toLowerCase()] || 'SHA-256';
}

/**
 * Simple MD5 implementation (Web Crypto doesn't support MD5)
 */
function md5(str: string): string {
  // MD5 is not available in Web Crypto API
  // This is a simplified implementation for demonstration
  // In production, consider using a library
  
  function rotateLeft(x: number, n: number): number {
    return (x << n) | (x >>> (32 - n));
  }
  
  function addUnsigned(x: number, y: number): number {
    const lsw = (x & 0xFFFF) + (y & 0xFFFF);
    const msw = (x >> 16) + (y >> 16) + (lsw >> 16);
    return (msw << 16) | (lsw & 0xFFFF);
  }
  
  function F(x: number, y: number, z: number): number { return (x & y) | ((~x) & z); }
  function G(x: number, y: number, z: number): number { return (x & z) | (y & (~z)); }
  function H(x: number, y: number, z: number): number { return x ^ y ^ z; }
  function I(x: number, y: number, z: number): number { return y ^ (x | (~z)); }
  
  function FF(a: number, b: number, c: number, d: number, x: number, s: number, ac: number): number {
    a = addUnsigned(a, addUnsigned(addUnsigned(F(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function GG(a: number, b: number, c: number, d: number, x: number, s: number, ac: number): number {
    a = addUnsigned(a, addUnsigned(addUnsigned(G(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function HH(a: number, b: number, c: number, d: number, x: number, s: number, ac: number): number {
    a = addUnsigned(a, addUnsigned(addUnsigned(H(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  function II(a: number, b: number, c: number, d: number, x: number, s: number, ac: number): number {
    a = addUnsigned(a, addUnsigned(addUnsigned(I(b, c, d), x), ac));
    return addUnsigned(rotateLeft(a, s), b);
  }
  
  const bytes = new TextEncoder().encode(str);
  const wordArray: number[] = [];
  
  for (let i = 0; i < bytes.length; i++) {
    wordArray[i >> 2] |= bytes[i] << ((i % 4) * 8);
  }
  wordArray[bytes.length >> 2] |= 0x80 << ((bytes.length % 4) * 8);
  
  const numWords = ((bytes.length + 8) >>> 6) + 1;
  while (wordArray.length < numWords * 16) {
    wordArray.push(0);
  }
  wordArray[numWords * 16 - 2] = bytes.length * 8;
  
  let [a, b, c, d] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476];
  
  for (let i = 0; i < wordArray.length; i += 16) {
    const x = wordArray.slice(i, i + 16);
    const [aa, bb, cc, dd] = [a, b, c, d];
    
    a = FF(a, b, c, d, x[0], 7, 0xD76AA478);
    d = FF(d, a, b, c, x[1], 12, 0xE8C7B756);
    c = FF(c, d, a, b, x[2], 17, 0x242070DB);
    b = FF(b, c, d, a, x[3], 22, 0xC1BDCEEE);
    a = FF(a, b, c, d, x[4], 7, 0xF57C0FAF);
    d = FF(d, a, b, c, x[5], 12, 0x4787C62A);
    c = FF(c, d, a, b, x[6], 17, 0xA8304613);
    b = FF(b, c, d, a, x[7], 22, 0xFD469501);
    a = FF(a, b, c, d, x[8], 7, 0x698098D8);
    d = FF(d, a, b, c, x[9], 12, 0x8B44F7AF);
    c = FF(c, d, a, b, x[10], 17, 0xFFFF5BB1);
    b = FF(b, c, d, a, x[11], 22, 0x895CD7BE);
    a = FF(a, b, c, d, x[12], 7, 0x6B901122);
    d = FF(d, a, b, c, x[13], 12, 0xFD987193);
    c = FF(c, d, a, b, x[14], 17, 0xA679438E);
    b = FF(b, c, d, a, x[15], 22, 0x49B40821);
    
    a = GG(a, b, c, d, x[1], 5, 0xF61E2562);
    d = GG(d, a, b, c, x[6], 9, 0xC040B340);
    c = GG(c, d, a, b, x[11], 14, 0x265E5A51);
    b = GG(b, c, d, a, x[0], 20, 0xE9B6C7AA);
    a = GG(a, b, c, d, x[5], 5, 0xD62F105D);
    d = GG(d, a, b, c, x[10], 9, 0x02441453);
    c = GG(c, d, a, b, x[15], 14, 0xD8A1E681);
    b = GG(b, c, d, a, x[4], 20, 0xE7D3FBC8);
    a = GG(a, b, c, d, x[9], 5, 0x21E1CDE6);
    d = GG(d, a, b, c, x[14], 9, 0xC33707D6);
    c = GG(c, d, a, b, x[3], 14, 0xF4D50D87);
    b = GG(b, c, d, a, x[8], 20, 0x455A14ED);
    a = GG(a, b, c, d, x[13], 5, 0xA9E3E905);
    d = GG(d, a, b, c, x[2], 9, 0xFCEFA3F8);
    c = GG(c, d, a, b, x[7], 14, 0x676F02D9);
    b = GG(b, c, d, a, x[12], 20, 0x8D2A4C8A);
    
    a = HH(a, b, c, d, x[5], 4, 0xFFFA3942);
    d = HH(d, a, b, c, x[8], 11, 0x8771F681);
    c = HH(c, d, a, b, x[11], 16, 0x6D9D6122);
    b = HH(b, c, d, a, x[14], 23, 0xFDE5380C);
    a = HH(a, b, c, d, x[1], 4, 0xA4BEEA44);
    d = HH(d, a, b, c, x[4], 11, 0x4BDECFA9);
    c = HH(c, d, a, b, x[7], 16, 0xF6BB4B60);
    b = HH(b, c, d, a, x[10], 23, 0xBEBFBC70);
    a = HH(a, b, c, d, x[13], 4, 0x289B7EC6);
    d = HH(d, a, b, c, x[0], 11, 0xEAA127FA);
    c = HH(c, d, a, b, x[3], 16, 0xD4EF3085);
    b = HH(b, c, d, a, x[6], 23, 0x04881D05);
    a = HH(a, b, c, d, x[9], 4, 0xD9D4D039);
    d = HH(d, a, b, c, x[12], 11, 0xE6DB99E5);
    c = HH(c, d, a, b, x[15], 16, 0x1FA27CF8);
    b = HH(b, c, d, a, x[2], 23, 0xC4AC5665);
    
    a = II(a, b, c, d, x[0], 6, 0xF4292244);
    d = II(d, a, b, c, x[7], 10, 0x432AFF97);
    c = II(c, d, a, b, x[14], 15, 0xAB9423A7);
    b = II(b, c, d, a, x[5], 21, 0xFC93A039);
    a = II(a, b, c, d, x[12], 6, 0x655B59C3);
    d = II(d, a, b, c, x[3], 10, 0x8F0CCC92);
    c = II(c, d, a, b, x[10], 15, 0xFFEFF47D);
    b = II(b, c, d, a, x[1], 21, 0x85845DD1);
    a = II(a, b, c, d, x[8], 6, 0x6FA87E4F);
    d = II(d, a, b, c, x[15], 10, 0xFE2CE6E0);
    c = II(c, d, a, b, x[6], 15, 0xA3014314);
    b = II(b, c, d, a, x[13], 21, 0x4E0811A1);
    a = II(a, b, c, d, x[4], 6, 0xF7537E82);
    d = II(d, a, b, c, x[11], 10, 0xBD3AF235);
    c = II(c, d, a, b, x[2], 15, 0x2AD7D2BB);
    b = II(b, c, d, a, x[9], 21, 0xEB86D391);
    
    a = addUnsigned(a, aa);
    b = addUnsigned(b, bb);
    c = addUnsigned(c, cc);
    d = addUnsigned(d, dd);
  }
  
  const toHexStr = (n: number) => {
    let hex = '';
    for (let i = 0; i < 4; i++) {
      hex += ((n >> (i * 8)) & 0xFF).toString(16).padStart(2, '0');
    }
    return hex;
  };
  
  return toHexStr(a) + toHexStr(b) + toHexStr(c) + toHexStr(d);
}

/**
 * Main entry point for agent plugin
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
  const { text, algorithm = 'sha256', format = 'hex', hmacKey } = input;
  
  // Validate input
  if (!text || typeof text !== 'string') {
    return {
      success: false,
      error: 'Text parameter is required and must be a string'
    };
  }
  
  const validAlgorithms = ['md5', 'sha1', 'sha256', 'sha384', 'sha512'];
  if (!validAlgorithms.includes(algorithm.toLowerCase())) {
    return {
      success: false,
      error: `Invalid algorithm: ${algorithm}. Must be one of: ${validAlgorithms.join(', ')}`
    };
  }
  
  if (!['hex', 'base64'].includes(format)) {
    return {
      success: false,
      error: `Invalid format: ${format}. Must be "hex" or "base64"`
    };
  }
  
  try {
    let hashResult: string;
    const isHmac = !!hmacKey;
    
    // Handle MD5 separately (not in Web Crypto)
    if (algorithm.toLowerCase() === 'md5') {
      if (isHmac) {
        return {
          success: false,
          error: 'HMAC-MD5 is not supported. Use SHA-256 or higher for HMAC.'
        };
      }
      hashResult = md5(text);
      if (format === 'base64') {
        // Convert hex to base64
        const bytes = new Uint8Array(hashResult.match(/.{2}/g)!.map(b => parseInt(b, 16)));
        hashResult = bufferToBase64(bytes.buffer);
      }
    } else {
      // Use Web Crypto API
      const encoder = new TextEncoder();
      const data = encoder.encode(text);
      const algoName = getAlgorithmName(algorithm);
      
      let hashBuffer: ArrayBuffer;
      
      if (isHmac) {
        // HMAC calculation
        const keyData = encoder.encode(hmacKey);
        const cryptoKey = await crypto.subtle.importKey(
          'raw',
          keyData,
          { name: 'HMAC', hash: algoName },
          false,
          ['sign']
        );
        hashBuffer = await crypto.subtle.sign('HMAC', cryptoKey, data);
      } else {
        // Simple hash
        hashBuffer = await crypto.subtle.digest(algoName, data);
      }
      
      hashResult = format === 'hex'
        ? bufferToHex(hashBuffer)
        : bufferToBase64(hashBuffer);
    }
    
    return {
      success: true,
      data: {
        input: text.length > 100 ? text.substring(0, 100) + '...' : text,
        hash: hashResult,
        algorithm: algorithm.toUpperCase(),
        format,
        isHmac
      }
    };
  } catch (e) {
    return {
      success: false,
      error: `Hash calculation failed: ${e}`
    };
  }
}

// Required: bind to globalThis
globalThis.analyze = analyze;
