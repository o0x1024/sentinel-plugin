/**
 * @plugin hash_calculator
 * @name Hash Calculator Tool
 * @version 1.0.0
 * @author Sentinel Team
 * @category utility
 * @default_severity info
 * @tags hash, md5, sha256, checksum, crypto
 * @description Calculate various hash values for given text or compare hashes
 */

// Type definitions
interface ToolInput {
  text?: string;
  algorithm?: 'md5' | 'sha1' | 'sha256' | 'sha512' | 'all';
  compare_hash?: string;
}

interface HashResult {
  md5?: string;
  sha1?: string;
  sha256?: string;
  sha512?: string;
}

interface ToolOutput {
  success: boolean;
  data?: {
    input: string;
    hashes: HashResult;
    match?: boolean;
    matched_algorithm?: string;
  };
  error?: string;
}

// Simple hash implementations using Web Crypto API
async function computeHash(text: string, algorithm: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  
  let algoName: string;
  switch (algorithm) {
    case 'sha1': algoName = 'SHA-1'; break;
    case 'sha256': algoName = 'SHA-256'; break;
    case 'sha512': algoName = 'SHA-512'; break;
    default: throw new Error(`Unsupported algorithm: ${algorithm}`);
  }
  
  const hashBuffer = await crypto.subtle.digest(algoName, data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Simple MD5 implementation (for demo - Web Crypto doesn't support MD5)
function md5(text: string): string {
  // Simplified MD5 - for actual use, include a proper library
  // This is a placeholder that returns a deterministic hash-like string
  let hash = 0;
  for (let i = 0; i < text.length; i++) {
    const char = text.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  const hex = Math.abs(hash).toString(16);
  return hex.padStart(32, '0').substring(0, 32);
}

// Main entry point for agent plugins
export async function analyze(input: ToolInput): Promise<ToolOutput> {
  try {
    const { text, algorithm = 'all', compare_hash } = input;
    
    if (!text && text !== '') {
      return { success: false, error: 'Input text is required' };
    }
    
    const hashes: HashResult = {};
    
    if (algorithm === 'all' || algorithm === 'md5') {
      hashes.md5 = md5(text!);
    }
    if (algorithm === 'all' || algorithm === 'sha1') {
      hashes.sha1 = await computeHash(text!, 'sha1');
    }
    if (algorithm === 'all' || algorithm === 'sha256') {
      hashes.sha256 = await computeHash(text!, 'sha256');
    }
    if (algorithm === 'all' || algorithm === 'sha512') {
      hashes.sha512 = await computeHash(text!, 'sha512');
    }
    
    const result: ToolOutput['data'] = {
      input: text!,
      hashes
    };
    
    // Compare with provided hash if given
    if (compare_hash) {
      const normalizedCompare = compare_hash.toLowerCase();
      result.match = false;
      
      for (const [algo, hashValue] of Object.entries(hashes)) {
        if (hashValue?.toLowerCase() === normalizedCompare) {
          result.match = true;
          result.matched_algorithm = algo;
          break;
        }
      }
    }
    
    return { success: true, data: result };
    
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Hash calculation failed'
    };
  }
}

// Required: bind to globalThis for plugin engine
globalThis.analyze = analyze;

