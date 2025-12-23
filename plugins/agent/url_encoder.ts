/**
 * @plugin url_encoder
 * @name URL Encoder/Decoder Tool
 * @version 1.0.0
 * @author Sentinel Team
 * @category utility
 * @default_severity info
 * @tags encoding, url, utility, decoder
 * @description A utility tool for encoding and decoding URLs with multiple schemes
 */

// Type definitions
interface ToolInput {
  text: string;
  action: 'encode' | 'decode' | 'encode_component' | 'decode_component' | 'base64_encode' | 'base64_decode';
  double?: boolean;
}

interface ToolOutput {
  success: boolean;
  data?: {
    input: string;
    output: string;
    action: string;
  };
  error?: string;
}

// Main entry point for agent plugins
export async function analyze(input: ToolInput): Promise<ToolOutput> {
  try {
    const { text, action, double } = input;
    
    if (!text && text !== '') {
      return { success: false, error: 'Input text is required' };
    }
    
    let result: string;
    
    switch (action) {
      case 'encode':
        result = encodeURI(text);
        if (double) result = encodeURI(result);
        break;
        
      case 'decode':
        result = decodeURI(text);
        if (double) result = decodeURI(result);
        break;
        
      case 'encode_component':
        result = encodeURIComponent(text);
        if (double) result = encodeURIComponent(result);
        break;
        
      case 'decode_component':
        result = decodeURIComponent(text);
        if (double) result = decodeURIComponent(result);
        break;
        
      case 'base64_encode':
        result = btoa(text);
        if (double) result = btoa(result);
        break;
        
      case 'base64_decode':
        result = atob(text);
        if (double) result = atob(result);
        break;
        
      default:
        return {
          success: false,
          error: `Unknown action: ${action}. Valid: encode, decode, encode_component, decode_component, base64_encode, base64_decode`
        };
    }
    
    return {
      success: true,
      data: { input: text, output: result, action }
    };
    
  } catch (error) {
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Encoding/decoding failed'
    };
  }
}

// Required: bind to globalThis for plugin engine
globalThis.analyze = analyze;
