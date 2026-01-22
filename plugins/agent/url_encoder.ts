/**
 * URL Encoder/Decoder Tool
 * 
 * @plugin url_encoder
 * @name URL Encoder
 * @version 2.1.0
 * @author Sentinel Team
 * @category utility
 * @default_severity info
 * @tags encoding, url, base64, html, utility
 * @description Encode and decode text using various encoding schemes (URL, Base64, HTML entities)
 */

declare const SecurityUtils: {
  urlEncode: (str: string) => string;
  urlDecode: (str: string) => string;
  htmlEncode: (str: string) => string;
  htmlDecode: (str: string) => string;
  hexEncode: (str: string) => string;
  hexDecode: (hex: string) => string;
};

/**
 * Tool input parameters
 */
interface ToolInput {
  text: string;
  mode: "encode" | "decode";
  encoding?: "url" | "base64" | "html" | "hex" | "unicode";
}

/**
 * 【方案2】导出参数 Schema 函数
 * 
 * 这是最优雅的方式：插件自己告诉引擎它需要什么参数。
 * 引擎加载插件后会调用此函数获取参数说明。
 */
export function get_input_schema() {
  return {
    type: "object",
    required: ["text", "mode"],
    properties: {
      text: {
        type: "string",
        description: "要编码或解码的文本"
      },
      mode: {
        type: "string",
        enum: ["encode", "decode"],
        description: "操作模式：encode=编码, decode=解码",
        default: "encode"
      },
      encoding: {
        type: "string",
        enum: ["url", "base64", "html", "hex", "unicode"],
        description: "编码类型",
        default: "url"
      }
    }
  };
}

// 绑定到 globalThis
globalThis.get_input_schema = get_input_schema;

/**
 * Export output schema
 */
export function get_output_schema() {
    return {
        type: "object",
        properties: {
            success: { type: "boolean", description: "Whether the operation succeeded" },
            data: {
                type: "object",
                properties: {
                    input: { type: "string", description: "Original input text" },
                    output: { type: "string", description: "Encoded/decoded result" },
                    mode: { type: "string", description: "encode or decode" },
                    encoding: { type: "string", description: "Encoding type used" }
                }
            },
            error: { type: "string", description: "Error message if failed" }
        }
    };
}

globalThis.get_output_schema = get_output_schema;

interface ToolOutput {
  success: boolean;
  data?: {
    input: string;
    output: string;
    mode: string;
    encoding: string;
  };
  error?: string;
}

/**
 * Encode text using various schemes
 */
function encodeText(text: string, encoding: string): string {
  switch (encoding) {
    case 'url':
      return encodeURIComponent(text);
    
    case 'base64':
      return btoa(unescape(encodeURIComponent(text)));
    
    case 'html':
      return SecurityUtils.htmlEncode(text);
    
    case 'hex':
      return SecurityUtils.hexEncode(text);
    
    case 'unicode':
      return text.split('').map(char => {
        const code = char.charCodeAt(0);
        if (code > 127) {
          return '\\u' + code.toString(16).padStart(4, '0');
        }
        return char;
      }).join('');
    
    default:
      return encodeURIComponent(text);
  }
}

/**
 * Decode text using various schemes
 */
function decodeText(text: string, encoding: string): string {
  switch (encoding) {
    case 'url':
      return decodeURIComponent(text);
    
    case 'base64':
      return decodeURIComponent(escape(atob(text)));
    
    case 'html':
      return SecurityUtils.htmlDecode(text);
    
    case 'hex':
      return SecurityUtils.hexDecode(text);
    
    case 'unicode':
      return text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => {
        return String.fromCharCode(parseInt(hex, 16));
      });
    
    default:
      return decodeURIComponent(text);
  }
}

/**
 * Main entry point for agent plugin
 */
export async function analyze(input: ToolInput): Promise<ToolOutput> {
  const { text, mode = 'encode', encoding = 'url' } = input;
  
  // Validate input
  if (!text || typeof text !== 'string') {
    return {
      success: false,
      error: 'Text parameter is required and must be a string'
    };
  }
  
  if (!['encode', 'decode'].includes(mode)) {
    return {
      success: false,
      error: `Invalid mode: ${mode}. Must be "encode" or "decode"`
    };
  }
  
  const validEncodings = ['url', 'base64', 'html', 'hex', 'unicode'];
  if (!validEncodings.includes(encoding)) {
    return {
      success: false,
      error: `Invalid encoding: ${encoding}. Must be one of: ${validEncodings.join(', ')}`
    };
  }
  
  try {
    const output = mode === 'encode'
      ? encodeText(text, encoding)
      : decodeText(text, encoding);
    
    return {
      success: true,
      data: {
        input: text,
        output,
        mode,
        encoding
      }
    };
  } catch (e) {
    return {
      success: false,
      error: `${mode === 'encode' ? 'Encoding' : 'Decoding'} failed: ${e}`
    };
  }
}

// Required: bind to globalThis
globalThis.analyze = analyze;
