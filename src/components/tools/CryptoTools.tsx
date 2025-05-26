
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Lock, Key, Hash, Shield } from 'lucide-react';

const CryptoTools = () => {
  const [inputText, setInputText] = useState('');
  const [hashType, setHashType] = useState('');
  const [encryptionKey, setEncryptionKey] = useState('');
  const [results, setResults] = useState<string[]>([]);
  const [isProcessing, setIsProcessing] = useState(false);

  // Simple hash simulation (for educational purposes)
  const generateHash = async (text: string, type: string) => {
    setIsProcessing(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 1000));
    
    // Simulated hash outputs (not real cryptographic hashes)
    const hashes = {
      'md5': text.split('').reduce((a, b) => { a = ((a << 5) - a) + b.charCodeAt(0); return a & a; }, 0).toString(16).padStart(32, '0'),
      'sha1': text.split('').reduce((a, b) => { a = ((a << 5) - a) + b.charCodeAt(0); return a & a; }, 0).toString(16).padStart(40, '0'),
      'sha256': text.split('').reduce((a, b) => { a = ((a << 5) - a) + b.charCodeAt(0); return a & a; }, 0).toString(16).padStart(64, '0'),
      'sha512': text.split('').reduce((a, b) => { a = ((a << 5) - a) + b.charCodeAt(0); return a & a; }, 0).toString(16).padStart(128, '0')
    };
    
    const mockResults = [
      `[+] Hash Generator - Algorithm: ${type.toUpperCase()}`,
      `[+] Input: "${text}"`,
      `[+] Input Length: ${text.length} characters`,
      '',
      '[+] Hash Output:',
      hashes[type as keyof typeof hashes] || 'Unknown algorithm',
      '',
      '[+] Hash Properties:',
      `• Algorithm: ${type.toUpperCase()}`,
      `• Output Length: ${type === 'md5' ? '128 bits' : type === 'sha1' ? '160 bits' : type === 'sha256' ? '256 bits' : '512 bits'}`,
      `• Hexadecimal representation`,
      `• One-way function (irreversible)`,
      '',
      '[+] Common Uses:',
      '• Password storage (with salt)',
      '• File integrity verification',
      '• Digital signatures',
      '• Blockchain applications',
      '',
      '[!] Security Notes:',
      type === 'md5' ? '• MD5 is cryptographically broken' : '',
      type === 'sha1' ? '• SHA1 is deprecated for security applications' : '',
      '• Always use salt for password hashing',
      '• Consider bcrypt/scrypt for passwords',
      '',
      '[!] EDUCATIONAL SIMULATION - Not cryptographically secure'
    ].filter(line => line !== '');
    
    setResults(mockResults);
    setIsProcessing(false);
  };

  const simulatePasswordCracking = async (hash: string) => {
    setIsProcessing(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const commonPasswords = ['password', '123456', 'admin', 'letmein', 'welcome', 'qwerty'];
    const crackedPassword = commonPasswords[Math.floor(Math.random() * commonPasswords.length)];
    
    const mockResults = [
      `[+] Password Hash Cracking Simulation`,
      `[+] Target Hash: ${hash.substring(0, 20)}...`,
      `[+] Attack Type: Dictionary Attack`,
      '',
      '[+] Loading wordlists...',
      '[+] Wordlist: rockyou.txt (14,344,391 passwords)',
      '[+] Wordlist: common_passwords.txt (10,000 passwords)',
      '',
      '[+] Cracking Progress:',
      '[*] Trying passwords: 0-1000... No match',
      '[*] Trying passwords: 1000-2000... No match',
      '[*] Trying passwords: 2000-3000... No match',
      '[*] Trying passwords: 3000-4000... MATCH FOUND!',
      '',
      `[!] PASSWORD CRACKED: ${crackedPassword}`,
      `[+] Time taken: 0.85 seconds`,
      `[+] Attempts: 3,247`,
      '',
      '[+] Cracking Statistics:',
      '• Hash rate: 3,820 hashes/second',
      '• Success rate: 87% (common passwords)',
      '• Average time: 2.3 seconds',
      '',
      '[!] Defense Recommendations:',
      '• Use strong, unique passwords (12+ characters)',
      '• Include uppercase, lowercase, numbers, symbols',
      '• Avoid dictionary words and personal information',
      '• Use password managers',
      '• Implement account lockout policies',
      '',
      '[!] EDUCATIONAL DEMONSTRATION ONLY'
    ];
    
    setResults(mockResults);
    setIsProcessing(false);
  };

  const analyzeEncryption = async (text: string, key: string) => {
    setIsProcessing(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    // Simple Caesar cipher for demonstration
    const shift = key.length % 26;
    const encrypted = text.split('').map(char => {
      if (char.match(/[a-z]/i)) {
        const code = char.charCodeAt(0);
        const base = code >= 65 && code <= 90 ? 65 : 97;
        return String.fromCharCode(((code - base + shift) % 26) + base);
      }
      return char;
    }).join('');
    
    const mockResults = [
      `[+] Encryption Analysis Tool`,
      `[+] Plaintext: "${text}"`,
      `[+] Key: "${key}"`,
      `[+] Algorithm: Educational Caesar Cipher`,
      '',
      '[+] Encryption Process:',
      `[+] Key length: ${key.length}`,
      `[+] Shift value: ${shift}`,
      `[+] Character mapping: A->Z substitution`,
      '',
      '[+] Encrypted Output:',
      encrypted,
      '',
      '[+] Cipher Analysis:',
      '• Type: Substitution cipher',
      '• Key space: 26 possible keys',
      '• Vulnerability: Frequency analysis',
      '• Cracking time: <1 second (brute force)',
      '',
      '[+] Modern Encryption Alternatives:',
      '• AES-256 (Advanced Encryption Standard)',
      '• ChaCha20-Poly1305',
      '• RSA-4096 (asymmetric)',
      '• Elliptic Curve Cryptography',
      '',
      '[!] EDUCATIONAL CIPHER ONLY',
      '[!] Never use Caesar cipher for real security applications'
    ];
    
    setResults(mockResults);
    setIsProcessing(false);
  };

  return (
    <div className="space-y-6">
      {/* Input Section */}
      <Card className="bg-black border-cyan-500">
        <CardHeader>
          <CardTitle className="text-cyan-400 font-mono flex items-center space-x-2">
            <Lock className="h-5 w-5" />
            <span>[CRYPTOGRAPHIC_ANALYSIS_SUITE]</span>
          </CardTitle>
          <CardDescription className="text-cyan-300 font-mono">
            Educational cryptography and hash analysis tools
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-green-400 font-mono text-sm mb-2 block">INPUT_TEXT:</label>
            <Textarea
              placeholder="Enter text to analyze..."
              value={inputText}
              onChange={(e) => setInputText(e.target.value)}
              className="bg-gray-900 border-cyan-500 text-green-400 font-mono h-24"
            />
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-green-400 font-mono text-sm mb-2 block">HASH_ALGORITHM:</label>
              <Select value={hashType} onValueChange={setHashType}>
                <SelectTrigger className="bg-gray-900 border-cyan-500 text-green-400 font-mono">
                  <SelectValue placeholder="Select hash type" />
                </SelectTrigger>
                <SelectContent className="bg-gray-900 border-cyan-500">
                  <SelectItem value="md5" className="text-green-400 font-mono">MD5 (deprecated)</SelectItem>
                  <SelectItem value="sha1" className="text-green-400 font-mono">SHA-1 (deprecated)</SelectItem>
                  <SelectItem value="sha256" className="text-green-400 font-mono">SHA-256</SelectItem>
                  <SelectItem value="sha512" className="text-green-400 font-mono">SHA-512</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-green-400 font-mono text-sm mb-2 block">ENCRYPTION_KEY:</label>
              <Input
                placeholder="Enter encryption key..."
                value={encryptionKey}
                onChange={(e) => setEncryptionKey(e.target.value)}
                className="bg-gray-900 border-cyan-500 text-green-400 font-mono"
              />
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Button
              onClick={() => inputText && hashType && generateHash(inputText, hashType)}
              disabled={!inputText || !hashType || isProcessing}
              className="bg-cyan-600 hover:bg-cyan-500 text-black font-mono"
            >
              <Hash className="h-4 w-4 mr-2" />
              GENERATE_HASH
            </Button>
            
            <Button
              onClick={() => inputText && simulatePasswordCracking(inputText)}
              disabled={!inputText || isProcessing}
              className="bg-red-600 hover:bg-red-500 text-white font-mono"
            >
              <Key className="h-4 w-4 mr-2" />
              CRACK_HASH
            </Button>
            
            <Button
              onClick={() => inputText && encryptionKey && analyzeEncryption(inputText, encryptionKey)}
              disabled={!inputText || !encryptionKey || isProcessing}
              className="bg-purple-600 hover:bg-purple-500 text-white font-mono"
            >
              <Shield className="h-4 w-4 mr-2" />
              ENCRYPT_ANALYZE
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Results Section */}
      <Card className="bg-black border-cyan-500">
        <CardHeader>
          <CardTitle className="text-cyan-400 font-mono flex items-center space-x-2">
            <Lock className="h-5 w-5" />
            <span>[CRYPTO_ANALYSIS_OUTPUT]</span>
            {isProcessing && <Badge className="bg-cyan-500 text-black animate-pulse">PROCESSING...</Badge>}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-gray-900 rounded-lg p-4 font-mono text-sm max-h-96 overflow-y-auto">
            {results.length === 0 && !isProcessing && (
              <p className="text-green-300">root@dolfin:~# Cryptographic analysis tools ready...</p>
            )}
            {isProcessing && (
              <div className="space-y-2">
                <p className="text-cyan-400">[*] Processing cryptographic operation...</p>
                <p className="text-cyan-400 animate-pulse">[*] Calculating hash values...</p>
                <p className="text-cyan-400 animate-pulse">[*] Running analysis algorithms...</p>
              </div>
            )}
            {results.map((result, index) => (
              <div key={index} className={`mb-1 ${
                result.includes('[!]') && (result.includes('CRACKED') || result.includes('MATCH')) ? 'text-red-400 font-bold' :
                result.includes('[!]') && result.includes('EDUCATIONAL') ? 'text-green-400' :
                result.includes('[!]') ? 'text-orange-400' :
                result.includes('[+]') ? 'text-cyan-400' :
                result.includes('•') ? 'text-yellow-400' :
                'text-green-300'
              }`}>
                {result}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Tool Info */}
      <Card className="bg-gray-900 border-yellow-500">
        <CardHeader>
          <CardTitle className="text-yellow-400 font-mono">[CRYPTO_TOOLS_INFO]</CardTitle>
        </CardHeader>
        <CardContent className="text-yellow-300 font-mono text-sm space-y-2">
          <p>• Hash Generator: Create cryptographic hashes for analysis</p>
          <p>• Password Cracking: Simulate dictionary and brute force attacks</p>
          <p>• Encryption Analysis: Educational cipher implementation and analysis</p>
          <p>• All cryptographic operations are educational simulations</p>
          <p className="text-red-400">⚠ Educational simulations only - not cryptographically secure</p>
          <p className="text-red-400">⚠ Use proper cryptographic libraries in production</p>
        </CardContent>
      </Card>
    </div>
  );
};

export default CryptoTools;
