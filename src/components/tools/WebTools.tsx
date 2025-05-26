
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Textarea } from "@/components/ui/textarea";
import { Globe, Bug, Shield, Code } from 'lucide-react';

const WebTools = () => {
  const [targetUrl, setTargetUrl] = useState('');
  const [sqlPayload, setSqlPayload] = useState("' OR 1=1 --");
  const [xssPayload, setXssPayload] = useState('<script>alert("XSS")</script>');
  const [results, setResults] = useState<string[]>([]);
  const [isScanning, setIsScanning] = useState(false);

  const simulateSqlInjection = async (url: string, payload: string) => {
    setIsScanning(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const mockResults = [
      `[+] SQL Injection Test for: ${url}`,
      `[+] Payload: ${payload}`,
      `[+] Testing common injection points...`,
      '',
      '[+] Parameter Analysis:',
      '[!] VULNERABLE: id parameter (GET)',
      '[+] Safe: username parameter (POST)',
      '[!] VULNERABLE: search parameter (GET)',
      '',
      '[+] Database Information:',
      '[+] Database Type: MySQL 5.7.33',
      '[+] Database Name: webapp_db',
      '[+] Tables Found: users, products, orders',
      '[+] Columns in users: id, username, password, email',
      '',
      '[!] CRITICAL: Password hashes extracted',
      '[!] Recommend: Input sanitization & parameterized queries',
      `[!] Note: This is simulated data for educational purposes`
    ];
    
    setResults(mockResults);
    setIsScanning(false);
  };

  const simulateXssTest = async (url: string, payload: string) => {
    setIsScanning(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 2500));
    
    const mockResults = [
      `[+] XSS Vulnerability Test for: ${url}`,
      `[+] Payload: ${payload}`,
      `[+] Testing for Cross-Site Scripting vulnerabilities...`,
      '',
      '[+] Reflected XSS Test:',
      '[!] VULNERABLE: search parameter reflects input',
      '[!] VULNERABLE: error message displays unescaped input',
      '',
      '[+] Stored XSS Test:',
      '[!] VULNERABLE: comment field stores malicious scripts',
      '[+] Safe: username field properly sanitized',
      '',
      '[+] DOM-based XSS Test:',
      '[!] VULNERABLE: URL fragment processed by JavaScript',
      '',
      '[!] Potential Impact: Session hijacking, data theft',
      '[!] Recommend: Input validation, output encoding, CSP headers',
      `[!] Note: This is simulated data for educational purposes`
    ];
    
    setResults(mockResults);
    setIsScanning(false);
  };

  const simulateWebVulnScan = async (url: string) => {
    setIsScanning(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 4000));
    
    const mockResults = [
      `[+] Comprehensive Web Vulnerability Scan for: ${url}`,
      `[+] Scanning for OWASP Top 10 vulnerabilities...`,
      '',
      '[+] Security Headers Analysis:',
      '[!] Missing: X-Frame-Options (Clickjacking risk)',
      '[!] Missing: Content-Security-Policy',
      '[+] Present: X-XSS-Protection',
      '[!] Weak: X-Content-Type-Options',
      '',
      '[+] SSL/TLS Configuration:',
      '[+] Certificate valid and properly configured',
      '[!] Weak cipher suites detected',
      '[!] TLS 1.0 still supported (deprecated)',
      '',
      '[+] Directory Traversal Test:',
      '[!] VULNERABLE: ../../../etc/passwd accessible',
      '',
      '[+] File Upload Security:',
      '[!] VULNERABLE: No file type validation',
      '[!] VULNERABLE: Executable files can be uploaded',
      '',
      '[+] Session Management:',
      '[!] Session cookies not marked as Secure',
      '[!] No session timeout implemented',
      '',
      `[+] Scan completed. Found 8 vulnerabilities`,
      `[!] Note: This is simulated data for educational purposes`
    ];
    
    setResults(mockResults);
    setIsScanning(false);
  };

  return (
    <div className="space-y-6">
      {/* Input Section */}
      <Card className="bg-black border-purple-500">
        <CardHeader>
          <CardTitle className="text-purple-400 font-mono flex items-center space-x-2">
            <Globe className="h-5 w-5" />
            <span>[WEB_APPLICATION_SCANNER]</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <label className="text-green-400 font-mono text-sm mb-2 block">TARGET_URL:</label>
            <Input
              placeholder="https://example.com/vulnerable.php?id=1"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              className="bg-gray-900 border-purple-500 text-green-400 font-mono"
            />
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-green-400 font-mono text-sm mb-2 block">SQL_PAYLOAD:</label>
              <Input
                value={sqlPayload}
                onChange={(e) => setSqlPayload(e.target.value)}
                className="bg-gray-900 border-purple-500 text-green-400 font-mono text-xs"
              />
            </div>
            <div>
              <label className="text-green-400 font-mono text-sm mb-2 block">XSS_PAYLOAD:</label>
              <Input
                value={xssPayload}
                onChange={(e) => setXssPayload(e.target.value)}
                className="bg-gray-900 border-purple-500 text-green-400 font-mono text-xs"
              />
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Button
              onClick={() => targetUrl && simulateSqlInjection(targetUrl, sqlPayload)}
              disabled={!targetUrl || isScanning}
              className="bg-purple-600 hover:bg-purple-500 text-white font-mono"
            >
              <Bug className="h-4 w-4 mr-2" />
              SQL_INJECT
            </Button>
            
            <Button
              onClick={() => targetUrl && simulateXssTest(targetUrl, xssPayload)}
              disabled={!targetUrl || isScanning}
              className="bg-red-600 hover:bg-red-500 text-white font-mono"
            >
              <Code className="h-4 w-4 mr-2" />
              XSS_TEST
            </Button>
            
            <Button
              onClick={() => targetUrl && simulateWebVulnScan(targetUrl)}
              disabled={!targetUrl || isScanning}
              className="bg-orange-600 hover:bg-orange-500 text-white font-mono"
            >
              <Shield className="h-4 w-4 mr-2" />
              FULL_SCAN
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Results Section */}
      <Card className="bg-black border-purple-500">
        <CardHeader>
          <CardTitle className="text-purple-400 font-mono flex items-center space-x-2">
            <Bug className="h-5 w-5" />
            <span>[VULNERABILITY_RESULTS]</span>
            {isScanning && <Badge className="bg-purple-500 text-white animate-pulse">TESTING...</Badge>}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-gray-900 rounded-lg p-4 font-mono text-sm max-h-96 overflow-y-auto">
            {results.length === 0 && !isScanning && (
              <p className="text-green-300">root@dolfin:~# Ready to test web applications...</p>
            )}
            {isScanning && (
              <div className="space-y-2">
                <p className="text-purple-400">[*] Initializing web vulnerability scanner...</p>
                <p className="text-purple-400 animate-pulse">[*] Testing injection points...</p>
                <p className="text-purple-400 animate-pulse">[*] Analyzing responses...</p>
              </div>
            )}
            {results.map((result, index) => (
              <div key={index} className={`mb-1 ${
                result.includes('[!]') && result.includes('VULNERABLE') ? 'text-red-400' :
                result.includes('[!]') ? 'text-orange-400' :
                result.includes('[+]') ? 'text-green-400' :
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
          <CardTitle className="text-yellow-400 font-mono">[WEB_TESTING_INFO]</CardTitle>
        </CardHeader>
        <CardContent className="text-yellow-300 font-mono text-sm space-y-2">
          <p>• SQL Injection: Test for database vulnerabilities</p>
          <p>• XSS Testing: Cross-site scripting vulnerability detection</p>
          <p>• Full Scan: Comprehensive OWASP Top 10 assessment</p>
          <p>• Custom payloads for advanced testing scenarios</p>
          <p className="text-red-400">⚠ Only test applications you own or have permission to test</p>
        </CardContent>
      </Card>
    </div>
  );
};

export default WebTools;
