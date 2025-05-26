
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Network, Shield, Zap, Search } from 'lucide-react';

const NetworkTools = () => {
  const [target, setTarget] = useState('');
  const [portRange, setPortRange] = useState('1-1000');
  const [results, setResults] = useState<string[]>([]);
  const [isScanning, setIsScanning] = useState(false);

  const simulatePortScan = async (targetIp: string, ports: string) => {
    setIsScanning(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const openPorts = [21, 22, 53, 80, 443, 993, 995];
    const mockResults = [
      `[+] Port Scan Results for: ${targetIp}`,
      `[+] Scan Type: TCP SYN Scan`,
      `[+] Port Range: ${ports}`,
      `[+] Host is up (0.025s latency)`,
      `[+] Scanning ${ports.split('-').length > 1 ? 'range' : 'single port'}...`,
      '',
      '[+] Open Ports:',
      ...openPorts.map(port => {
        const services = {
          21: 'ftp',
          22: 'ssh',
          53: 'domain',
          80: 'http',
          443: 'https',
          993: 'imaps',
          995: 'pop3s'
        };
        return `[+] ${port}/tcp open ${services[port as keyof typeof services] || 'unknown'}`;
      }),
      '',
      `[+] Scan completed in 2.85 seconds`,
      `[!] Note: This is simulated data for educational purposes`
    ];
    
    setResults(mockResults);
    setIsScanning(false);
  };

  const simulateVulnScan = async (targetIp: string) => {
    setIsScanning(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 4000));
    
    const mockResults = [
      `[+] Vulnerability Scan for: ${targetIp}`,
      `[+] Using NSE vulnerability scripts...`,
      `[+] Testing for common vulnerabilities...`,
      '',
      '[+] Vulnerability Assessment Results:',
      '[!] CVE-2021-34527 (PrintNightmare) - CRITICAL',
      '[!] CVE-2020-1472 (Zerologon) - HIGH',
      '[+] CVE-2019-0708 (BlueKeep) - Not Vulnerable',
      '[+] CVE-2017-0144 (EternalBlue) - Patched',
      '[!] Weak SSH Configuration - MEDIUM',
      '[!] HTTP Security Headers Missing - LOW',
      '',
      '[+] Total vulnerabilities found: 3',
      '[+] Critical: 1, High: 1, Medium: 1, Low: 1',
      `[!] Note: This is simulated data for educational purposes`
    ];
    
    setResults(mockResults);
    setIsScanning(false);
  };

  const simulateBannerGrab = async (targetIp: string) => {
    setIsScanning(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const mockResults = [
      `[+] Banner Grabbing for: ${targetIp}`,
      `[+] Attempting to grab service banners...`,
      '',
      '[+] Port 22/tcp (SSH):',
      'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3',
      '',
      '[+] Port 80/tcp (HTTP):',
      'Server: Apache/2.4.41 (Ubuntu)',
      'X-Powered-By: PHP/7.4.3',
      '',
      '[+] Port 443/tcp (HTTPS):',
      'Server: nginx/1.18.0 (Ubuntu)',
      'SSL Certificate: example.com (Valid until: 2024-12-31)',
      '',
      '[+] Port 21/tcp (FTP):',
      '220 ProFTPD Server (ProFTPD Default Installation)',
      '',
      `[+] Banner grabbing completed`,
      `[!] Note: This is simulated data for educational purposes`
    ];
    
    setResults(mockResults);
    setIsScanning(false);
  };

  return (
    <div className="space-y-6">
      {/* Input Section */}
      <Card className="bg-black border-red-500">
        <CardHeader>
          <CardTitle className="text-red-400 font-mono flex items-center space-x-2">
            <Network className="h-5 w-5" />
            <span>[NETWORK_SCANNER]</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-green-400 font-mono text-sm mb-2 block">TARGET_IP:</label>
              <Input
                placeholder="192.168.1.1 or example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                className="bg-gray-900 border-red-500 text-green-400 font-mono"
              />
            </div>
            <div>
              <label className="text-green-400 font-mono text-sm mb-2 block">PORT_RANGE:</label>
              <Input
                placeholder="1-1000 or 80,443,22"
                value={portRange}
                onChange={(e) => setPortRange(e.target.value)}
                className="bg-gray-900 border-red-500 text-green-400 font-mono"
              />
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Button
              onClick={() => target && simulatePortScan(target, portRange)}
              disabled={!target || isScanning}
              className="bg-red-600 hover:bg-red-500 text-white font-mono"
            >
              <Search className="h-4 w-4 mr-2" />
              PORT_SCAN
            </Button>
            
            <Button
              onClick={() => target && simulateVulnScan(target)}
              disabled={!target || isScanning}
              className="bg-orange-600 hover:bg-orange-500 text-white font-mono"
            >
              <Shield className="h-4 w-4 mr-2" />
              VULN_SCAN
            </Button>
            
            <Button
              onClick={() => target && simulateBannerGrab(target)}
              disabled={!target || isScanning}
              className="bg-yellow-600 hover:bg-yellow-500 text-black font-mono"
            >
              <Zap className="h-4 w-4 mr-2" />
              BANNER_GRAB
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Results Section */}
      <Card className="bg-black border-red-500">
        <CardHeader>
          <CardTitle className="text-red-400 font-mono flex items-center space-x-2">
            <Network className="h-5 w-5" />
            <span>[SCAN_OUTPUT]</span>
            {isScanning && <Badge className="bg-red-500 text-white animate-pulse">SCANNING...</Badge>}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-gray-900 rounded-lg p-4 font-mono text-sm max-h-96 overflow-y-auto">
            {results.length === 0 && !isScanning && (
              <p className="text-green-300">root@dolfin:~# Ready to scan network targets...</p>
            )}
            {isScanning && (
              <div className="space-y-2">
                <p className="text-red-400">[*] Initializing network scan...</p>
                <p className="text-red-400 animate-pulse">[*] Probing target ports...</p>
                <p className="text-red-400 animate-pulse">[*] Analyzing responses...</p>
              </div>
            )}
            {results.map((result, index) => (
              <div key={index} className={`mb-1 ${
                result.includes('[!]') ? 'text-red-400' :
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
          <CardTitle className="text-yellow-400 font-mono">[NETWORK_TOOLS_INFO]</CardTitle>
        </CardHeader>
        <CardContent className="text-yellow-300 font-mono text-sm space-y-2">
          <p>• Port Scan: Discover open ports and services</p>
          <p>• Vulnerability Scan: Identify security weaknesses</p>
          <p>• Banner Grabbing: Extract service version information</p>
          <p>• All scans use simulated nmap-style techniques</p>
          <p className="text-red-400">⚠ Only scan networks you own or have permission to test</p>
        </CardContent>
      </Card>
    </div>
  );
};

export default NetworkTools;
