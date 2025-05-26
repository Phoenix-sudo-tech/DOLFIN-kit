
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Eye, Globe, Search, Database, MapPin } from 'lucide-react';

const ReconTools = () => {
  const [target, setTarget] = useState('');
  const [results, setResults] = useState<string[]>([]);
  const [isScanning, setIsScanning] = useState(false);

  const simulateWhoisLookup = async (domain: string) => {
    setIsScanning(true);
    setResults([]);
    
    // Simulate API call delay
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const mockResults = [
      `[+] WHOIS Lookup for: ${domain}`,
      `[+] Domain: ${domain}`,
      `[+] Registrar: SIMULATED_REGISTRAR_INC`,
      `[+] Creation Date: 2020-01-15`,
      `[+] Expiry Date: 2025-01-15`,
      `[+] Name Server: ns1.${domain}`,
      `[+] Name Server: ns2.${domain}`,
      `[+] Status: ACTIVE`,
      `[+] DNSSEC: Unsigned`,
      `[!] Note: This is simulated data for educational purposes`
    ];
    
    setResults(mockResults);
    setIsScanning(false);
  };

  const simulateDnsEnum = async (domain: string) => {
    setIsScanning(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 2500));
    
    const mockResults = [
      `[+] DNS Enumeration for: ${domain}`,
      `[+] A Record: ${domain} -> 192.168.1.100`,
      `[+] A Record: www.${domain} -> 192.168.1.100`,
      `[+] MX Record: mail.${domain} (Priority: 10)`,
      `[+] NS Record: ns1.${domain}`,
      `[+] NS Record: ns2.${domain}`,
      `[+] TXT Record: v=spf1 include:_spf.google.com ~all`,
      `[+] CNAME: ftp.${domain} -> ${domain}`,
      `[+] Subdomain found: admin.${domain}`,
      `[+] Subdomain found: mail.${domain}`,
      `[!] Note: This is simulated data for educational purposes`
    ];
    
    setResults(mockResults);
    setIsScanning(false);
  };

  const simulateSubdomainEnum = async (domain: string) => {
    setIsScanning(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const subdomains = ['www', 'mail', 'ftp', 'admin', 'test', 'dev', 'api', 'blog', 'shop', 'support'];
    const mockResults = [
      `[+] Subdomain Enumeration for: ${domain}`,
      `[+] Using wordlist: common_subdomains.txt`,
      `[+] Testing ${subdomains.length * 100} potential subdomains...`,
      ...subdomains.map(sub => `[+] Found: ${sub}.${domain} -> 192.168.1.${Math.floor(Math.random() * 254) + 1}`),
      `[+] Scan completed. Found ${subdomains.length} active subdomains`,
      `[!] Note: This is simulated data for educational purposes`
    ];
    
    setResults(mockResults);
    setIsScanning(false);
  };

  return (
    <div className="space-y-6">
      {/* Input Section */}
      <Card className="bg-black border-green-500">
        <CardHeader>
          <CardTitle className="text-green-400 font-mono flex items-center space-x-2">
            <Search className="h-5 w-5" />
            <span>[TARGET_INPUT]</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex space-x-2">
            <Input
              placeholder="Enter target domain (e.g., example.com)"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              className="bg-gray-900 border-green-500 text-green-400 font-mono"
            />
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Button
              onClick={() => target && simulateWhoisLookup(target)}
              disabled={!target || isScanning}
              className="bg-green-600 hover:bg-green-500 text-black font-mono"
            >
              <Globe className="h-4 w-4 mr-2" />
              WHOIS_LOOKUP
            </Button>
            
            <Button
              onClick={() => target && simulateDnsEnum(target)}
              disabled={!target || isScanning}
              className="bg-blue-600 hover:bg-blue-500 text-white font-mono"
            >
              <Database className="h-4 w-4 mr-2" />
              DNS_ENUM
            </Button>
            
            <Button
              onClick={() => target && simulateSubdomainEnum(target)}
              disabled={!target || isScanning}
              className="bg-purple-600 hover:bg-purple-500 text-white font-mono"
            >
              <MapPin className="h-4 w-4 mr-2" />
              SUBDOMAIN_ENUM
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Results Section */}
      <Card className="bg-black border-green-500">
        <CardHeader>
          <CardTitle className="text-green-400 font-mono flex items-center space-x-2">
            <Eye className="h-5 w-5" />
            <span>[SCAN_RESULTS]</span>
            {isScanning && <Badge className="bg-yellow-500 text-black animate-pulse">SCANNING...</Badge>}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-gray-900 rounded-lg p-4 font-mono text-sm max-h-96 overflow-y-auto">
            {results.length === 0 && !isScanning && (
              <p className="text-green-300">root@dolfin:~# Waiting for scan command...</p>
            )}
            {isScanning && (
              <div className="space-y-2">
                <p className="text-green-400">[*] Initializing scan...</p>
                <p className="text-green-400 animate-pulse">[*] Gathering target information...</p>
                <p className="text-green-400 animate-pulse">[*] Processing results...</p>
              </div>
            )}
            {results.map((result, index) => (
              <div key={index} className="text-green-300 mb-1">
                {result}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Tool Info */}
      <Card className="bg-gray-900 border-yellow-500">
        <CardHeader>
          <CardTitle className="text-yellow-400 font-mono">[RECONNAISSANCE_INFO]</CardTitle>
        </CardHeader>
        <CardContent className="text-yellow-300 font-mono text-sm space-y-2">
          <p>• WHOIS Lookup: Gather domain registration information</p>
          <p>• DNS Enumeration: Discover DNS records and subdomains</p>
          <p>• Subdomain Enumeration: Find hidden subdomains</p>
          <p>• All tools simulate realistic reconnaissance techniques</p>
          <p className="text-red-400">⚠ For educational and authorized testing only</p>
        </CardContent>
      </Card>
    </div>
  );
};

export default ReconTools;
