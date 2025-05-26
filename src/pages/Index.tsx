import React, { useState, useEffect } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, Eye, Network, Database, Lock, AlertTriangle, BookOpen, Code, Terminal, Users, Globe, Server } from 'lucide-react';
import SecurityModuleCard from '../components/SecurityModuleCard';
import EducationalContent from '../components/EducationalContent';
import DefenseStrategies from '../components/DefenseStrategies';
import HackingTools from '../components/HackingTools';
import LoadingScreen from '../components/LoadingScreen';

const Index = () => {
  const [selectedModule, setSelectedModule] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Simulate loading time
    const timer = setTimeout(() => {
      setIsLoading(false);
    }, 3000);

    return () => clearTimeout(timer);
  }, []);

  if (isLoading) {
    return <LoadingScreen />;
  }

  const securityModules = [
    {
      id: 'reconnaissance',
      title: 'Reconnaissance & Information Gathering',
      description: 'Learn about passive information gathering techniques for authorized security assessments',
      icon: Eye,
      color: 'bg-green-500',
      techniques: [
        'Footprinting Fundamentals',
        'DNS Enumeration (Authorized)',
        'WHOIS Analysis',
        'Network Mapping Basics',
        'OSINT Techniques'
      ],
      defenseStrategies: [
        'Information Disclosure Prevention',
        'DNS Security Configuration',
        'Network Segmentation',
        'Privacy Controls'
      ]
    },
    {
      id: 'network-security',
      title: 'Network Security Assessment',
      description: 'Understanding network vulnerabilities and defensive measures',
      icon: Network,
      color: 'bg-red-500',
      techniques: [
        'Port Scanning (Authorized Networks)',
        'Banner Grabbing Analysis',
        'Vulnerability Scanning',
        'Network Architecture Analysis',
        'Service Enumeration'
      ],
      defenseStrategies: [
        'Firewall Configuration',
        'Intrusion Detection Systems',
        'Network Monitoring',
        'Service Hardening'
      ]
    },
    {
      id: 'social-engineering',
      title: 'Social Engineering Awareness',
      description: 'Educational content on social engineering tactics and defense',
      icon: Users,
      color: 'bg-orange-500',
      techniques: [
        'Phishing Awareness Training',
        'Pretexting Recognition',
        'Vishing Defense',
        'Smishing Identification',
        'Spear Phishing Prevention'
      ],
      defenseStrategies: [
        'Security Awareness Training',
        'Email Security Policies',
        'Multi-Factor Authentication',
        'Incident Response Procedures'
      ]
    },
    {
      id: 'web-security',
      title: 'Web Application Security',
      description: 'Learn about web vulnerabilities and secure development practices',
      icon: Globe,
      color: 'bg-purple-500',
      techniques: [
        'XSS Prevention',
        'SQL Injection Defense',
        'CSRF Protection',
        'Input Validation',
        'Session Management'
      ],
      defenseStrategies: [
        'Secure Coding Practices',
        'Web Application Firewalls',
        'Security Headers',
        'Regular Security Testing'
      ]
    },
    {
      id: 'system-security',
      title: 'System & Infrastructure Security',
      description: 'Understanding system-level security and hardening techniques',
      icon: Server,
      color: 'bg-yellow-500',
      techniques: [
        'Buffer Overflow Prevention',
        'Memory Protection',
        'Access Control',
        'Privilege Escalation Defense',
        'Malware Detection'
      ],
      defenseStrategies: [
        'System Hardening',
        'Endpoint Protection',
        'Patch Management',
        'Monitoring & Logging'
      ]
    },
    {
      id: 'cryptography',
      title: 'Cryptography & Data Protection',
      description: 'Learn about encryption, hashing, and data protection methods',
      icon: Lock,
      color: 'bg-cyan-500',
      techniques: [
        'Encryption Standards',
        'Hash Functions',
        'Digital Signatures',
        'Key Management',
        'SSL/TLS Implementation'
      ],
      defenseStrategies: [
        'Data Encryption at Rest',
        'Transport Layer Security',
        'Key Rotation Policies',
        'Certificate Management'
      ]
    }
  ];

  return (
    <div className="min-h-screen bg-black text-green-400 font-mono">
      {/* Enhanced Hacker-style Header */}
      <div className="bg-gradient-to-r from-gray-900 to-black border-b border-green-500 shadow-lg shadow-green-500/30">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-gradient-to-r from-green-500 to-green-400 rounded-lg animate-pulse shadow-lg shadow-green-500/50">
                <Shield className="h-6 w-6 text-black" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-green-400 tracking-wider">D0LF1N T00L5</h1>
                <p className="text-green-300 text-sm font-mono">[ETHICAL PENETRATION TESTING FRAMEWORK]</p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-green-400 text-sm">root@dolfin:~$</p>
              <p className="text-green-300 font-semibold">Developer: @ethicalphoenix</p>
              <div className="flex items-center space-x-2 mt-1">
                <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
                <span className="text-xs text-green-400">SYSTEM_ONLINE</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="container mx-auto px-6 py-8">
        {/* Enhanced Warning Banner */}
        <Card className="mb-8 border-red-500 bg-gradient-to-r from-red-900/30 to-gray-900/50 shadow-lg shadow-red-500/30">
          <CardContent className="p-6">
            <div className="flex items-start space-x-3">
              <AlertTriangle className="h-6 w-6 text-red-400 mt-1 animate-pulse" />
              <div>
                <h3 className="text-red-400 font-semibold mb-2 font-mono">[WARNING] AUTHORIZED USE ONLY</h3>
                <p className="text-red-300 text-sm font-mono">
                  {"> "}This platform is designed for educational purposes and authorized security testing only.<br/>
                  {"> "}All techniques should only be applied to systems you own or have explicit permission to test.<br/>
                  {"> "}Unauthorized use of these techniques may be illegal and unethical.<br/>
                  {"> "}Framework developed by @ethicalphoenix for ethical security research.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Enhanced Tabs with better styling */}
        <Tabs defaultValue="tools" className="w-full">
          <TabsList className="grid w-full grid-cols-4 bg-gradient-to-r from-gray-900 to-black border border-green-500 shadow-lg shadow-green-500/20">
            <TabsTrigger value="tools" className="data-[state=active]:bg-gradient-to-r data-[state=active]:from-green-500 data-[state=active]:to-green-400 data-[state=active]:text-black font-mono font-bold">
              HACK_TOOLS
            </TabsTrigger>
            <TabsTrigger value="modules" className="data-[state=active]:bg-gradient-to-r data-[state=active]:from-green-500 data-[state=active]:to-green-400 data-[state=active]:text-black font-mono font-bold">
              MODULES
            </TabsTrigger>
            <TabsTrigger value="education" className="data-[state=active]:bg-gradient-to-r data-[state=active]:from-green-500 data-[state=active]:to-green-400 data-[state=active]:text-black font-mono font-bold">
              EDUCATION
            </TabsTrigger>
            <TabsTrigger value="defense" className="data-[state=active]:bg-gradient-to-r data-[state=active]:from-green-500 data-[state=active]:to-green-400 data-[state=active]:text-black font-mono font-bold">
              DEFENSE
            </TabsTrigger>
          </TabsList>

          <TabsContent value="tools" className="mt-8">
            <HackingTools />
          </TabsContent>

          <TabsContent value="modules" className="mt-8">
            {!selectedModule ? (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {securityModules.map((module) => (
                  <SecurityModuleCard
                    key={module.id}
                    module={module}
                    onSelect={() => setSelectedModule(module.id)}
                  />
                ))}
              </div>
            ) : (
              <div className="space-y-6">
                <Button 
                  onClick={() => setSelectedModule(null)}
                  variant="outline"
                  className="mb-4 border-green-500 text-green-400 hover:bg-green-500 hover:text-black font-mono"
                >
                  ← BACK_TO_MODULES
                </Button>
                {selectedModule && (
                  <EducationalContent 
                    module={securityModules.find(m => m.id === selectedModule)!}
                  />
                )}
              </div>
            )}
          </TabsContent>

          <TabsContent value="education" className="mt-8">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <Card className="bg-gray-900 border-green-500 shadow-lg shadow-green-500/20">
                <CardHeader>
                  <CardTitle className="text-green-400 flex items-center space-x-2 font-mono">
                    <BookOpen className="h-5 w-5" />
                    <span>[LEARNING_RESOURCES]</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-green-300 font-mono">
                  <ul className="space-y-2">
                    <li>• OWASP Top 10 Security Risks</li>
                    <li>• NIST Cybersecurity Framework</li>
                    <li>• Ethical Hacking Methodologies</li>
                    <li>• Penetration Testing Standards</li>
                    <li>• Security Compliance Guidelines</li>
                  </ul>
                </CardContent>
              </Card>

              <Card className="bg-gray-900 border-green-500 shadow-lg shadow-green-500/20">
                <CardHeader>
                  <CardTitle className="text-green-400 flex items-center space-x-2 font-mono">
                    <Code className="h-5 w-5" />
                    <span>[CERTIFICATION_PREP]</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-green-300 font-mono">
                  <ul className="space-y-2">
                    <li>• Certified Ethical Hacker (CEH)</li>
                    <li>• CompTIA Security+</li>
                    <li>• CISSP Preparation</li>
                    <li>• OSCP Training Materials</li>
                    <li>• Security+ Practice Tests</li>
                  </ul>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="defense" className="mt-8">
            <DefenseStrategies />
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default Index;
