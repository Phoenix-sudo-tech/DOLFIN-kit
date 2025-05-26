
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, Eye, Network, Database, Lock, AlertTriangle, BookOpen, Code, Terminal, Users, Globe, Server } from 'lucide-react';
import SecurityModuleCard from '../components/SecurityModuleCard';
import EducationalContent from '../components/EducationalContent';
import DefenseStrategies from '../components/DefenseStrategies';

const Index = () => {
  const [selectedModule, setSelectedModule] = useState<string | null>(null);

  const securityModules = [
    {
      id: 'reconnaissance',
      title: 'Reconnaissance & Information Gathering',
      description: 'Learn about passive information gathering techniques for authorized security assessments',
      icon: Eye,
      color: 'bg-blue-500',
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
      color: 'bg-green-500',
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
      color: 'bg-red-500',
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
      color: 'bg-indigo-500',
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
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-800">
      {/* Header */}
      <div className="bg-black/20 backdrop-blur-sm border-b border-white/10">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-blue-500 rounded-lg">
                <Shield className="h-6 w-6 text-white" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-white">DOLFIN TOOLS</h1>
                <p className="text-blue-200 text-sm">Ethical Cybersecurity Education Platform</p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-white text-sm">Created by</p>
              <p className="text-blue-300 font-semibold">ethicalphoenix</p>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="container mx-auto px-6 py-8">
        {/* Warning Banner */}
        <Card className="mb-8 border-orange-500/50 bg-orange-500/10">
          <CardContent className="p-6">
            <div className="flex items-start space-x-3">
              <AlertTriangle className="h-6 w-6 text-orange-400 mt-1" />
              <div>
                <h3 className="text-orange-300 font-semibold mb-2">Ethical Use Only</h3>
                <p className="text-orange-200 text-sm">
                  This platform is designed for educational purposes and authorized security testing only. 
                  All techniques should only be applied to systems you own or have explicit permission to test. 
                  Unauthorized use of these techniques may be illegal and unethical.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        <Tabs defaultValue="modules" className="w-full">
          <TabsList className="grid w-full grid-cols-3 bg-white/10 border border-white/20">
            <TabsTrigger value="modules" className="data-[state=active]:bg-blue-500 data-[state=active]:text-white">
              Security Modules
            </TabsTrigger>
            <TabsTrigger value="education" className="data-[state=active]:bg-blue-500 data-[state=active]:text-white">
              Educational Content
            </TabsTrigger>
            <TabsTrigger value="defense" className="data-[state=active]:bg-blue-500 data-[state=active]:text-white">
              Defense Strategies
            </TabsTrigger>
          </TabsList>

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
                  className="mb-4 border-white/20 text-white hover:bg-white/10"
                >
                  ← Back to Modules
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
              <Card className="bg-white/5 border-white/20">
                <CardHeader>
                  <CardTitle className="text-white flex items-center space-x-2">
                    <BookOpen className="h-5 w-5" />
                    <span>Learning Resources</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-white/80">
                  <ul className="space-y-2">
                    <li>• OWASP Top 10 Security Risks</li>
                    <li>• NIST Cybersecurity Framework</li>
                    <li>• Ethical Hacking Methodologies</li>
                    <li>• Penetration Testing Standards</li>
                    <li>• Security Compliance Guidelines</li>
                  </ul>
                </CardContent>
              </Card>

              <Card className="bg-white/5 border-white/20">
                <CardHeader>
                  <CardTitle className="text-white flex items-center space-x-2">
                    <Code className="h-5 w-5" />
                    <span>Certification Prep</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-white/80">
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
