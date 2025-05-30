
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Shield, Eye, Network, Database, Lock, AlertTriangle, BookOpen, Code, Terminal, Users, Globe, Server, User, Instagram, MessageCircle } from 'lucide-react';
import SecurityModuleCard from '../components/SecurityModuleCard';
import EducationalContent from '../components/EducationalContent';
import DefenseStrategies from '../components/DefenseStrategies';
import HackingTools from '../components/HackingTools';
import LoadingScreen from '../components/LoadingScreen';

const Index = () => {
  const [selectedModule, setSelectedModule] = useState<string | null>(null);
  const [hasAccess, setHasAccess] = useState(false);

  if (!hasAccess) {
    return <LoadingScreen onEnter={() => setHasAccess(true)} />;
  }

  const securityModules = [
    {
      id: 'reconnaissance',
      title: 'Advanced Reconnaissance',
      description: 'Professional OSINT and information gathering framework',
      icon: Eye,
      color: 'bg-red-600',
      techniques: [
        'Advanced OSINT Framework',
        'Subdomain Enumeration',
        'Port & Service Discovery',
        'Vulnerability Assessment',
        'Social Media Intelligence'
      ],
      defenseStrategies: [
        'Information Disclosure Prevention',
        'DNS Security Hardening',
        'Network Segmentation',
        'Privacy Controls'
      ]
    },
    {
      id: 'network-security',
      title: 'Network Penetration',
      description: 'Advanced network exploitation and assessment tools',
      icon: Network,
      color: 'bg-red-700',
      techniques: [
        'Advanced Port Scanning',
        'Service Exploitation',
        'Network Pivoting',
        'Lateral Movement',
        'Traffic Analysis'
      ],
      defenseStrategies: [
        'Network Hardening',
        'IDS/IPS Implementation',
        'Zero Trust Architecture',
        'Micro-segmentation'
      ]
    },
    {
      id: 'social-engineering',
      title: 'Social Engineering',
      description: 'Human factor security assessment and training',
      icon: Users,
      color: 'bg-red-800',
      techniques: [
        'Advanced Phishing Campaigns',
        'Pretexting Frameworks',
        'Voice Phishing (Vishing)',
        'Physical Security Bypass',
        'OSINT-based Targeting'
      ],
      defenseStrategies: [
        'Security Awareness Programs',
        'Phishing Simulation',
        'Behavioral Analysis',
        'Incident Response Training'
      ]
    },
    {
      id: 'web-security',
      title: 'Web Application Hacking',
      description: 'Advanced web application penetration testing',
      icon: Globe,
      color: 'bg-red-600',
      techniques: [
        'Advanced XSS Exploitation',
        'SQL Injection Mastery',
        'Authentication Bypass',
        'Session Hijacking',
        'API Security Testing'
      ],
      defenseStrategies: [
        'Secure Development Lifecycle',
        'Web Application Firewalls',
        'Runtime Protection',
        'Security Headers Implementation'
      ]
    },
    {
      id: 'system-security',
      title: 'System Exploitation',
      description: 'Advanced system-level penetration testing',
      icon: Server,
      color: 'bg-red-700',
      techniques: [
        'Buffer Overflow Exploitation',
        'Privilege Escalation',
        'Kernel Exploitation',
        'Memory Corruption',
        'Advanced Persistence'
      ],
      defenseStrategies: [
        'System Hardening',
        'Endpoint Detection & Response',
        'Application Whitelisting',
        'Behavioral Monitoring'
      ]
    },
    {
      id: 'cryptography',
      title: 'Cryptographic Attacks',
      description: 'Advanced cryptanalysis and implementation attacks',
      icon: Lock,
      color: 'bg-red-800',
      techniques: [
        'Hash Collision Attacks',
        'Side-Channel Analysis',
        'Implementation Flaws',
        'Key Recovery Attacks',
        'Protocol Weaknesses'
      ],
      defenseStrategies: [
        'Cryptographic Standards',
        'Key Management Systems',
        'Hardware Security Modules',
        'Quantum-Resistant Algorithms'
      ]
    }
  ];

  return (
    <div className="min-h-screen bg-black text-red-400 font-mono">
      {/* Mobile-optimized Header */}
      <div className="bg-black border-b border-red-600">
        <div className="container mx-auto px-4 sm:px-6 py-3 sm:py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-2 sm:space-x-3">
              <div className="p-1.5 sm:p-2 bg-red-600 rounded">
                <Shield className="h-4 w-4 sm:h-6 sm:w-6 text-black" />
              </div>
              <div>
                <h1 className="text-lg sm:text-2xl font-bold text-red-400">PHOENIX FRAMEWORK</h1>
                <p className="text-red-300 text-xs sm:text-sm">Advanced Penetration Testing Suite</p>
              </div>
            </div>
            <div className="text-right">
              <p className="text-red-400 text-xs sm:text-sm">phoenix@framework:~$</p>
              <div className="flex items-center space-x-1 sm:space-x-2 mt-1">
                <div className="w-1.5 h-1.5 sm:w-2 sm:h-2 bg-red-500 rounded-full animate-pulse"></div>
                <span className="text-xs text-red-400">ONLINE</span>
              </div>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="container mx-auto px-4 sm:px-6 py-4 sm:py-6">
        {/* Warning Banner */}
        <Card className="mb-4 sm:mb-6 border-red-600 bg-black">
          <CardContent className="p-3 sm:p-4">
            <div className="flex items-start space-x-2 sm:space-x-3">
              <AlertTriangle className="h-4 w-4 sm:h-5 sm:w-5 text-red-500 mt-1 flex-shrink-0" />
              <div>
                <h3 className="text-red-500 font-semibold mb-1 text-sm sm:text-base">[AUTHORIZED USE ONLY]</h3>
                <p className="text-red-400 text-xs sm:text-sm">
                  Professional penetration testing framework. Use only on authorized systems.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Mobile-optimized Tabs */}
        <Tabs defaultValue="tools" className="w-full">
          <TabsList className="grid w-full grid-cols-5 bg-black border border-red-600 h-auto p-1">
            <TabsTrigger value="tools" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 text-xs sm:text-sm px-1 sm:px-3 py-2">
              TOOLS
            </TabsTrigger>
            <TabsTrigger value="modules" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 text-xs sm:text-sm px-1 sm:px-3 py-2">
              MODULES
            </TabsTrigger>
            <TabsTrigger value="education" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 text-xs sm:text-sm px-1 sm:px-3 py-2">
              EDUCATION
            </TabsTrigger>
            <TabsTrigger value="defense" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 text-xs sm:text-sm px-1 sm:px-3 py-2">
              DEFENSE
            </TabsTrigger>
            <TabsTrigger value="about" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 text-xs sm:text-sm px-1 sm:px-3 py-2">
              ABOUT
            </TabsTrigger>
          </TabsList>

          <TabsContent value="tools" className="mt-4 sm:mt-6">
            <HackingTools />
          </TabsContent>

          <TabsContent value="modules" className="mt-4 sm:mt-6">
            {!selectedModule ? (
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 sm:gap-4">
                {securityModules.map((module) => (
                  <SecurityModuleCard
                    key={module.id}
                    module={module}
                    onSelect={() => setSelectedModule(module.id)}
                  />
                ))}
              </div>
            ) : (
              <div className="space-y-4">
                <Button 
                  onClick={() => setSelectedModule(null)}
                  variant="outline"
                  className="mb-4 border-red-600 text-red-400 hover:bg-red-600 hover:text-black"
                >
                  ← BACK
                </Button>
                {selectedModule && (
                  <EducationalContent 
                    module={securityModules.find(m => m.id === selectedModule)!}
                  />
                )}
              </div>
            )}
          </TabsContent>

          <TabsContent value="education" className="mt-4 sm:mt-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-3 sm:gap-4">
              <Card className="bg-black border-red-600">
                <CardHeader className="p-4 sm:p-6">
                  <CardTitle className="text-red-400 flex items-center space-x-2 text-sm sm:text-base">
                    <BookOpen className="h-4 w-4 sm:h-5 sm:w-5" />
                    <span>[LEARNING_RESOURCES]</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-red-300 p-4 sm:p-6 pt-0">
                  <ul className="space-y-2 text-xs sm:text-sm">
                    <li>• Advanced Penetration Testing</li>
                    <li>• Red Team Operations</li>
                    <li>• Vulnerability Research</li>
                    <li>• Exploit Development</li>
                    <li>• Threat Intelligence</li>
                  </ul>
                </CardContent>
              </Card>

              <Card className="bg-black border-red-600">
                <CardHeader className="p-4 sm:p-6">
                  <CardTitle className="text-red-400 flex items-center space-x-2 text-sm sm:text-base">
                    <Code className="h-4 w-4 sm:h-5 sm:w-5" />
                    <span>[CERTIFICATIONS]</span>
                  </CardTitle>
                </CardHeader>
                <CardContent className="text-red-300 p-4 sm:p-6 pt-0">
                  <ul className="space-y-2 text-xs sm:text-sm">
                    <li>• OSCP - Offensive Security</li>
                    <li>• OSCE - Expert Level</li>
                    <li>• CISSP - Security Professional</li>
                    <li>• CEH - Ethical Hacker</li>
                    <li>• GPEN - Penetration Tester</li>
                  </ul>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="defense" className="mt-4 sm:mt-6">
            <DefenseStrategies />
          </TabsContent>

          <TabsContent value="about" className="mt-4 sm:mt-6">
            <div className="max-w-2xl mx-auto">
              <Card className="bg-black border-red-600">
                <CardHeader className="text-center p-4 sm:p-6">
                  <div className="mx-auto w-16 h-16 sm:w-20 sm:h-20 bg-red-600 rounded-full flex items-center justify-center mb-4">
                    <User className="h-8 w-8 sm:h-10 sm:w-10 text-black" />
                  </div>
                  <CardTitle className="text-red-400 text-xl sm:text-2xl">CREATOR: PHOENIX</CardTitle>
                  <CardDescription className="text-red-300 text-sm sm:text-base">
                    Advanced Penetration Testing Framework Developer
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4 sm:space-y-6 p-4 sm:p-6 pt-0">
                  <div className="text-center space-y-4">
                    <p className="text-red-300 text-xs sm:text-sm">
                      Professional cybersecurity researcher and penetration testing framework developer.
                      Specialized in advanced offensive security tools and techniques.
                    </p>
                    
                    <div className="space-y-3">
                      <a 
                        href="https://instagram.com/ethicalphoenix" 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="flex items-center justify-center space-x-3 p-3 border border-red-600 rounded hover:bg-red-600 hover:text-black transition-colors cursor-pointer"
                      >
                        <Instagram className="h-4 w-4 sm:h-5 sm:w-5" />
                        <span className="font-mono text-sm">@ethicalphoenix</span>
                      </a>
                      
                      <a 
                        href="https://t.me/grey_008" 
                        target="_blank" 
                        rel="noopener noreferrer"
                        className="flex items-center justify-center space-x-3 p-3 border border-red-600 rounded hover:bg-red-600 hover:text-black transition-colors cursor-pointer"
                      >
                        <MessageCircle className="h-4 w-4 sm:h-5 sm:w-5" />
                        <span className="font-mono text-sm">t.me/grey_008</span>
                      </a>
                    </div>
                    
                    <div className="mt-6 p-3 sm:p-4 bg-gray-900 border border-red-600 rounded">
                      <h4 className="text-red-400 font-semibold mb-2 text-sm">[FRAMEWORK_INFO]</h4>
                      <p className="text-red-300 text-xs sm:text-sm">
                        This framework provides real penetration testing tools for authorized security research.
                        All tools generate executable scripts for professional security assessments.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
};

export default Index;
