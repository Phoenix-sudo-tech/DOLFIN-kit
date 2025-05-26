
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Shield, Lock, Eye, AlertTriangle, CheckCircle, Network } from 'lucide-react';

const DefenseStrategies = () => {
  const defenseCategories = [
    {
      title: 'Network Security',
      icon: Network,
      color: 'bg-blue-500',
      strategies: [
        'Implement network segmentation',
        'Deploy intrusion detection systems',
        'Configure firewalls properly',
        'Monitor network traffic',
        'Use VPNs for remote access'
      ]
    },
    {
      title: 'Access Control',
      icon: Lock,
      color: 'bg-green-500',
      strategies: [
        'Implement multi-factor authentication',
        'Use principle of least privilege',
        'Regular access reviews',
        'Strong password policies',
        'Session management controls'
      ]
    },
    {
      title: 'Monitoring & Detection',
      icon: Eye,
      color: 'bg-purple-500',
      strategies: [
        'Security information and event management (SIEM)',
        'Log monitoring and analysis',
        'Behavioral analysis',
        'Threat intelligence integration',
        'Incident response procedures'
      ]
    },
    {
      title: 'Data Protection',
      icon: Shield,
      color: 'bg-orange-500',
      strategies: [
        'Data encryption at rest and in transit',
        'Data loss prevention (DLP)',
        'Backup and recovery procedures',
        'Data classification and handling',
        'Privacy controls implementation'
      ]
    }
  ];

  const securityFrameworks = [
    {
      name: 'NIST Cybersecurity Framework',
      description: 'Identify, Protect, Detect, Respond, Recover',
      status: 'Industry Standard'
    },
    {
      name: 'ISO 27001',
      description: 'Information security management systems',
      status: 'International Standard'
    },
    {
      name: 'OWASP Top 10',
      description: 'Web application security risks',
      status: 'Best Practice'
    },
    {
      name: 'CIS Controls',
      description: 'Critical security controls',
      status: 'Implementation Guide'
    }
  ];

  return (
    <div className="space-y-8">
      {/* Defense Categories */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {defenseCategories.map((category, index) => {
          const Icon = category.icon;
          return (
            <Card key={index} className="bg-white/5 border-white/20">
              <CardHeader>
                <CardTitle className="text-white flex items-center space-x-3">
                  <div className={`p-2 rounded-lg ${category.color}`}>
                    <Icon className="h-5 w-5 text-white" />
                  </div>
                  <span>{category.title}</span>
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {category.strategies.map((strategy, strategyIndex) => (
                    <div key={strategyIndex} className="flex items-start space-x-2">
                      <CheckCircle className="h-4 w-4 text-green-400 mt-1 flex-shrink-0" />
                      <span className="text-white/80 text-sm">{strategy}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Security Frameworks */}
      <Card className="bg-white/5 border-white/20">
        <CardHeader>
          <CardTitle className="text-white">Security Frameworks & Standards</CardTitle>
          <CardDescription className="text-white/70">
            Industry-recognized frameworks for implementing comprehensive security programs
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {securityFrameworks.map((framework, index) => (
              <div key={index} className="p-4 rounded-lg bg-white/5 border border-white/10">
                <div className="flex justify-between items-start mb-2">
                  <h4 className="text-white font-medium">{framework.name}</h4>
                  <Badge variant="outline" className="border-blue-500/50 text-blue-300">
                    {framework.status}
                  </Badge>
                </div>
                <p className="text-white/60 text-sm">{framework.description}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Security Incident Response */}
      <Card className="bg-white/5 border-white/20">
        <CardHeader>
          <CardTitle className="text-white flex items-center space-x-2">
            <AlertTriangle className="h-5 w-5 text-orange-400" />
            <span>Incident Response Process</span>
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { phase: 'Preparation', description: 'Establish incident response capabilities' },
              { phase: 'Identification', description: 'Detect and analyze incidents' },
              { phase: 'Containment', description: 'Limit damage and prevent spread' },
              { phase: 'Recovery', description: 'Restore systems and prevent recurrence' }
            ].map((phase, index) => (
              <div key={index} className="text-center p-4 rounded-lg bg-white/5 border border-white/10">
                <div className="w-8 h-8 rounded-full bg-blue-500 text-white flex items-center justify-center mx-auto mb-3 text-sm font-bold">
                  {index + 1}
                </div>
                <h4 className="text-white font-medium mb-2">{phase.phase}</h4>
                <p className="text-white/60 text-sm">{phase.description}</p>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default DefenseStrategies;
