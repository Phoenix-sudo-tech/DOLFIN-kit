
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Eye, Network, Users, Globe, Server, Lock, Terminal, Shield, Zap } from 'lucide-react';
import ReconTools from './tools/ReconTools';
import NetworkTools from './tools/NetworkTools';
import WebTools from './tools/WebTools';
import SocialEngTools from './tools/SocialEngTools';
import ExploitTools from './tools/ExploitTools';
import CryptoTools from './tools/CryptoTools';

const HackingTools = () => {
  const [activeCategory, setActiveCategory] = useState('recon');

  const toolCategories = [
    {
      id: 'recon',
      name: 'RECONNAISSANCE',
      icon: Eye,
      color: 'text-green-400',
      description: 'Information gathering and footprinting tools'
    },
    {
      id: 'network',
      name: 'NETWORK_SCAN',
      icon: Network,
      color: 'text-red-400',
      description: 'Network discovery and port scanning'
    },
    {
      id: 'web',
      name: 'WEB_EXPLOIT',
      icon: Globe,
      color: 'text-purple-400',
      description: 'Web application vulnerability testing'
    },
    {
      id: 'social',
      name: 'SOCIAL_ENG',
      icon: Users,
      color: 'text-orange-400',
      description: 'Social engineering simulation tools'
    },
    {
      id: 'exploit',
      name: 'EXPLOIT_KIT',
      icon: Zap,
      color: 'text-yellow-400',
      description: 'System exploitation and payload generation'
    },
    {
      id: 'crypto',
      name: 'CRYPTO_TOOLS',
      icon: Lock,
      color: 'text-cyan-400',
      description: 'Cryptographic analysis and hash tools'
    }
  ];

  const renderToolContent = () => {
    switch (activeCategory) {
      case 'recon':
        return <ReconTools />;
      case 'network':
        return <NetworkTools />;
      case 'web':
        return <WebTools />;
      case 'social':
        return <SocialEngTools />;
      case 'exploit':
        return <ExploitTools />;
      case 'crypto':
        return <CryptoTools />;
      default:
        return <ReconTools />;
    }
  };

  return (
    <div className="space-y-6">
      {/* Terminal Header */}
      <Card className="bg-gray-900 border-green-500 shadow-lg shadow-green-500/20">
        <CardHeader>
          <CardTitle className="text-green-400 font-mono flex items-center space-x-2">
            <Terminal className="h-5 w-5" />
            <span>[ACTIVE_TERMINAL] root@dolfin-tools:~#</span>
          </CardTitle>
          <CardDescription className="text-green-300 font-mono">
            Select a tool category to begin penetration testing operations
          </CardDescription>
        </CardHeader>
      </Card>

      {/* Tool Categories */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        {toolCategories.map((category) => {
          const Icon = category.icon;
          return (
            <Card
              key={category.id}
              className={`cursor-pointer transition-all duration-300 border-2 ${
                activeCategory === category.id
                  ? 'bg-green-900/30 border-green-500 shadow-lg shadow-green-500/20'
                  : 'bg-gray-900 border-gray-700 hover:border-green-500 hover:shadow-md hover:shadow-green-500/10'
              }`}
              onClick={() => setActiveCategory(category.id)}
            >
              <CardContent className="p-4 text-center">
                <Icon className={`h-8 w-8 mx-auto mb-2 ${category.color}`} />
                <h3 className="font-mono text-sm text-green-400 mb-1">{category.name}</h3>
                <p className="text-xs text-green-300 font-mono">{category.description}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Active Tool Interface */}
      <Card className="bg-gray-900 border-green-500 shadow-lg shadow-green-500/20">
        <CardHeader>
          <CardTitle className="text-green-400 font-mono">
            [{toolCategories.find(c => c.id === activeCategory)?.name}] ACTIVE_MODULE
          </CardTitle>
        </CardHeader>
        <CardContent>
          {renderToolContent()}
        </CardContent>
      </Card>
    </div>
  );
};

export default HackingTools;
