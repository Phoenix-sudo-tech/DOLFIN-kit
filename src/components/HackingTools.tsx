
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Eye, Network, Users, Globe, Server, Lock, Terminal, Shield, Zap, Wifi, Smartphone } from 'lucide-react';
import ReconTools from './tools/ReconTools';
import NetworkTools from './tools/NetworkTools';
import WebTools from './tools/WebTools';
import SocialEngTools from './tools/SocialEngTools';
import ExploitTools from './tools/ExploitTools';
import CryptoTools from './tools/CryptoTools';
import WiFiTools from './tools/WiFiTools';
import MobileTools from './tools/MobileTools';

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
      id: 'wifi',
      name: 'WIFI_AUDIT',
      icon: Wifi,
      color: 'text-blue-400',
      description: 'Wireless security assessment tools'
    },
    {
      id: 'mobile',
      name: 'MOBILE_TEST',
      icon: Smartphone,
      color: 'text-cyan-400',
      description: 'Android/iOS security testing'
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
      color: 'text-pink-400',
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
      case 'wifi':
        return <WiFiTools />;
      case 'mobile':
        return <MobileTools />;
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
      {/* Enhanced Terminal Header */}
      <Card className="bg-gradient-to-r from-gray-900 to-black border-green-500 shadow-lg shadow-green-500/30">
        <CardHeader>
          <CardTitle className="text-green-400 font-mono flex items-center justify-between">
            <div className="flex items-center space-x-2">
              <Terminal className="h-5 w-5 animate-pulse" />
              <span>[ACTIVE_TERMINAL] root@dolfin-tools:~#</span>
            </div>
            <div className="text-sm text-green-300">
              Developer: @ethicalphoenix
            </div>
          </CardTitle>
          <CardDescription className="text-green-300 font-mono">
            Professional penetration testing framework with advanced exploitation tools
          </CardDescription>
        </CardHeader>
      </Card>

      {/* Enhanced Tool Categories Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-4">
        {toolCategories.map((category) => {
          const Icon = category.icon;
          return (
            <Card
              key={category.id}
              className={`cursor-pointer transition-all duration-300 border-2 hover:scale-105 ${
                activeCategory === category.id
                  ? 'bg-gradient-to-br from-green-900/50 to-gray-900 border-green-500 shadow-lg shadow-green-500/30 scale-105'
                  : 'bg-gradient-to-br from-gray-900 to-black border-gray-700 hover:border-green-500 hover:shadow-md hover:shadow-green-500/20'
              }`}
              onClick={() => setActiveCategory(category.id)}
            >
              <CardContent className="p-4 text-center">
                <Icon className={`h-8 w-8 mx-auto mb-2 ${category.color} ${activeCategory === category.id ? 'animate-pulse' : ''}`} />
                <h3 className="font-mono text-xs text-green-400 mb-1">{category.name}</h3>
                <p className="text-xs text-green-300 font-mono opacity-80">{category.description}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Enhanced Active Tool Interface */}
      <Card className="bg-gradient-to-r from-gray-900 to-black border-green-500 shadow-lg shadow-green-500/30">
        <CardHeader className="bg-gradient-to-r from-green-900/20 to-transparent">
          <CardTitle className="text-green-400 font-mono flex items-center justify-between">
            <span>[{toolCategories.find(c => c.id === activeCategory)?.name}] ACTIVE_MODULE</span>
            <div className="flex items-center space-x-2">
              <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
              <span className="text-sm">ONLINE</span>
            </div>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-6">
          {renderToolContent()}
        </CardContent>
      </Card>
    </div>
  );
};

export default HackingTools;
