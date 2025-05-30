
import React from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Shield, Eye, Wifi, Smartphone, Users, Globe, Server, Lock } from 'lucide-react';
import ReconTools from './tools/ReconTools';
import NetworkTools from './tools/NetworkTools';
import WiFiTools from './tools/WiFiTools';
import WebTools from './tools/WebTools';
import MobileTools from './tools/MobileTools';
import SocialEngTools from './tools/SocialEngTools';
import ExploitTools from './tools/ExploitTools';
import CryptoTools from './tools/CryptoTools';

const HackingTools = () => {
  return (
    <div className="space-y-4">
      <Card className="bg-black border-red-600">
        <CardHeader>
          <CardTitle className="text-red-400 font-mono flex items-center space-x-2">
            <Shield className="h-6 w-6" />
            <span>[PHOENIX_PENETRATION_TESTING_FRAMEWORK]</span>
          </CardTitle>
          <CardDescription className="text-red-300 font-mono">
            Professional cybersecurity research and penetration testing tools
          </CardDescription>
        </CardHeader>
      </Card>

      <Tabs defaultValue="recon" className="w-full">
        <TabsList className="grid w-full grid-cols-4 lg:grid-cols-8 bg-black border border-red-600 p-1">
          <TabsTrigger value="recon" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-xs flex items-center justify-center">
            <Eye className="h-3 w-3 mr-1" />
            <span className="hidden sm:inline">RECON</span>
          </TabsTrigger>
          <TabsTrigger value="network" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-xs flex items-center justify-center">
            <Server className="h-3 w-3 mr-1" />
            <span className="hidden sm:inline">NETWORK</span>
          </TabsTrigger>
          <TabsTrigger value="wifi" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-xs flex items-center justify-center">
            <Wifi className="h-3 w-3 mr-1" />
            <span className="hidden sm:inline">WIFI</span>
          </TabsTrigger>
          <TabsTrigger value="web" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-xs flex items-center justify-center">
            <Globe className="h-3 w-3 mr-1" />
            <span className="hidden sm:inline">WEB</span>
          </TabsTrigger>
          <TabsTrigger value="mobile" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-xs flex items-center justify-center">
            <Smartphone className="h-3 w-3 mr-1" />
            <span className="hidden sm:inline">MOBILE</span>
          </TabsTrigger>
          <TabsTrigger value="social" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-xs flex items-center justify-center">
            <Users className="h-3 w-3 mr-1" />
            <span className="hidden sm:inline">SOCIAL</span>
          </TabsTrigger>
          <TabsTrigger value="exploit" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-xs flex items-center justify-center">
            <Shield className="h-3 w-3 mr-1" />
            <span className="hidden sm:inline">EXPLOIT</span>
          </TabsTrigger>
          <TabsTrigger value="crypto" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-xs flex items-center justify-center">
            <Lock className="h-3 w-3 mr-1" />
            <span className="hidden sm:inline">CRYPTO</span>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="recon" className="mt-4">
          <ReconTools />
        </TabsContent>

        <TabsContent value="network" className="mt-4">
          <NetworkTools />
        </TabsContent>

        <TabsContent value="wifi" className="mt-4">
          <WiFiTools />
        </TabsContent>

        <TabsContent value="web" className="mt-4">
          <WebTools />
        </TabsContent>

        <TabsContent value="mobile" className="mt-4">
          <MobileTools />
        </TabsContent>

        <TabsContent value="social" className="mt-4">
          <SocialEngTools />
        </TabsContent>

        <TabsContent value="exploit" className="mt-4">
          <ExploitTools />
        </TabsContent>

        <TabsContent value="crypto" className="mt-4">
          <CryptoTools />
        </TabsContent>
      </Tabs>
    </div>
  );
};

export default HackingTools;
