
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
        <TabsList className="grid w-full grid-cols-4 lg:grid-cols-8 bg-black border border-red-600">
          <TabsTrigger value="recon" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono">
            <Eye className="h-4 w-4 mr-1" />
            RECON
          </TabsTrigger>
          <TabsTrigger value="network" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono">
            <Server className="h-4 w-4 mr-1" />
            NETWORK
          </TabsTrigger>
          <TabsTrigger value="wifi" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono">
            <Wifi className="h-4 w-4 mr-1" />
            WIFI
          </TabsTrigger>
          <TabsTrigger value="web" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono">
            <Globe className="h-4 w-4 mr-1" />
            WEB
          </TabsTrigger>
          <TabsTrigger value="mobile" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono">
            <Smartphone className="h-4 w-4 mr-1" />
            MOBILE
          </TabsTrigger>
          <TabsTrigger value="social" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono">
            <Users className="h-4 w-4 mr-1" />
            SOCIAL
          </TabsTrigger>
          <TabsTrigger value="exploit" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono">
            <Shield className="h-4 w-4 mr-1" />
            EXPLOIT
          </TabsTrigger>
          <TabsTrigger value="crypto" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono">
            <Lock className="h-4 w-4 mr-1" />
            CRYPTO
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
