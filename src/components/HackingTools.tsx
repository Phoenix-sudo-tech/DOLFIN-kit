
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
        <CardHeader className="p-4 sm:p-6">
          <CardTitle className="text-red-400 font-mono flex items-center space-x-2 text-sm sm:text-base">
            <Shield className="h-4 w-4 sm:h-6 sm:w-6" />
            <span>[PHOENIX_PENETRATION_TESTING_FRAMEWORK]</span>
          </CardTitle>
          <CardDescription className="text-red-300 font-mono text-xs sm:text-sm">
            Professional cybersecurity research and penetration testing tools
          </CardDescription>
        </CardHeader>
      </Card>

      <Tabs defaultValue="recon" className="w-full">
        <TabsList className="grid w-full grid-cols-4 sm:grid-cols-8 bg-black border border-red-600 p-1 gap-0.5 sm:gap-1">
          <TabsTrigger value="recon" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-[10px] sm:text-xs flex items-center justify-center px-1 sm:px-2 py-2 min-h-[40px]">
            <Eye className="h-3 w-3 mr-0.5 sm:mr-1" />
            <span className="hidden xs:inline">RECON</span>
          </TabsTrigger>
          <TabsTrigger value="network" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-[10px] sm:text-xs flex items-center justify-center px-1 sm:px-2 py-2 min-h-[40px]">
            <Server className="h-3 w-3 mr-0.5 sm:mr-1" />
            <span className="hidden xs:inline">NETWORK</span>
          </TabsTrigger>
          <TabsTrigger value="wifi" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-[10px] sm:text-xs flex items-center justify-center px-1 sm:px-2 py-2 min-h-[40px]">
            <Wifi className="h-3 w-3 mr-0.5 sm:mr-1" />
            <span className="hidden xs:inline">WIFI</span>
          </TabsTrigger>
          <TabsTrigger value="web" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-[10px] sm:text-xs flex items-center justify-center px-1 sm:px-2 py-2 min-h-[40px]">
            <Globe className="h-3 w-3 mr-0.5 sm:mr-1" />
            <span className="hidden xs:inline">WEB</span>
          </TabsTrigger>
          <TabsTrigger value="mobile" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-[10px] sm:text-xs flex items-center justify-center px-1 sm:px-2 py-2 min-h-[40px]">
            <Smartphone className="h-3 w-3 mr-0.5 sm:mr-1" />
            <span className="hidden xs:inline">MOBILE</span>
          </TabsTrigger>
          <TabsTrigger value="social" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-[10px] sm:text-xs flex items-center justify-center px-1 sm:px-2 py-2 min-h-[40px]">
            <Users className="h-3 w-3 mr-0.5 sm:mr-1" />
            <span className="hidden xs:inline">SOCIAL</span>
          </TabsTrigger>
          <TabsTrigger value="exploit" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-[10px] sm:text-xs flex items-center justify-center px-1 sm:px-2 py-2 min-h-[40px]">
            <Shield className="h-3 w-3 mr-0.5 sm:mr-1" />
            <span className="hidden xs:inline">EXPLOIT</span>
          </TabsTrigger>
          <TabsTrigger value="crypto" className="data-[state=active]:bg-red-600 data-[state=active]:text-black text-red-400 font-mono text-[10px] sm:text-xs flex items-center justify-center px-1 sm:px-2 py-2 min-h-[40px]">
            <Lock className="h-3 w-3 mr-0.5 sm:mr-1" />
            <span className="hidden xs:inline">CRYPTO</span>
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
