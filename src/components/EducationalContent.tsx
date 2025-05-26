
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { BookOpen, Shield, AlertTriangle, CheckCircle } from 'lucide-react';

interface SecurityModule {
  id: string;
  title: string;
  description: string;
  techniques: string[];
  defenseStrategies: string[];
}

interface EducationalContentProps {
  module: SecurityModule;
}

const EducationalContent: React.FC<EducationalContentProps> = ({ module }) => {
  return (
    <div className="space-y-6">
      <Card className="bg-white/5 border-white/20">
        <CardHeader>
          <CardTitle className="text-white text-2xl">{module.title}</CardTitle>
          <CardDescription className="text-white/70">
            {module.description}
          </CardDescription>
        </CardHeader>
      </Card>

      <Tabs defaultValue="learning" className="w-full">
        <TabsList className="grid w-full grid-cols-2 bg-white/10 border border-white/20">
          <TabsTrigger value="learning" className="data-[state=active]:bg-blue-500 data-[state=active]:text-white">
            Learning Topics
          </TabsTrigger>
          <TabsTrigger value="defense" className="data-[state=active]:bg-blue-500 data-[state=active]:text-white">
            Defense Strategies
          </TabsTrigger>
        </TabsList>

        <TabsContent value="learning" className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {module.techniques.map((technique, index) => (
              <Card key={index} className="bg-white/5 border-white/20 hover:bg-white/10 transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-start space-x-3">
                    <BookOpen className="h-5 w-5 text-blue-400 mt-1" />
                    <div>
                      <h4 className="text-white font-medium">{technique}</h4>
                      <p className="text-white/60 text-sm mt-1">
                        Educational content and ethical application guidelines
                      </p>
                      <Badge variant="outline" className="mt-2 border-blue-500/50 text-blue-300">
                        Educational Only
                      </Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="defense" className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {module.defenseStrategies.map((strategy, index) => (
              <Card key={index} className="bg-white/5 border-white/20 hover:bg-white/10 transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-start space-x-3">
                    <Shield className="h-5 w-5 text-green-400 mt-1" />
                    <div>
                      <h4 className="text-white font-medium">{strategy}</h4>
                      <p className="text-white/60 text-sm mt-1">
                        Protective measures and implementation guidelines
                      </p>
                      <Badge variant="outline" className="mt-2 border-green-500/50 text-green-300">
                        Defense Strategy
                      </Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>

      {/* Ethical Guidelines */}
      <Card className="bg-red-500/10 border-red-500/50">
        <CardContent className="p-6">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="h-6 w-6 text-red-400 mt-1" />
            <div>
              <h3 className="text-red-300 font-semibold mb-2">Ethical Guidelines</h3>
              <ul className="text-red-200 text-sm space-y-1">
                <li>• Only test on systems you own or have explicit written permission</li>
                <li>• Follow responsible disclosure practices for any vulnerabilities found</li>
                <li>• Respect privacy and confidentiality at all times</li>
                <li>• Use knowledge gained for defensive and educational purposes only</li>
                <li>• Stay within legal boundaries and obtain proper authorization</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default EducationalContent;
