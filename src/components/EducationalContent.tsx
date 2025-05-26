
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
      <Card className="bg-gray-900 border-green-500 shadow-lg shadow-green-500/20">
        <CardHeader>
          <CardTitle className="text-green-400 text-2xl font-mono">[{module.title.toUpperCase()}]</CardTitle>
          <CardDescription className="text-green-300 font-mono">
            {module.description}
          </CardDescription>
        </CardHeader>
      </Card>

      <Tabs defaultValue="learning" className="w-full">
        <TabsList className="grid w-full grid-cols-2 bg-gray-900 border border-green-500">
          <TabsTrigger value="learning" className="data-[state=active]:bg-green-500 data-[state=active]:text-black font-mono">
            LEARNING_T0PIC5
          </TabsTrigger>
          <TabsTrigger value="defense" className="data-[state=active]:bg-green-500 data-[state=active]:text-black font-mono">
            DEFEN5E_5TRATEGIE5
          </TabsTrigger>
        </TabsList>

        <TabsContent value="learning" className="mt-6">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {module.techniques.map((technique, index) => (
              <Card key={index} className="bg-gray-900 border-green-500 hover:bg-gray-800 transition-colors shadow-md shadow-green-500/10">
                <CardContent className="p-4">
                  <div className="flex items-start space-x-3">
                    <BookOpen className="h-5 w-5 text-green-400 mt-1" />
                    <div>
                      <h4 className="text-green-400 font-mono font-medium">{technique}</h4>
                      <p className="text-green-300 text-sm mt-1 font-mono">
                        Educational content and ethical application guidelines
                      </p>
                      <Badge variant="outline" className="mt-2 border-green-500 text-green-300 font-mono">
                        EDUCATIONAL_ONLY
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
              <Card key={index} className="bg-gray-900 border-green-500 hover:bg-gray-800 transition-colors shadow-md shadow-green-500/10">
                <CardContent className="p-4">
                  <div className="flex items-start space-x-3">
                    <Shield className="h-5 w-5 text-cyan-400 mt-1" />
                    <div>
                      <h4 className="text-green-400 font-mono font-medium">{strategy}</h4>
                      <p className="text-green-300 text-sm mt-1 font-mono">
                        Protective measures and implementation guidelines
                      </p>
                      <Badge variant="outline" className="mt-2 border-cyan-500 text-cyan-300 font-mono">
                        DEFENSE_PROTOCOL
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
      <Card className="bg-red-900/20 border-red-500 shadow-lg shadow-red-500/20">
        <CardContent className="p-6">
          <div className="flex items-start space-x-3">
            <AlertTriangle className="h-6 w-6 text-red-400 mt-1" />
            <div>
              <h3 className="text-red-400 font-semibold mb-2 font-mono">[ETHICAL_GUIDELINES]</h3>
              <ul className="text-red-300 text-sm space-y-1 font-mono">
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
