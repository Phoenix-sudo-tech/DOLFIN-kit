
import React from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { LucideIcon } from 'lucide-react';

interface SecurityModule {
  id: string;
  title: string;
  description: string;
  icon: LucideIcon;
  color: string;
  techniques: string[];
  defenseStrategies: string[];
}

interface SecurityModuleCardProps {
  module: SecurityModule;
  onSelect: () => void;
}

const SecurityModuleCard: React.FC<SecurityModuleCardProps> = ({ module, onSelect }) => {
  const Icon = module.icon;

  return (
    <Card className="bg-gray-900 border-green-500 hover:bg-gray-800 transition-all duration-300 cursor-pointer group shadow-lg shadow-green-500/20">
      <CardHeader>
        <div className="flex items-center space-x-3">
          <div className={`p-3 rounded-lg ${module.color} group-hover:scale-110 transition-transform duration-300`}>
            <Icon className="h-6 w-6 text-white" />
          </div>
          <div>
            <CardTitle className="text-green-400 text-lg font-mono">{module.title}</CardTitle>
            <Badge variant="outline" className="mt-1 border-green-500 text-green-300 font-mono">
              {module.techniques.length} T00L5
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <CardDescription className="text-green-300 mb-4 font-mono">
          {module.description}
        </CardDescription>
        <div className="space-y-2 mb-4">
          <p className="text-green-400 text-sm font-mono font-medium">[KEY_AREAS]:</p>
          <div className="flex flex-wrap gap-1">
            {module.techniques.slice(0, 3).map((technique, index) => (
              <Badge key={index} variant="secondary" className="text-xs bg-gray-800 text-green-300 border border-green-500 font-mono">
                {technique}
              </Badge>
            ))}
            {module.techniques.length > 3 && (
              <Badge variant="secondary" className="text-xs bg-gray-800 text-green-300 border border-green-500 font-mono">
                +{module.techniques.length - 3} M0RE
              </Badge>
            )}
          </div>
        </div>
        <Button 
          onClick={onSelect}
          className="w-full bg-green-600 hover:bg-green-500 text-black font-mono"
        >
          ACCESS_MODULE
        </Button>
      </CardContent>
    </Card>
  );
};

export default SecurityModuleCard;
