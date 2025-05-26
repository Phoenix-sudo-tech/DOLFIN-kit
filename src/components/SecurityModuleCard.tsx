
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
    <Card className="bg-white/5 border-white/20 hover:bg-white/10 transition-all duration-300 cursor-pointer group">
      <CardHeader>
        <div className="flex items-center space-x-3">
          <div className={`p-3 rounded-lg ${module.color} group-hover:scale-110 transition-transform duration-300`}>
            <Icon className="h-6 w-6 text-white" />
          </div>
          <div>
            <CardTitle className="text-white text-lg">{module.title}</CardTitle>
            <Badge variant="outline" className="mt-1 border-white/30 text-white/70">
              {module.techniques.length} Topics
            </Badge>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <CardDescription className="text-white/70 mb-4">
          {module.description}
        </CardDescription>
        <div className="space-y-2 mb-4">
          <p className="text-white/80 text-sm font-medium">Key Areas:</p>
          <div className="flex flex-wrap gap-1">
            {module.techniques.slice(0, 3).map((technique, index) => (
              <Badge key={index} variant="secondary" className="text-xs bg-white/10 text-white/80">
                {technique}
              </Badge>
            ))}
            {module.techniques.length > 3 && (
              <Badge variant="secondary" className="text-xs bg-white/10 text-white/80">
                +{module.techniques.length - 3} more
              </Badge>
            )}
          </div>
        </div>
        <Button 
          onClick={onSelect}
          className="w-full bg-blue-500 hover:bg-blue-600 text-white"
        >
          Explore Module
        </Button>
      </CardContent>
    </Card>
  );
};

export default SecurityModuleCard;
