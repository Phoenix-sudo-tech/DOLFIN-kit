
import React from 'react';
import { Shield, Terminal } from 'lucide-react';
import { Button } from "@/components/ui/button";

interface LoadingScreenProps {
  onEnter: () => void;
}

const LoadingScreen = ({ onEnter }: LoadingScreenProps) => {
  return (
    <div className="fixed inset-0 bg-black flex items-center justify-center z-50">
      <div className="text-center space-y-8 max-w-md">
        {/* Minimal Logo */}
        <div className="relative mx-auto">
          <div className="w-24 h-24 mx-auto relative">
            <div className="absolute inset-0 border-2 border-red-500 rounded-full animate-pulse"></div>
            <div className="absolute inset-4 flex items-center justify-center">
              <Shield className="h-8 w-8 text-red-400" />
            </div>
          </div>
        </div>

        {/* Minimal Text */}
        <div className="space-y-4">
          <h1 className="text-3xl font-bold text-red-400 font-mono tracking-wider">
            PHOENIX FRAMEWORK
          </h1>
          <p className="text-red-300 font-mono">
            Advanced Penetration Testing Suite
          </p>
          
          {/* Simple Loading Indicator */}
          <div className="flex items-center justify-center space-x-2">
            <Terminal className="h-4 w-4 text-red-400 animate-pulse" />
            <span className="text-red-300 font-mono text-sm">INITIALIZING...</span>
          </div>

          {/* Access Button */}
          <div className="mt-8">
            <Button
              onClick={onEnter}
              className="bg-red-600 hover:bg-red-500 text-white font-mono px-8 py-3 text-lg"
            >
              [ACCESS_FRAMEWORK]
            </Button>
          </div>
        </div>

        {/* Warning */}
        <div className="text-xs text-red-400 font-mono">
          [AUTHORIZED USE ONLY] • Created by @ethicalphoenix
        </div>
      </div>
    </div>
  );
};

export default LoadingScreen;
