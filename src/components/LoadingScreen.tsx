
import React from 'react';
import { Shield, Terminal, Eye, Network } from 'lucide-react';

const LoadingScreen = () => {
  return (
    <div className="fixed inset-0 bg-black flex items-center justify-center z-50">
      <div className="text-center space-y-8">
        {/* Animated Logo */}
        <div className="relative">
          <div className="w-32 h-32 mx-auto relative">
            <div className="absolute inset-0 border-4 border-green-500 rounded-full animate-spin border-t-transparent"></div>
            <div className="absolute inset-4 border-2 border-green-400 rounded-full animate-spin animate-reverse border-r-transparent"></div>
            <div className="absolute inset-8 flex items-center justify-center">
              <Shield className="h-12 w-12 text-green-400 animate-pulse" />
            </div>
          </div>
        </div>

        {/* Loading Text */}
        <div className="space-y-4">
          <h1 className="text-4xl font-bold text-green-400 font-mono tracking-wider">
            D0LF1N T00L5
          </h1>
          <p className="text-green-300 font-mono text-lg">
            [INITIALIZING ETHICAL PENETRATION TESTING FRAMEWORK]
          </p>
          
          {/* Loading Steps */}
          <div className="space-y-2 text-sm font-mono text-green-300 max-w-md mx-auto">
            <div className="flex items-center justify-between">
              <span>• Loading security modules...</span>
              <span className="text-green-400">✓</span>
            </div>
            <div className="flex items-center justify-between">
              <span>• Initializing exploit frameworks...</span>
              <span className="text-green-400 animate-pulse">⟳</span>
            </div>
            <div className="flex items-center justify-between">
              <span>• Configuring network tools...</span>
              <span className="text-gray-500">○</span>
            </div>
            <div className="flex items-center justify-between">
              <span>• Establishing secure connection...</span>
              <span className="text-gray-500">○</span>
            </div>
          </div>

          {/* Progress Bar */}
          <div className="w-80 mx-auto bg-gray-800 rounded-full h-2">
            <div className="bg-green-500 h-2 rounded-full animate-pulse" style={{ width: '65%' }}></div>
          </div>

          {/* Rotating Icons */}
          <div className="flex justify-center space-x-8 mt-8">
            <Terminal className="h-6 w-6 text-green-400 animate-bounce" />
            <Eye className="h-6 w-6 text-green-400 animate-bounce" style={{ animationDelay: '0.2s' }} />
            <Network className="h-6 w-6 text-green-400 animate-bounce" style={{ animationDelay: '0.4s' }} />
          </div>
        </div>

        {/* Warning */}
        <div className="text-xs text-red-400 font-mono max-w-lg mx-auto">
          [WARNING] Authorized use only • Educational purposes • Developer: @ethicalphoenix
        </div>
      </div>
    </div>
  );
};

export default LoadingScreen;
