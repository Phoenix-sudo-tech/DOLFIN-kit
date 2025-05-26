
import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Users, Mail, Phone, MessageSquare } from 'lucide-react';

const SocialEngTools = () => {
  const [targetEmail, setTargetEmail] = useState('');
  const [targetPhone, setTargetPhone] = useState('');
  const [emailTemplate, setEmailTemplate] = useState('');
  const [results, setResults] = useState<string[]>([]);
  const [isGenerating, setIsGenerating] = useState(false);

  const generatePhishingEmail = async (email: string) => {
    setIsGenerating(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 2000));
    
    const templates = [
      {
        subject: "Urgent: Account Security Alert",
        body: `Dear ${email.split('@')[0]},\n\nWe have detected suspicious activity on your account. Please verify your identity immediately by clicking the link below:\n\nhttps://secure-verification-portal.com/verify\n\nFailure to verify within 24 hours will result in account suspension.\n\nBest regards,\nSecurity Team`
      },
      {
        subject: "IT Department: System Maintenance",
        body: `Hello,\n\nScheduled maintenance requires all users to update their passwords. Please use the secure portal below:\n\nhttps://company-password-update.com/login\n\nMaintenance window: Tonight 2:00 AM - 4:00 AM\n\nIT Support Team`
      }
    ];
    
    const selectedTemplate = templates[Math.floor(Math.random() * templates.length)];
    
    const mockResults = [
      `[+] Phishing Email Generator - Target: ${email}`,
      `[+] Template Generated Successfully`,
      '',
      '[+] Email Details:',
      `Subject: ${selectedTemplate.subject}`,
      `To: ${email}`,
      `From: security@company-domain.com`,
      '',
      '[+] Email Body:',
      selectedTemplate.body,
      '',
      '[!] SUCCESS INDICATORS:',
      '• Uses urgency and authority',
      '• Mimics legitimate communication style',
      '• Includes believable call-to-action',
      '• Uses deceptive but realistic domain',
      '',
      '[!] EDUCATIONAL PURPOSE ONLY - Do not use for malicious intent',
      '[!] This demonstrates common phishing techniques for awareness training'
    ];
    
    setEmailTemplate(selectedTemplate.body);
    setResults(mockResults);
    setIsGenerating(false);
  };

  const generateVishingScript = async (phone: string) => {
    setIsGenerating(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 2500));
    
    const mockResults = [
      `[+] Vishing Script Generator - Target: ${phone}`,
      `[+] Voice Phishing Script Created`,
      '',
      '[+] SCENARIO: IT Support Call',
      '[+] PERSONA: Technical Support Representative',
      '',
      '[+] SCRIPT:',
      '"Hello, this is John from IT Support. We\'ve detected unusual activity',
      'on your computer that appears to be malware. For security, I need to',
      'remote into your system to remove the threat immediately."',
      '',
      '"Can you please go to your computer and press Windows+R? Then type',
      'in the following URL so I can help secure your system..."',
      '',
      '[+] PSYCHOLOGICAL TECHNIQUES USED:',
      '• Authority (IT Support role)',
      '• Urgency (immediate threat)',
      '• Fear (malware infection)',
      '• Helpfulness (offering assistance)',
      '',
      '[+] RED FLAGS TO RECOGNIZE:',
      '• Unsolicited technical support calls',
      '• Requests for remote access',
      '• Pressure to act immediately',
      '• Requests for personal information',
      '',
      '[!] EDUCATIONAL PURPOSE ONLY - Awareness training scenario',
      '[!] Real IT support will never call unsolicited'
    ];
    
    setResults(mockResults);
    setIsGenerating(false);
  };

  const analyzeTarget = async (email: string) => {
    setIsGenerating(true);
    setResults([]);
    
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const domain = email.split('@')[1];
    const username = email.split('@')[0];
    
    const mockResults = [
      `[+] Social Engineering Target Analysis: ${email}`,
      `[+] OSINT Gathering Simulation`,
      '',
      '[+] EMAIL ANALYSIS:',
      `Domain: ${domain}`,
      `Username pattern: ${username}`,
      `Domain type: ${domain.includes('.edu') ? 'Educational' : domain.includes('.gov') ? 'Government' : 'Commercial'}`,
      '',
      '[+] SIMULATED SOCIAL MEDIA PRESENCE:',
      '• LinkedIn: Professional profile found',
      '• Facebook: Limited public information',
      '• Twitter: Active user, posts about technology',
      '• Instagram: Personal photos with location tags',
      '',
      '[+] POTENTIAL ATTACK VECTORS:',
      '• Work-related phishing (LinkedIn connection)',
      '• Personal interest targeting (tech posts)',
      '• Location-based pretexting (Instagram data)',
      '• Authority-based approach (professional profile)',
      '',
      '[+] RECOMMENDED DEFENSES:',
      '• Privacy settings review on all platforms',
      '• Limit personal information sharing',
      '• Security awareness training',
      '• Multi-factor authentication setup',
      '',
      '[!] EDUCATIONAL ANALYSIS ONLY',
      '[!] This demonstrates information gathering techniques for awareness'
    ];
    
    setResults(mockResults);
    setIsGenerating(false);
  };

  return (
    <div className="space-y-6">
      {/* Input Section */}
      <Card className="bg-black border-orange-500">
        <CardHeader>
          <CardTitle className="text-orange-400 font-mono flex items-center space-x-2">
            <Users className="h-5 w-5" />
            <span>[SOCIAL_ENGINEERING_TOOLKIT]</span>
          </CardTitle>
          <CardDescription className="text-orange-300 font-mono">
            Educational tools for security awareness training
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-green-400 font-mono text-sm mb-2 block">TARGET_EMAIL:</label>
              <Input
                placeholder="target@company.com"
                value={targetEmail}
                onChange={(e) => setTargetEmail(e.target.value)}
                className="bg-gray-900 border-orange-500 text-green-400 font-mono"
              />
            </div>
            <div>
              <label className="text-green-400 font-mono text-sm mb-2 block">TARGET_PHONE:</label>
              <Input
                placeholder="+1 (555) 123-4567"
                value={targetPhone}
                onChange={(e) => setTargetPhone(e.target.value)}
                className="bg-gray-900 border-orange-500 text-green-400 font-mono"
              />
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Button
              onClick={() => targetEmail && generatePhishingEmail(targetEmail)}
              disabled={!targetEmail || isGenerating}
              className="bg-orange-600 hover:bg-orange-500 text-white font-mono"
            >
              <Mail className="h-4 w-4 mr-2" />
              PHISH_EMAIL
            </Button>
            
            <Button
              onClick={() => targetPhone && generateVishingScript(targetPhone)}
              disabled={!targetPhone || isGenerating}
              className="bg-red-600 hover:bg-red-500 text-white font-mono"
            >
              <Phone className="h-4 w-4 mr-2" />
              VISH_SCRIPT
            </Button>
            
            <Button
              onClick={() => targetEmail && analyzeTarget(targetEmail)}
              disabled={!targetEmail || isGenerating}
              className="bg-purple-600 hover:bg-purple-500 text-white font-mono"
            >
              <MessageSquare className="h-4 w-4 mr-2" />
              TARGET_OSINT
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Results Section */}
      <Card className="bg-black border-orange-500">
        <CardHeader>
          <CardTitle className="text-orange-400 font-mono flex items-center space-x-2">
            <Users className="h-5 w-5" />
            <span>[SOCIAL_ENG_OUTPUT]</span>
            {isGenerating && <Badge className="bg-orange-500 text-white animate-pulse">GENERATING...</Badge>}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-gray-900 rounded-lg p-4 font-mono text-sm max-h-96 overflow-y-auto">
            {results.length === 0 && !isGenerating && (
              <p className="text-green-300">root@dolfin:~# Social engineering awareness tools ready...</p>
            )}
            {isGenerating && (
              <div className="space-y-2">
                <p className="text-orange-400">[*] Generating social engineering content...</p>
                <p className="text-orange-400 animate-pulse">[*] Creating awareness scenarios...</p>
                <p className="text-orange-400 animate-pulse">[*] Analyzing psychological triggers...</p>
              </div>
            )}
            {results.map((result, index) => (
              <div key={index} className={`mb-1 ${
                result.includes('[!]') && result.includes('PURPOSE') ? 'text-green-400' :
                result.includes('[!]') ? 'text-red-400' :
                result.includes('[+]') ? 'text-orange-400' :
                'text-green-300'
              }`}>
                {result}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Generated Email Template */}
      {emailTemplate && (
        <Card className="bg-gray-900 border-yellow-500">
          <CardHeader>
            <CardTitle className="text-yellow-400 font-mono">[GENERATED_EMAIL_TEMPLATE]</CardTitle>
          </CardHeader>
          <CardContent>
            <Textarea
              value={emailTemplate}
              onChange={(e) => setEmailTemplate(e.target.value)}
              className="bg-black border-yellow-500 text-green-400 font-mono text-sm h-32"
              placeholder="Generated email template will appear here..."
            />
          </CardContent>
        </Card>
      )}

      {/* Tool Info */}
      <Card className="bg-gray-900 border-yellow-500">
        <CardHeader>
          <CardTitle className="text-yellow-400 font-mono">[SOCIAL_ENG_INFO]</CardTitle>
        </CardHeader>
        <CardContent className="text-yellow-300 font-mono text-sm space-y-2">
          <p>• Phishing Email: Generate realistic phishing awareness examples</p>
          <p>• Vishing Script: Create voice phishing scenarios for training</p>
          <p>• Target OSINT: Demonstrate information gathering techniques</p>
          <p>• All tools designed for security awareness training</p>
          <p className="text-red-400">⚠ FOR EDUCATIONAL AND AUTHORIZED TRAINING ONLY</p>
          <p className="text-red-400">⚠ Using these techniques maliciously is illegal</p>
        </CardContent>
      </Card>
    </div>
  );
};

export default SocialEngTools;
