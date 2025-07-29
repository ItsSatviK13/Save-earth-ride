'use client';

import { useState, useEffect } from 'react';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Bike, TreePine, Shield, AlertCircle } from 'lucide-react';
import { toast } from 'sonner';

/**
 * Admin Authentication System
 * 
 * This component handles admin login with role-based access control.
 * It validates credentials against the admin API and manages sessions
 * with automatic timeout after 3 minutes of inactivity.
 * 
 * Roles:
 * - Super Admin: Full access to all features and data
 * - Admin: Access to most features with some restrictions
 * - Manager: Limited access to specific sections
 * - Editor: Read-only access with content editing permissions
 */

interface Admin {
  id: number;
  username: string;
  email: string;
  password: string;
  role: string;
  createdAt?: string;
  lastLogin?: string;
  status?: string;
}

interface AdminSession {
  id: number;
  username: string;
  email: string;
  role: string;
  loginTime: string;
  lastActivity: string;
  permissions: RolePermissions;
}

interface RolePermissions {
  canManageAdmins: boolean;
  canManageAllData: boolean;
  canDeleteData: boolean;
  canExportData: boolean;
  canViewAnalytics: boolean;
  canManageSettings: boolean;
}

const SESSION_TIMEOUT = 3 * 60 * 1000; // 3 minutes in milliseconds

export default function AdminPage() {
  const [loginForm, setLoginForm] = useState({ username: '', password: '' });
  const [isLoading, setIsLoading] = useState(false);
  const [loginAttempts, setLoginAttempts] = useState(0);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentSession, setCurrentSession] = useState<AdminSession | null>(null);

  /**
   * Session Management
   * 
   * Checks for existing session and validates timeout
   */
  useEffect(() => {
    checkExistingSession();
    
    // Set up session timeout checker
    const sessionChecker = setInterval(() => {
      checkSessionTimeout();
    }, 30000); // Check every 30 seconds

    // Update last activity on user interaction
    const updateActivity = () => updateLastActivity();
    
    document.addEventListener('mousedown', updateActivity);
    document.addEventListener('keydown', updateActivity);
    document.addEventListener('scroll', updateActivity);
    document.addEventListener('touchstart', updateActivity);

    return () => {
      clearInterval(sessionChecker);
      document.removeEventListener('mousedown', updateActivity);
      document.removeEventListener('keydown', updateActivity);
      document.removeEventListener('scroll', updateActivity);
      document.removeEventListener('touchstart', updateActivity);
    };
  }, []);

  /**
   * Check for existing valid session
   */
  const checkExistingSession = () => {
    if (typeof window !== 'undefined') {
      try {
        const sessionData = localStorage.getItem('adminSession');
        if (sessionData) {
          const session: AdminSession = JSON.parse(sessionData);
          const now = Date.now();
          const lastActivity = new Date(session.lastActivity).getTime();
          
          if (now - lastActivity < SESSION_TIMEOUT) {
            setCurrentSession(session);
            setIsAuthenticated(true);
            updateLastActivity();
            // Redirect to dashboard if already authenticated
            setTimeout(() => {
              window.location.href = '/admin/dashboard';
            }, 1000);
          } else {
            // Session expired
            handleLogout(false);
          }
        }
      } catch (error) {
        console.error('Error checking session:', error);
        handleLogout(false);
      }
    }
  };

  /**
   * Check if session has timed out
   */
  const checkSessionTimeout = () => {
    if (currentSession && typeof window !== 'undefined') {
      const sessionData = localStorage.getItem('adminSession');
      if (sessionData) {
        try {
          const session: AdminSession = JSON.parse(sessionData);
          const now = Date.now();
          const lastActivity = new Date(session.lastActivity).getTime();
          
          if (now - lastActivity >= SESSION_TIMEOUT) {
            toast.error('Session expired due to inactivity');
            handleLogout(false);
          }
        } catch (error) {
          console.error('Error checking session timeout:', error);
          handleLogout(false);
        }
      }
    }
  };

  /**
   * Update last activity timestamp
   */
  const updateLastActivity = () => {
    if (typeof window !== 'undefined' && currentSession) {
      try {
        const updatedSession = {
          ...currentSession,
          lastActivity: new Date().toISOString()
        };
        localStorage.setItem('adminSession', JSON.stringify(updatedSession));
        setCurrentSession(updatedSession);
      } catch (error) {
        console.error('Error updating activity:', error);
      }
    }
  };

  /**
   * Fetch admin data from API
   */
  const fetchAdminData = async (): Promise<Admin[]> => {
    try {
      const response = await fetch('/api/admins', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      });

      if (!response.ok) {
        throw new Error(`API Error: ${response.status}`);
      }

      const result = await response.json();
      return result.data || [];
    } catch (error) {
      console.error('Error fetching admin data:', error);
      throw new Error('Failed to fetch admin data from API');
    }
  };

  /**
   * Authentication Handler
   * 
   * Validates user credentials against the admin API.
   * Implements security features like attempt limiting and role-based access.
   */
  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    
    // Check for too many failed attempts
    if (loginAttempts >= 5) {
      toast.error('Too many failed attempts. Please try again later.');
      return;
    }

    // Input validation
    if (!loginForm.username.trim() || !loginForm.password.trim()) {
      toast.error('Please enter both username and password');
      return;
    }

    setIsLoading(true);

    try {
      // Fetch admin data from API
      const adminCredentials = await fetchAdminData();
      
      // Find matching admin
      const admin = adminCredentials.find((a: Admin) => 
        a.username.toLowerCase() === loginForm.username.toLowerCase() && 
        a.password === loginForm.password &&
        (a.status === 'active' || !a.status) // Handle undefined status as active
      );

      if (admin) {
        // Create session data
        const sessionData: AdminSession = {
          id: admin.id,
          username: admin.username,
          email: admin.email,
          role: admin.role,
          loginTime: new Date().toISOString(),
          lastActivity: new Date().toISOString(),
          permissions: getRolePermissions(admin.role)
        };
        
        // Store session
        localStorage.setItem('adminSession', JSON.stringify(sessionData));
        setCurrentSession(sessionData);
        setIsAuthenticated(true);
        
        // Update admin's last login in API
        try {
          const updatedAdmins = adminCredentials.map((a: Admin) => 
            a.id === admin.id 
              ? { ...a, lastLogin: new Date().toLocaleDateString() }
              : a
          );
          
          await fetch('/api/admins', {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
            },
            body: JSON.stringify(updatedAdmins),
          });
        } catch (updateError) {
          console.error('Error updating last login:', updateError);
          // Don't fail login if update fails
        }
        
        toast.success(`Welcome back, ${admin.username}! (${admin.role})`);
        
        // Role-based redirection
        setTimeout(() => {
          window.location.href = '/admin/dashboard';
        }, 1000);
        
        // Reset login attempts on successful login
        setLoginAttempts(0);
      } else {
        setLoginAttempts(prev => prev + 1);
        toast.error(`Invalid credentials. ${5 - loginAttempts - 1} attempts remaining.`);
      }
    } catch (error) {
      console.error('Login error:', error);
      toast.error('Login failed. Unable to connect to authentication service.');
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Role Permissions System
   * 
   * Defines what each role can access and modify.
   */
  const getRolePermissions = (role: string): RolePermissions => {
    switch (role) {
      case 'Super Admin':
        return {
          canManageAdmins: true,
          canManageAllData: true,
          canDeleteData: true,
          canExportData: true,
          canViewAnalytics: true,
          canManageSettings: true
        };
      case 'Admin':
        return {
          canManageAdmins: false,
          canManageAllData: true,
          canDeleteData: true,
          canExportData: true,
          canViewAnalytics: true,
          canManageSettings: false
        };
      case 'Manager':
        return {
          canManageAdmins: false,
          canManageAllData: false,
          canDeleteData: false,
          canExportData: true,
          canViewAnalytics: true,
          canManageSettings: false
        };
      case 'Editor':
        return {
          canManageAdmins: false,
          canManageAllData: false,
          canDeleteData: false,
          canExportData: false,
          canViewAnalytics: false,
          canManageSettings: false
        };
      default:
        return {
          canManageAdmins: false,
          canManageAllData: false,
          canDeleteData: false,
          canExportData: false,
          canViewAnalytics: false,
          canManageSettings: false
        };
    }
  };

  /**
   * Logout Handler
   */
  const handleLogout = (showMessage: boolean = true) => {
    if (typeof window !== 'undefined') {
      localStorage.removeItem('adminSession');
      setCurrentSession(null);
      setIsAuthenticated(false);
      setLoginAttempts(0);
      
      if (showMessage) {
        toast.success('You have been logged out successfully.');
      }
      
      // Clear form
      setLoginForm({ username: '', password: '' });
    }
  };

  // Show logout button if authenticated
  if (isAuthenticated && currentSession) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-50 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center">
        <Card className="w-full max-w-md shadow-2xl border-0">
          <CardHeader className="text-center pb-8">
            <div className="flex items-center justify-center space-x-2 mb-6">
              <Shield className="h-12 w-12 text-primary" />
            </div>
            <CardTitle className="text-3xl bg-gradient-to-r from-green-600 to-blue-600 bg-clip-text text-transparent mb-2">
              Welcome Back!
            </CardTitle>
            <p className="text-muted-foreground">
              You are logged in as {currentSession.username} ({currentSession.role})
            </p>
          </CardHeader>
          
          <CardContent className="space-y-4">
            <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
              <h4 className="text-sm font-semibold text-green-800 dark:text-green-200 mb-2">
                Session Information:
              </h4>
              <div className="space-y-1 text-xs text-green-700 dark:text-green-300">
                <div><strong>Login Time:</strong> {new Date(currentSession.loginTime).toLocaleString()}</div>
                <div><strong>Role:</strong> {currentSession.role}</div>
                <div><strong>Session Timeout:</strong> 3 minutes of inactivity</div>
              </div>
            </div>
            
            <div className="flex space-x-2">
              <Button 
                onClick={() => window.location.href = '/admin/dashboard'} 
                className="flex-1"
              >
                Go to Dashboard
              </Button>
              <Button variant="outline" onClick={() => handleLogout()}>
                Logout
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-blue-50 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center">
      <Card className="w-full max-w-md shadow-2xl border-0">
        <CardHeader className="text-center pb-8">
          <div className="flex items-center justify-center space-x-2 mb-6">
            <div className="relative">
              <Shield className="h-12 w-12 text-primary" />
            </div>
          </div>
          <CardTitle className="text-3xl bg-gradient-to-r from-green-600 to-blue-600 bg-clip-text text-transparent mb-2">
            Admin Login
          </CardTitle>
          <p className="text-muted-foreground">
            Secure access to Save Earth Ride admin panel
          </p>
        </CardHeader>
        
        <CardContent>
          <form onSubmit={handleLogin} className="space-y-6">
            <div className="space-y-2">
              <Label htmlFor="username">Username</Label>
              <Input
                id="username"
                value={loginForm.username}
                onChange={(e) => setLoginForm({...loginForm, username: e.target.value})}
                placeholder="Enter your username"
                className="bg-background"
                disabled={isLoading}
                required
              />
            </div>
            
            <div className="space-y-2">
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                value={loginForm.password}
                onChange={(e) => setLoginForm({...loginForm, password: e.target.value})}
                placeholder="Enter your password"
                className="bg-background"
                disabled={isLoading}
                required
              />
            </div>
            
            {/* Security Warning */}
            {loginAttempts > 2 && (
              <div className="flex items-center space-x-2 p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
                <AlertCircle className="h-4 w-4 text-red-500" />
                <span className="text-sm text-red-600 dark:text-red-400">
                  {5 - loginAttempts} attempts remaining before lockout
                </span>
              </div>
            )}
            
            <Button 
              type="submit" 
              className="w-full" 
              size="lg"
              disabled={isLoading || loginAttempts >= 5}
            >
              {isLoading ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Authenticating...
                </>
              ) : (
                <>
                  <Shield className="h-4 w-4 mr-2" />
                  Login to Admin Panel
                </>
              )}
            </Button>
            
            {/* Session Info */}
            <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
              <h4 className="text-sm font-semibold text-blue-800 dark:text-blue-200 mb-2">
                Session Security:
              </h4>
              <div className="space-y-1 text-xs text-blue-700 dark:text-blue-300">
                <div>• Sessions expire after 3 minutes of inactivity</div>
                <div>• Maximum 5 login attempts before lockout</div>
                <div>• Secure API-based authentication</div>
              </div>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  );
}