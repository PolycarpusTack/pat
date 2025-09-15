'use client';

import React, { useState } from 'react';
import { useForm, Controller } from 'react-hook-form';
import { zodResolver } from '@hookform/resolvers/zod';
import { z } from 'zod';
import {
  Box,
  Button,
  Card,
  CardContent,
  CardHeader,
  Checkbox,
  Divider,
  FormControl,
  FormControlLabel,
  FormHelperText,
  IconButton,
  InputAdornment,
  Link,
  TextField,
  Typography,
  Alert,
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Email as EmailIcon,
  Lock as LockIcon,
  Login as LoginIcon,
} from '@mui/icons-material';
import { useAuth } from '../../hooks/useAuth';
import { LoadingSpinner } from '../ui/LoadingSpinner';

const loginSchema = z.object({
  email: z.string().email('Please enter a valid email address'),
  password: z.string().min(1, 'Password is required'),
  mfaCode: z.string().optional(),
  rememberMe: z.boolean().default(false),
});

type LoginFormData = z.infer<typeof loginSchema>;

interface LoginFormProps {
  onSuccess?: () => void;
  onForgotPassword?: () => void;
  onSignUp?: () => void;
  redirectTo?: string;
}

export const LoginForm: React.FC<LoginFormProps> = ({
  onSuccess,
  onForgotPassword,
  onSignUp,
  redirectTo,
}) => {
  const [showPassword, setShowPassword] = useState(false);
  const [showMFA, setShowMFA] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const { login, isLoading } = useAuth();

  const {
    control,
    handleSubmit,
    formState: { errors, isValid },
    watch,
    setError: setFieldError,
  } = useForm<LoginFormData>({
    resolver: zodResolver(loginSchema),
    mode: 'onChange',
  });

  const watchedEmail = watch('email');
  const watchedPassword = watch('password');

  const onSubmit = async (data: LoginFormData) => {
    setError(null);
    
    try {
      const result = await login({
        email: data.email,
        password: data.password,
        mfa_code: data.mfaCode,
        device_id: generateDeviceId(),
        remember_me: data.rememberMe,
      });

      if (result.requiresMFA && !data.mfaCode) {
        setShowMFA(true);
        setError('Please enter your MFA code to continue');
        return;
      }

      onSuccess?.();
      
      // Redirect if specified
      if (redirectTo) {
        window.location.href = redirectTo;
      }
    } catch (err: any) {
      setError(err.message || 'Login failed. Please try again.');
      
      // Handle specific error cases
      if (err.message?.includes('invalid_mfa')) {
        setFieldError('mfaCode', { message: 'Invalid MFA code' });
      }
    }
  };

  const generateDeviceId = (): string => {
    const stored = localStorage.getItem('pat_device_id');
    if (stored) return stored;
    
    const deviceId = `web_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
    localStorage.setItem('pat_device_id', deviceId);
    return deviceId;
  };

  const togglePasswordVisibility = () => {
    setShowPassword(!showPassword);
  };

  const isFormValid = isValid && watchedEmail && watchedPassword;

  return (
    <Card 
      sx={{ 
        maxWidth: 400, 
        width: '100%',
        boxShadow: (theme) => theme.shadows[8],
      }}
    >
      <CardHeader
        title={
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <LoginIcon color="primary" />
            <Typography variant="h5" component="h1">
              Sign In
            </Typography>
          </Box>
        }
        subheader={
          <Typography variant="body2" color="text.secondary">
            Access your Pat email testing dashboard
          </Typography>
        }
        sx={{ pb: 1 }}
      />

      <CardContent>
        {error && (
          <Alert 
            severity="error" 
            sx={{ mb: 2 }}
            onClose={() => setError(null)}
          >
            {error}
          </Alert>
        )}

        <Box
          component="form"
          onSubmit={handleSubmit(onSubmit)}
          sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}
        >
          <Controller
            name="email"
            control={control}
            render={({ field }) => (
              <TextField
                {...field}
                type="email"
                label="Email Address"
                placeholder="Enter your email"
                fullWidth
                variant="outlined"
                error={!!errors.email}
                helperText={errors.email?.message}
                disabled={isLoading}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <EmailIcon color="action" />
                    </InputAdornment>
                  ),
                }}
                autoComplete="email"
                autoFocus
              />
            )}
          />

          <Controller
            name="password"
            control={control}
            render={({ field }) => (
              <TextField
                {...field}
                type={showPassword ? 'text' : 'password'}
                label="Password"
                placeholder="Enter your password"
                fullWidth
                variant="outlined"
                error={!!errors.password}
                helperText={errors.password?.message}
                disabled={isLoading}
                InputProps={{
                  startAdornment: (
                    <InputAdornment position="start">
                      <LockIcon color="action" />
                    </InputAdornment>
                  ),
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        onClick={togglePasswordVisibility}
                        edge="end"
                        disabled={isLoading}
                        size="small"
                      >
                        {showPassword ? <VisibilityOff /> : <Visibility />}
                      </IconButton>
                    </InputAdornment>
                  ),
                }}
                autoComplete="current-password"
              />
            )}
          />

          {showMFA && (
            <Controller
              name="mfaCode"
              control={control}
              render={({ field }) => (
                <TextField
                  {...field}
                  label="MFA Code"
                  placeholder="Enter your 6-digit code"
                  fullWidth
                  variant="outlined"
                  error={!!errors.mfaCode}
                  helperText={errors.mfaCode?.message || 'Enter the 6-digit code from your authenticator app'}
                  disabled={isLoading}
                  inputProps={{ 
                    maxLength: 6,
                    pattern: '[0-9]*',
                  }}
                />
              )}
            />
          )}

          <Controller
            name="rememberMe"
            control={control}
            render={({ field }) => (
              <FormControlLabel
                control={
                  <Checkbox
                    {...field}
                    checked={field.value || false}
                    disabled={isLoading}
                  />
                }
                label="Remember me for 30 days"
              />
            )}
          />

          <Button
            type="submit"
            variant="contained"
            size="large"
            fullWidth
            disabled={!isFormValid || isLoading}
            startIcon={isLoading ? <LoadingSpinner size={20} /> : <LoginIcon />}
            sx={{ mt: 1 }}
          >
            {isLoading ? 'Signing In...' : 'Sign In'}
          </Button>

          <Divider sx={{ my: 2 }}>
            <Typography variant="body2" color="text.secondary">
              Need help?
            </Typography>
          </Divider>

          <Box sx={{ display: 'flex', justifyContent: 'space-between', gap: 1 }}>
            {onForgotPassword && (
              <Link
                component="button"
                type="button"
                variant="body2"
                onClick={onForgotPassword}
                disabled={isLoading}
                sx={{ textAlign: 'left' }}
              >
                Forgot password?
              </Link>
            )}
            
            {onSignUp && (
              <Link
                component="button"
                type="button"
                variant="body2"
                onClick={onSignUp}
                disabled={isLoading}
                sx={{ textAlign: 'right' }}
              >
                Create account
              </Link>
            )}
          </Box>
        </Box>
      </CardContent>
    </Card>
  );
};

export default LoginForm;