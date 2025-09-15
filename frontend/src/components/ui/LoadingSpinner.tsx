'use client';

import React from 'react';
import { CircularProgress, Box, Typography } from '@mui/material';

interface LoadingSpinnerProps {
  size?: number | string;
  color?: 'primary' | 'secondary' | 'error' | 'info' | 'success' | 'warning' | 'inherit';
  message?: string;
  variant?: 'determinate' | 'indeterminate';
  value?: number;
  thickness?: number;
  fullScreen?: boolean;
  overlay?: boolean;
}

export const LoadingSpinner: React.FC<LoadingSpinnerProps> = ({
  size = 40,
  color = 'primary',
  message,
  variant = 'indeterminate',
  value,
  thickness = 3.6,
  fullScreen = false,
  overlay = false,
}) => {
  const spinner = (
    <CircularProgress
      size={size}
      color={color}
      variant={variant}
      value={value}
      thickness={thickness}
    />
  );

  if (fullScreen) {
    return (
      <Box
        sx={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          display: 'flex',
          flexDirection: 'column',
          justifyContent: 'center',
          alignItems: 'center',
          backgroundColor: overlay ? 'rgba(0, 0, 0, 0.5)' : 'background.default',
          zIndex: 9999,
          gap: 2,
        }}
      >
        {spinner}
        {message && (
          <Typography variant="body1" color="text.secondary">
            {message}
          </Typography>
        )}
      </Box>
    );
  }

  if (message) {
    return (
      <Box
        sx={{
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          gap: 2,
          p: 2,
        }}
      >
        {spinner}
        <Typography variant="body2" color="text.secondary" textAlign="center">
          {message}
        </Typography>
      </Box>
    );
  }

  return spinner;
};

export default LoadingSpinner;