'use client';

import React from 'react';
import { ThemeProvider } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ReactQueryDevtools } from '@tanstack/react-query-devtools';
import { ApolloProvider } from '@apollo/client';
import { Toaster } from 'react-hot-toast';

import { theme } from '@/lib/theme';
import { apolloClient } from '@/lib/apollo';
import { AuthProvider } from '@/lib/auth/AuthProvider';
import ErrorBoundary from '@/components/common/ErrorBoundary';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 3,
      retryDelay: (attemptIndex) => Math.min(1000 * 2 ** attemptIndex, 30000),
      staleTime: 5 * 60 * 1000, // 5 minutes
      refetchOnWindowFocus: false,
    },
    mutations: {
      retry: 1,
    },
  },
});

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <head>
        <meta charSet="utf-8" />
        <meta name="viewport" content="width=device-width, initial-scale=1" />
        <meta name="description" content="Pat Email Testing Platform" />
        <title>Pat - Email Testing Platform</title>
        <link rel="icon" href="/favicon.ico" />
      </head>
      <body>
        <ErrorBoundary>
          <ThemeProvider theme={theme}>
            <CssBaseline />
            <QueryClientProvider client={queryClient}>
              <ApolloProvider client={apolloClient}>
                <AuthProvider>
                  {children}
                  <Toaster
                    position="top-right"
                    toastOptions={{
                      duration: 4000,
                      style: {
                        background: '#363636',
                        color: '#fff',
                      },
                      success: {
                        duration: 3000,
                        iconTheme: {
                          primary: '#4caf50',
                          secondary: '#fff',
                        },
                      },
                      error: {
                        duration: 5000,
                        iconTheme: {
                          primary: '#f44336',
                          secondary: '#fff',
                        },
                      },
                    }}
                  />
                </AuthProvider>
              </ApolloProvider>
              <ReactQueryDevtools initialIsOpen={false} />
            </QueryClientProvider>
          </ThemeProvider>
        </ErrorBoundary>
      </body>
    </html>
  );
}