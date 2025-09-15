'use client';

import React, { useState, useCallback } from 'react';
import {
  Box,
  Card,
  CardContent,
  CardHeader,
  Typography,
  Chip,
  IconButton,
  Divider,
  List,
  ListItem,
  ListItemText,
  ListItemIcon,
  Button,
  Dialog,
  DialogContent,
  DialogTitle,
  Tab,
  Tabs,
  Tooltip,
  Alert,
  Link,
  Paper,
} from '@mui/material';
import {
  Email as EmailIcon,
  Person as PersonIcon,
  Schedule as ScheduleIcon,
  Attachment as AttachmentIcon,
  Security as SecurityIcon,
  Code as CodeIcon,
  Visibility as ViewIcon,
  Download as DownloadIcon,
  Forward as ForwardIcon,
  Reply as ReplyIcon,
  Delete as DeleteIcon,
  Flag as FlagIcon,
  Close as CloseIcon,
} from '@mui/icons-material';
import { formatDistanceToNow, format } from 'date-fns';
import { useEmailActions } from '../../hooks/useEmailActions';
import { LoadingSpinner } from '../ui/LoadingSpinner';
import type { Email, EmailAttachment } from '../../types/email';

interface EmailViewerProps {
  email: Email;
  onClose?: () => void;
  onReply?: (email: Email) => void;
  onForward?: (email: Email) => void;
  onDelete?: (emailId: string) => void;
  showActions?: boolean;
}

interface TabPanelProps {
  children?: React.ReactNode;
  index: number;
  value: number;
}

function TabPanel(props: TabPanelProps) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`email-tabpanel-${index}`}
      aria-labelledby={`email-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ pt: 2 }}>{children}</Box>}
    </div>
  );
}

export const EmailViewer: React.FC<EmailViewerProps> = ({
  email,
  onClose,
  onReply,
  onForward,
  onDelete,
  showActions = true,
}) => {
  const [currentTab, setCurrentTab] = useState(0);
  const [showRawEmail, setShowRawEmail] = useState(false);
  const [showAttachment, setShowAttachment] = useState<EmailAttachment | null>(null);

  const {
    deleteEmail,
    markAsSpam,
    markAsNotSpam,
    addTags,
    removeTags,
    isLoading,
  } = useEmailActions();

  const handleTabChange = useCallback((event: React.SyntheticEvent, newValue: number) => {
    setCurrentTab(newValue);
  }, []);

  const handleDelete = useCallback(async () => {
    if (window.confirm('Are you sure you want to delete this email?')) {
      try {
        await deleteEmail(email.id);
        onDelete?.(email.id);
        onClose?.();
      } catch (error) {
        console.error('Failed to delete email:', error);
      }
    }
  }, [email.id, deleteEmail, onDelete, onClose]);

  const handleSpamToggle = useCallback(async () => {
    try {
      if (email.tags.includes('spam')) {
        await markAsNotSpam(email.id);
      } else {
        await markAsSpam(email.id);
      }
    } catch (error) {
      console.error('Failed to toggle spam status:', error);
    }
  }, [email.id, email.tags, markAsSpam, markAsNotSpam]);

  const handleDownloadAttachment = useCallback((attachment: EmailAttachment) => {
    // Create download link
    const link = document.createElement('a');
    link.href = attachment.url;
    link.download = attachment.filename;
    link.target = '_blank';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  }, []);

  const getSpamScoreColor = (score?: number) => {
    if (!score) return 'default';
    if (score < 3) return 'success';
    if (score < 7) return 'warning';
    return 'error';
  };

  const getEmailStatusColor = (status: string) => {
    switch (status) {
      case 'RECEIVED':
        return 'info';
      case 'PROCESSING':
        return 'warning';
      case 'PROCESSED':
        return 'success';
      case 'FAILED':
        return 'error';
      default:
        return 'default';
    }
  };

  return (
    <>
      <Card sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
        <CardHeader
          title={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flex: 1 }}>
              <EmailIcon />
              <Typography variant="h6" component="h2" noWrap sx={{ flex: 1 }}>
                {email.subject || '(No Subject)'}
              </Typography>
              {onClose && (
                <IconButton onClick={onClose} size="small">
                  <CloseIcon />
                </IconButton>
              )}
            </Box>
          }
          subheader={
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, mt: 1 }}>
              <Chip
                label={email.status}
                color={getEmailStatusColor(email.status)}
                size="small"
              />
              {email.spamScore !== undefined && (
                <Chip
                  label={`Spam: ${email.spamScore.toFixed(1)}`}
                  color={getSpamScoreColor(email.spamScore)}
                  size="small"
                />
              )}
              {email.tags.map((tag) => (
                <Chip key={tag} label={tag} size="small" variant="outlined" />
              ))}
            </Box>
          }
          action={
            showActions && (
              <Box sx={{ display: 'flex', gap: 1 }}>
                {onReply && (
                  <Tooltip title="Reply">
                    <IconButton onClick={() => onReply(email)}>
                      <ReplyIcon />
                    </IconButton>
                  </Tooltip>
                )}
                {onForward && (
                  <Tooltip title="Forward">
                    <IconButton onClick={() => onForward(email)}>
                      <ForwardIcon />
                    </IconButton>
                  </Tooltip>
                )}
                <Tooltip title={email.tags.includes('spam') ? 'Mark as Not Spam' : 'Mark as Spam'}>
                  <IconButton onClick={handleSpamToggle} disabled={isLoading}>
                    <FlagIcon color={email.tags.includes('spam') ? 'error' : 'inherit'} />
                  </IconButton>
                </Tooltip>
                <Tooltip title="Delete">
                  <IconButton onClick={handleDelete} disabled={isLoading} color="error">
                    <DeleteIcon />
                  </IconButton>
                </Tooltip>
              </Box>
            )
          }
        />

        <CardContent sx={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          {/* Email metadata */}
          <Paper variant="outlined" sx={{ p: 2, mb: 2 }}>
            <List dense>
              <ListItem disablePadding>
                <ListItemIcon>
                  <PersonIcon />
                </ListItemIcon>
                <ListItemText
                  primary="From"
                  secondary={
                    <Box>
                      <Typography component="span" fontWeight="medium">
                        {email.from.name || email.from.address}
                      </Typography>
                      {email.from.name && (
                        <Typography component="span" color="text.secondary" ml={1}>
                          &lt;{email.from.address}&gt;
                        </Typography>
                      )}
                    </Box>
                  }
                />
              </ListItem>

              <ListItem disablePadding>
                <ListItemIcon>
                  <PersonIcon />
                </ListItemIcon>
                <ListItemText
                  primary="To"
                  secondary={
                    <Box>
                      {email.to.map((recipient, index) => (
                        <Typography key={index} component="span">
                          {recipient.name || recipient.address}
                          {recipient.name && (
                            <Typography component="span" color="text.secondary" ml={1}>
                              &lt;{recipient.address}&gt;
                            </Typography>
                          )}
                          {index < email.to.length - 1 && ', '}
                        </Typography>
                      ))}
                    </Box>
                  }
                />
              </ListItem>

              {email.cc && email.cc.length > 0 && (
                <ListItem disablePadding>
                  <ListItemIcon>
                    <PersonIcon />
                  </ListItemIcon>
                  <ListItemText
                    primary="CC"
                    secondary={email.cc.map(cc => cc.name || cc.address).join(', ')}
                  />
                </ListItem>
              )}

              <ListItem disablePadding>
                <ListItemIcon>
                  <ScheduleIcon />
                </ListItemIcon>
                <ListItemText
                  primary="Received"
                  secondary={
                    <Tooltip title={format(email.receivedAt, 'PPPPpppp')}>
                      <span>
                        {formatDistanceToNow(email.receivedAt, { addSuffix: true })}
                      </span>
                    </Tooltip>
                  }
                />
              </ListItem>

              {email.attachments.length > 0 && (
                <ListItem disablePadding>
                  <ListItemIcon>
                    <AttachmentIcon />
                  </ListItemIcon>
                  <ListItemText
                    primary={`${email.attachments.length} attachment(s)`}
                    secondary={
                      <Box sx={{ mt: 1 }}>
                        {email.attachments.map((attachment, index) => (
                          <Box key={index} sx={{ display: 'flex', alignItems: 'center', gap: 1, mb: 0.5 }}>
                            <Link
                              component="button"
                              onClick={() => setShowAttachment(attachment)}
                              variant="body2"
                            >
                              {attachment.filename}
                            </Link>
                            <Typography variant="caption" color="text.secondary">
                              ({(attachment.size / 1024).toFixed(1)} KB)
                            </Typography>
                            <IconButton
                              size="small"
                              onClick={() => handleDownloadAttachment(attachment)}
                              title="Download"
                            >
                              <DownloadIcon fontSize="small" />
                            </IconButton>
                          </Box>
                        ))}
                      </Box>
                    }
                  />
                </ListItem>
              )}
            </List>
          </Paper>

          {/* Content tabs */}
          <Box sx={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
            <Tabs value={currentTab} onChange={handleTabChange}>
              {email.htmlBody && <Tab label="HTML" />}
              {email.textBody && <Tab label="Text" />}
              <Tab label="Headers" icon={<CodeIcon />} iconPosition="start" />
            </Tabs>

            <Box sx={{ flex: 1, overflow: 'auto' }}>
              {email.htmlBody && (
                <TabPanel value={currentTab} index={0}>
                  <Box
                    component="iframe"
                    srcDoc={email.htmlBody}
                    sx={{
                      width: '100%',
                      height: '400px',
                      border: 'none',
                      borderRadius: 1,
                      bgcolor: 'background.paper',
                    }}
                    sandbox="allow-same-origin"
                    title="Email HTML Content"
                  />
                </TabPanel>
              )}

              {email.textBody && (
                <TabPanel value={currentTab} index={email.htmlBody ? 1 : 0}>
                  <Paper variant="outlined" sx={{ p: 2, backgroundColor: 'grey.50' }}>
                    <Typography
                      component="pre"
                      variant="body2"
                      sx={{
                        whiteSpace: 'pre-wrap',
                        wordBreak: 'break-word',
                        fontFamily: 'monospace',
                        margin: 0,
                      }}
                    >
                      {email.textBody}
                    </Typography>
                  </Paper>
                </TabPanel>
              )}

              <TabPanel value={currentTab} index={(email.htmlBody ? 1 : 0) + (email.textBody ? 1 : 0)}>
                <Paper variant="outlined" sx={{ p: 2 }}>
                  <Box sx={{ mb: 2, display: 'flex', gap: 1 }}>
                    <Button
                      startIcon={<ViewIcon />}
                      onClick={() => setShowRawEmail(true)}
                      variant="outlined"
                      size="small"
                    >
                      View Raw Email
                    </Button>
                  </Box>
                  
                  <List dense>
                    {Object.entries(email.headers as Record<string, string>).map(([key, value]) => (
                      <ListItem key={key} divider>
                        <ListItemText
                          primary={
                            <Typography variant="body2" fontWeight="medium" color="primary">
                              {key}
                            </Typography>
                          }
                          secondary={
                            <Typography
                              variant="body2"
                              sx={{
                                wordBreak: 'break-all',
                                fontFamily: 'monospace',
                                fontSize: '0.75rem',
                              }}
                            >
                              {String(value)}
                            </Typography>
                          }
                        />
                      </ListItem>
                    ))}
                  </List>
                </Paper>
              </TabPanel>
            </Box>
          </Box>

          {/* Spam analysis */}
          {email.spamDetails && (
            <Box sx={{ mt: 2 }}>
              <Alert 
                severity={email.spamScore && email.spamScore > 5 ? 'warning' : 'info'}
                icon={<SecurityIcon />}
              >
                <Typography variant="subtitle2" gutterBottom>
                  Spam Analysis Results
                </Typography>
                <Typography variant="body2">
                  Score: {email.spamScore?.toFixed(1)} / 10
                </Typography>
                {/* Add more spam detail rendering as needed */}
              </Alert>
            </Box>
          )}
        </CardContent>
      </Card>

      {/* Raw email dialog */}
      <Dialog
        open={showRawEmail}
        onClose={() => setShowRawEmail(false)}
        maxWidth="md"
        fullWidth
      >
        <DialogTitle>Raw Email Source</DialogTitle>
        <DialogContent>
          <Paper variant="outlined" sx={{ p: 2, bgcolor: 'grey.50' }}>
            <Typography
              component="pre"
              variant="body2"
              sx={{
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
                fontFamily: 'monospace',
                fontSize: '0.75rem',
                margin: 0,
                maxHeight: 400,
                overflow: 'auto',
              }}
            >
              {/* Raw email source would be provided by API */}
              {JSON.stringify(email, null, 2)}
            </Typography>
          </Paper>
        </DialogContent>
      </Dialog>

      {/* Attachment viewer dialog */}
      <Dialog
        open={!!showAttachment}
        onClose={() => setShowAttachment(null)}
        maxWidth="md"
        fullWidth
      >
        {showAttachment && (
          <>
            <DialogTitle>
              {showAttachment.filename}
              <IconButton
                onClick={() => setShowAttachment(null)}
                sx={{ position: 'absolute', right: 8, top: 8 }}
              >
                <CloseIcon />
              </IconButton>
            </DialogTitle>
            <DialogContent>
              {showAttachment.contentType.startsWith('image/') ? (
                <Box sx={{ textAlign: 'center', p: 2 }}>
                  <img
                    src={showAttachment.url}
                    alt={showAttachment.filename}
                    style={{ maxWidth: '100%', maxHeight: '400px' }}
                  />
                </Box>
              ) : (
                <Alert severity="info">
                  Preview not available for this file type.{' '}
                  <Button onClick={() => handleDownloadAttachment(showAttachment)}>
                    Download to view
                  </Button>
                </Alert>
              )}
            </DialogContent>
          </>
        )}
      </Dialog>
    </>
  );
};

export default EmailViewer;