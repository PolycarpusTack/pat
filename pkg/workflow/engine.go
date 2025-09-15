package workflow

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/alexandria/pat-plugin/pkg/email"
	"github.com/alexandria/pat-plugin/pkg/events"
)

// WorkflowEngine manages workflow execution and lifecycle
type WorkflowEngine struct {
	workflows      map[string]*Workflow
	executions     map[string]*WorkflowExecution
	stepExecutors  map[string]StepExecutor
	eventBus       events.EventBus
	repository     WorkflowRepository
	scheduler      *WorkflowScheduler
	metrics        WorkflowMetrics
	mu             sync.RWMutex
	executionMu    sync.RWMutex
	maxConcurrency int
	executionPool  chan struct{}
}

// Workflow represents a workflow definition
type Workflow struct {
	ID           string                 `json:"id"`
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Version      int                    `json:"version"`
	TriggerRules []TriggerRule          `json:"trigger_rules"`
	Steps        []WorkflowStep         `json:"steps"`
	Settings     map[string]interface{} `json:"settings"`
	IsActive     bool                   `json:"is_active"`
	CreatedBy    string                 `json:"created_by"`
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	Tags         []string               `json:"tags"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// WorkflowStep represents a single step in a workflow
type WorkflowStep struct {
	ID            string                 `json:"id"`
	Name          string                 `json:"name"`
	Type          string                 `json:"type"`
	Config        map[string]interface{} `json:"config"`
	Conditions    []Condition            `json:"conditions"`
	OnSuccess     string                 `json:"on_success"`     // next step ID on success
	OnError       string                 `json:"on_error"`       // next step ID on error
	OnTimeout     string                 `json:"on_timeout"`     // next step ID on timeout
	Timeout       time.Duration          `json:"timeout"`
	RetryConfig   *RetryConfig           `json:"retry_config"`
	Parallel      bool                   `json:"parallel"`       // can run in parallel with other steps
	Dependencies  []string               `json:"dependencies"`   // step IDs this step depends on
}

// TriggerRule defines when a workflow should be triggered
type TriggerRule struct {
	Type       string                 `json:"type"`        // email_received, email_matched, schedule, manual
	Conditions []Condition            `json:"conditions"`  // conditions that must be met
	Config     map[string]interface{} `json:"config"`      // trigger-specific configuration
}

// Condition represents a condition for workflow execution
type Condition struct {
	Field    string      `json:"field"`    // email field to check
	Operator string      `json:"operator"` // equals, contains, matches, greater_than, etc.
	Value    interface{} `json:"value"`    // value to compare against
	Negate   bool        `json:"negate"`   // negate the condition
}

// WorkflowExecution represents a running workflow instance
type WorkflowExecution struct {
	ID               string                 `json:"id"`
	WorkflowID       string                 `json:"workflow_id"`
	TriggerType      string                 `json:"trigger_type"`
	TriggerData      map[string]interface{} `json:"trigger_data"`
	Status           ExecutionStatus        `json:"status"`
	CurrentStep      string                 `json:"current_step"`
	StepExecutions   []*StepExecution       `json:"step_executions"`
	Context          ExecutionContext       `json:"context"`
	StartedAt        time.Time              `json:"started_at"`
	CompletedAt      *time.Time             `json:"completed_at"`
	Error            string                 `json:"error"`
	ResultData       map[string]interface{} `json:"result_data"`
	ParentExecution  string                 `json:"parent_execution"`  // for sub-workflows
	ChildExecutions  []string               `json:"child_executions"`
}

// StepExecution represents a step execution within a workflow
type StepExecution struct {
	ID            string                 `json:"id"`
	StepID        string                 `json:"step_id"`
	Status        ExecutionStatus        `json:"status"`
	Input         map[string]interface{} `json:"input"`
	Output        map[string]interface{} `json:"output"`
	Error         string                 `json:"error"`
	StartedAt     time.Time              `json:"started_at"`
	CompletedAt   *time.Time             `json:"completed_at"`
	RetryCount    int                    `json:"retry_count"`
	ExecutionTime time.Duration          `json:"execution_time"`
}

// ExecutionContext holds workflow execution context
type ExecutionContext struct {
	Email       *email.Email           `json:"email"`
	Variables   map[string]interface{} `json:"variables"`
	UserID      string                 `json:"user_id"`
	TenantID    string                 `json:"tenant_id"`
	SessionID   string                 `json:"session_id"`
	TraceID     string                 `json:"trace_id"`
}

// ExecutionStatus represents workflow/step execution status
type ExecutionStatus string

const (
	StatusPending   ExecutionStatus = "pending"
	StatusRunning   ExecutionStatus = "running"
	StatusCompleted ExecutionStatus = "completed"
	StatusFailed    ExecutionStatus = "failed"
	StatusCanceled  ExecutionStatus = "canceled"
	StatusSkipped   ExecutionStatus = "skipped"
	StatusTimeout   ExecutionStatus = "timeout"
)

// RetryConfig defines retry behavior for steps
type RetryConfig struct {
	MaxRetries   int           `json:"max_retries"`
	RetryDelay   time.Duration `json:"retry_delay"`
	BackoffType  string        `json:"backoff_type"`  // fixed, exponential, linear
	MaxRetryTime time.Duration `json:"max_retry_time"`
}

// StepExecutor interface for step execution
type StepExecutor interface {
	Execute(ctx context.Context, step *WorkflowStep, execCtx *ExecutionContext) (*StepExecutionResult, error)
	GetType() string
	Validate(step *WorkflowStep) error
}

// StepExecutionResult represents the result of step execution
type StepExecutionResult struct {
	Status      ExecutionStatus        `json:"status"`
	Output      map[string]interface{} `json:"output"`
	Error       error                  `json:"error"`
	NextStepID  string                 `json:"next_step_id"`
	ShouldRetry bool                   `json:"should_retry"`
	Delay       time.Duration          `json:"delay"`
}

// NewWorkflowEngine creates a new workflow engine
func NewWorkflowEngine(
	eventBus events.EventBus,
	repository WorkflowRepository,
	metrics WorkflowMetrics,
	maxConcurrency int,
) *WorkflowEngine {
	if maxConcurrency <= 0 {
		maxConcurrency = 100
	}

	engine := &WorkflowEngine{
		workflows:      make(map[string]*Workflow),
		executions:     make(map[string]*WorkflowExecution),
		stepExecutors:  make(map[string]StepExecutor),
		eventBus:       eventBus,
		repository:     repository,
		metrics:        metrics,
		maxConcurrency: maxConcurrency,
		executionPool:  make(chan struct{}, maxConcurrency),
		scheduler:      NewWorkflowScheduler(),
	}

	// Register built-in step executors
	engine.registerBuiltinExecutors()

	return engine
}

// Start starts the workflow engine
func (we *WorkflowEngine) Start(ctx context.Context) error {
	// Load workflows from repository
	if err := we.loadWorkflows(ctx); err != nil {
		return fmt.Errorf("failed to load workflows: %w", err)
	}

	// Start scheduler
	if err := we.scheduler.Start(ctx); err != nil {
		return fmt.Errorf("failed to start scheduler: %w", err)
	}

	// Subscribe to events
	we.subscribeToEvents(ctx)

	return nil
}

// Stop stops the workflow engine
func (we *WorkflowEngine) Stop(ctx context.Context) error {
	we.scheduler.Stop()
	return nil
}

// CreateWorkflow creates a new workflow
func (we *WorkflowEngine) CreateWorkflow(ctx context.Context, workflow *Workflow) error {
	workflow.ID = uuid.New().String()
	workflow.CreatedAt = time.Now()
	workflow.UpdatedAt = time.Now()

	// Validate workflow
	if err := we.validateWorkflow(workflow); err != nil {
		return fmt.Errorf("workflow validation failed: %w", err)
	}

	// Save to repository
	if err := we.repository.CreateWorkflow(ctx, workflow); err != nil {
		return fmt.Errorf("failed to save workflow: %w", err)
	}

	// Cache workflow
	we.mu.Lock()
	we.workflows[workflow.ID] = workflow
	we.mu.Unlock()

	// Emit event
	we.eventBus.Publish("workflow.created", map[string]interface{}{
		"workflow_id": workflow.ID,
		"name":        workflow.Name,
	})

	return nil
}

// UpdateWorkflow updates an existing workflow
func (we *WorkflowEngine) UpdateWorkflow(ctx context.Context, workflow *Workflow) error {
	workflow.UpdatedAt = time.Now()

	// Validate workflow
	if err := we.validateWorkflow(workflow); err != nil {
		return fmt.Errorf("workflow validation failed: %w", err)
	}

	// Save to repository
	if err := we.repository.UpdateWorkflow(ctx, workflow); err != nil {
		return fmt.Errorf("failed to update workflow: %w", err)
	}

	// Update cache
	we.mu.Lock()
	we.workflows[workflow.ID] = workflow
	we.mu.Unlock()

	// Emit event
	we.eventBus.Publish("workflow.updated", map[string]interface{}{
		"workflow_id": workflow.ID,
		"name":        workflow.Name,
	})

	return nil
}

// DeleteWorkflow deletes a workflow
func (we *WorkflowEngine) DeleteWorkflow(ctx context.Context, workflowID string) error {
	// Check for active executions
	we.executionMu.RLock()
	hasActiveExecutions := false
	for _, execution := range we.executions {
		if execution.WorkflowID == workflowID && 
		   (execution.Status == StatusRunning || execution.Status == StatusPending) {
			hasActiveExecutions = true
			break
		}
	}
	we.executionMu.RUnlock()

	if hasActiveExecutions {
		return fmt.Errorf("cannot delete workflow with active executions")
	}

	// Delete from repository
	if err := we.repository.DeleteWorkflow(ctx, workflowID); err != nil {
		return fmt.Errorf("failed to delete workflow: %w", err)
	}

	// Remove from cache
	we.mu.Lock()
	delete(we.workflows, workflowID)
	we.mu.Unlock()

	// Emit event
	we.eventBus.Publish("workflow.deleted", map[string]interface{}{
		"workflow_id": workflowID,
	})

	return nil
}

// ExecuteWorkflow manually executes a workflow
func (we *WorkflowEngine) ExecuteWorkflow(ctx context.Context, workflowID string, triggerData map[string]interface{}, execCtx *ExecutionContext) (*WorkflowExecution, error) {
	we.mu.RLock()
	workflow, exists := we.workflows[workflowID]
	we.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("workflow not found: %s", workflowID)
	}

	if !workflow.IsActive {
		return nil, fmt.Errorf("workflow is not active: %s", workflowID)
	}

	return we.startExecution(ctx, workflow, "manual", triggerData, execCtx)
}

// TriggerWorkflowsForEmail triggers workflows based on email
func (we *WorkflowEngine) TriggerWorkflowsForEmail(ctx context.Context, email *email.Email) error {
	we.mu.RLock()
	workflows := make([]*Workflow, 0, len(we.workflows))
	for _, workflow := range we.workflows {
		if workflow.IsActive {
			workflows = append(workflows, workflow)
		}
	}
	we.mu.RUnlock()

	var triggeredCount int
	for _, workflow := range workflows {
		if we.shouldTriggerForEmail(workflow, email) {
			execCtx := &ExecutionContext{
				Email:     email,
				Variables: make(map[string]interface{}),
				TraceID:   uuid.New().String(),
			}

			triggerData := map[string]interface{}{
				"email_id": email.ID,
				"subject":  email.Subject,
				"from":     email.From.Address,
			}

			_, err := we.startExecution(ctx, workflow, "email_received", triggerData, execCtx)
			if err != nil {
				we.metrics.RecordWorkflowError(workflow.ID, "trigger_failed", err)
				continue
			}
			triggeredCount++
		}
	}

	we.metrics.RecordWorkflowsTrigered(triggeredCount)
	return nil
}

// startExecution starts a new workflow execution
func (we *WorkflowEngine) startExecution(ctx context.Context, workflow *Workflow, triggerType string, triggerData map[string]interface{}, execCtx *ExecutionContext) (*WorkflowExecution, error) {
	execution := &WorkflowExecution{
		ID:              uuid.New().String(),
		WorkflowID:      workflow.ID,
		TriggerType:     triggerType,
		TriggerData:     triggerData,
		Status:          StatusPending,
		StepExecutions:  make([]*StepExecution, 0),
		Context:         *execCtx,
		StartedAt:       time.Now(),
		ResultData:      make(map[string]interface{}),
		ChildExecutions: make([]string, 0),
	}

	// Save execution to repository
	if err := we.repository.CreateExecution(ctx, execution); err != nil {
		return nil, fmt.Errorf("failed to save execution: %w", err)
	}

	// Cache execution
	we.executionMu.Lock()
	we.executions[execution.ID] = execution
	we.executionMu.Unlock()

	// Start execution asynchronously
	go we.runExecution(context.Background(), execution, workflow)

	// Emit event
	we.eventBus.Publish("workflow.execution.started", map[string]interface{}{
		"execution_id": execution.ID,
		"workflow_id":  workflow.ID,
		"trigger_type": triggerType,
	})

	we.metrics.RecordExecutionStarted(workflow.ID)
	return execution, nil
}

// runExecution runs a workflow execution
func (we *WorkflowEngine) runExecution(ctx context.Context, execution *WorkflowExecution, workflow *Workflow) {
	// Acquire execution slot
	we.executionPool <- struct{}{}
	defer func() { <-we.executionPool }()

	startTime := time.Now()
	execution.Status = StatusRunning
	we.updateExecution(ctx, execution)

	// Find first step
	if len(workflow.Steps) == 0 {
		we.completeExecution(ctx, execution, StatusCompleted, "No steps to execute")
		return
	}

	// Execute steps
	err := we.executeSteps(ctx, execution, workflow, workflow.Steps[0].ID)
	
	if err != nil {
		we.completeExecution(ctx, execution, StatusFailed, err.Error())
		we.metrics.RecordExecutionCompleted(workflow.ID, StatusFailed, time.Since(startTime))
	} else {
		we.completeExecution(ctx, execution, StatusCompleted, "")
		we.metrics.RecordExecutionCompleted(workflow.ID, StatusCompleted, time.Since(startTime))
	}
}

// executeSteps executes workflow steps starting from the given step ID
func (we *WorkflowEngine) executeSteps(ctx context.Context, execution *WorkflowExecution, workflow *Workflow, currentStepID string) error {
	for currentStepID != "" {
		step := we.findStep(workflow, currentStepID)
		if step == nil {
			return fmt.Errorf("step not found: %s", currentStepID)
		}

		// Check conditions
		if !we.evaluateConditions(step.Conditions, &execution.Context) {
			// Skip this step
			currentStepID = step.OnSuccess
			continue
		}

		// Execute step
		nextStepID, err := we.executeStep(ctx, execution, step)
		if err != nil {
			return fmt.Errorf("step execution failed: %w", err)
		}

		currentStepID = nextStepID
	}

	return nil
}

// executeStep executes a single workflow step
func (we *WorkflowEngine) executeStep(ctx context.Context, execution *WorkflowExecution, step *WorkflowStep) (string, error) {
	stepExecution := &StepExecution{
		ID:        uuid.New().String(),
		StepID:    step.ID,
		Status:    StatusRunning,
		Input:     step.Config,
		StartedAt: time.Now(),
	}

	execution.StepExecutions = append(execution.StepExecutions, stepExecution)
	execution.CurrentStep = step.ID
	we.updateExecution(ctx, execution)

	// Get step executor
	executor, exists := we.stepExecutors[step.Type]
	if !exists {
		return "", fmt.Errorf("no executor found for step type: %s", step.Type)
	}

	// Execute with timeout
	execCtx, cancel := context.WithTimeout(ctx, step.Timeout)
	defer cancel()

	var result *StepExecutionResult
	var err error

	// Execute with retry logic
	for retry := 0; retry <= (step.RetryConfig.MaxRetries); retry++ {
		stepExecution.RetryCount = retry
		
		result, err = executor.Execute(execCtx, step, &execution.Context)
		
		if err == nil {
			break
		}

		if retry < step.RetryConfig.MaxRetries && (result == nil || result.ShouldRetry) {
			// Wait before retry
			delay := we.calculateRetryDelay(step.RetryConfig, retry)
			time.Sleep(delay)
			continue
		}
		
		break
	}

	// Update step execution
	stepExecution.CompletedAt = &[]time.Time{time.Now()}[0]
	stepExecution.ExecutionTime = time.Since(stepExecution.StartedAt)

	if err != nil {
		stepExecution.Status = StatusFailed
		stepExecution.Error = err.Error()
		we.metrics.RecordStepCompleted(execution.WorkflowID, step.Type, StatusFailed, stepExecution.ExecutionTime)
		return step.OnError, err
	}

	stepExecution.Status = result.Status
	stepExecution.Output = result.Output
	
	if result.Error != nil {
		stepExecution.Error = result.Error.Error()
		we.metrics.RecordStepCompleted(execution.WorkflowID, step.Type, StatusFailed, stepExecution.ExecutionTime)
		return step.OnError, result.Error
	}

	we.metrics.RecordStepCompleted(execution.WorkflowID, step.Type, StatusCompleted, stepExecution.ExecutionTime)

	// Determine next step
	nextStepID := result.NextStepID
	if nextStepID == "" {
		nextStepID = step.OnSuccess
	}

	return nextStepID, nil
}

// Helper methods

func (we *WorkflowEngine) shouldTriggerForEmail(workflow *Workflow, email *email.Email) bool {
	for _, rule := range workflow.TriggerRules {
		if rule.Type == "email_received" && we.evaluateConditions(rule.Conditions, &ExecutionContext{Email: email}) {
			return true
		}
	}
	return false
}

func (we *WorkflowEngine) evaluateConditions(conditions []Condition, execCtx *ExecutionContext) bool {
	if len(conditions) == 0 {
		return true
	}

	for _, condition := range conditions {
		if !we.evaluateCondition(condition, execCtx) {
			return false
		}
	}
	return true
}

func (we *WorkflowEngine) evaluateCondition(condition Condition, execCtx *ExecutionContext) bool {
	// Get field value based on condition.Field
	var fieldValue interface{}
	
	if execCtx.Email != nil {
		switch condition.Field {
		case "subject":
			fieldValue = execCtx.Email.Subject
		case "from":
			fieldValue = execCtx.Email.From.Address
		case "to":
			if len(execCtx.Email.To) > 0 {
				fieldValue = execCtx.Email.To[0].Address
			}
		case "body":
			fieldValue = execCtx.Email.TextBody
		case "has_attachments":
			fieldValue = len(execCtx.Email.Attachments) > 0
		}
	}

	// Evaluate condition based on operator
	result := we.compareValues(fieldValue, condition.Operator, condition.Value)
	
	if condition.Negate {
		result = !result
	}
	
	return result
}

func (we *WorkflowEngine) compareValues(fieldValue interface{}, operator string, expectedValue interface{}) bool {
	switch operator {
	case "equals":
		return fmt.Sprintf("%v", fieldValue) == fmt.Sprintf("%v", expectedValue)
	case "contains":
		fieldStr := fmt.Sprintf("%v", fieldValue)
		expectedStr := fmt.Sprintf("%v", expectedValue)
		return fmt.Sprintf(fieldStr, expectedStr)
	case "matches":
		// Regular expression matching would be implemented here
		return false
	case "greater_than":
		// Numeric comparison would be implemented here
		return false
	default:
		return false
	}
}

func (we *WorkflowEngine) findStep(workflow *Workflow, stepID string) *WorkflowStep {
	for i := range workflow.Steps {
		if workflow.Steps[i].ID == stepID {
			return &workflow.Steps[i]
		}
	}
	return nil
}

func (we *WorkflowEngine) calculateRetryDelay(retryConfig *RetryConfig, retryCount int) time.Duration {
	if retryConfig == nil {
		return time.Second
	}

	switch retryConfig.BackoffType {
	case "exponential":
		delay := retryConfig.RetryDelay * time.Duration(1<<uint(retryCount))
		if delay > retryConfig.MaxRetryTime {
			return retryConfig.MaxRetryTime
		}
		return delay
	case "linear":
		return retryConfig.RetryDelay * time.Duration(retryCount+1)
	default:
		return retryConfig.RetryDelay
	}
}

func (we *WorkflowEngine) updateExecution(ctx context.Context, execution *WorkflowExecution) {
	we.repository.UpdateExecution(ctx, execution)
}

func (we *WorkflowEngine) completeExecution(ctx context.Context, execution *WorkflowExecution, status ExecutionStatus, error string) {
	now := time.Now()
	execution.Status = status
	execution.CompletedAt = &now
	execution.Error = error
	
	we.updateExecution(ctx, execution)
	
	// Emit completion event
	we.eventBus.Publish("workflow.execution.completed", map[string]interface{}{
		"execution_id": execution.ID,
		"workflow_id":  execution.WorkflowID,
		"status":       string(status),
		"error":        error,
	})
}

func (we *WorkflowEngine) validateWorkflow(workflow *Workflow) error {
	if workflow.Name == "" {
		return fmt.Errorf("workflow name is required")
	}

	if len(workflow.Steps) == 0 {
		return fmt.Errorf("workflow must have at least one step")
	}

	// Validate steps
	stepIDs := make(map[string]bool)
	for _, step := range workflow.Steps {
		if step.ID == "" {
			return fmt.Errorf("step ID is required")
		}
		if stepIDs[step.ID] {
			return fmt.Errorf("duplicate step ID: %s", step.ID)
		}
		stepIDs[step.ID] = true

		if step.Type == "" {
			return fmt.Errorf("step type is required for step: %s", step.ID)
		}

		// Validate step executor exists
		if _, exists := we.stepExecutors[step.Type]; !exists {
			return fmt.Errorf("unknown step type: %s", step.Type)
		}
	}

	return nil
}

func (we *WorkflowEngine) loadWorkflows(ctx context.Context) error {
	workflows, err := we.repository.ListWorkflows(ctx)
	if err != nil {
		return err
	}

	we.mu.Lock()
	defer we.mu.Unlock()
	
	for _, workflow := range workflows {
		we.workflows[workflow.ID] = workflow
	}

	return nil
}

func (we *WorkflowEngine) subscribeToEvents(ctx context.Context) {
	// Subscribe to email events
	we.eventBus.Subscribe("email.received", func(data map[string]interface{}) {
		if emailData, ok := data["email"].(*email.Email); ok {
			we.TriggerWorkflowsForEmail(ctx, emailData)
		}
	})
}

func (we *WorkflowEngine) registerBuiltinExecutors() {
	// Register built-in step executors
	we.RegisterStepExecutor(&EmailFilterExecutor{})
	we.RegisterStepExecutor(&EmailForwardExecutor{})
	we.RegisterStepExecutor(&NotificationExecutor{})
	we.RegisterStepExecutor(&WebhookExecutor{})
	we.RegisterStepExecutor(&DelayExecutor{})
	we.RegisterStepExecutor(&ConditionalExecutor{})
}

// RegisterStepExecutor registers a step executor
func (we *WorkflowEngine) RegisterStepExecutor(executor StepExecutor) {
	we.stepExecutors[executor.GetType()] = executor
}

// GetWorkflow returns a workflow by ID
func (we *WorkflowEngine) GetWorkflow(workflowID string) (*Workflow, bool) {
	we.mu.RLock()
	defer we.mu.RUnlock()
	workflow, exists := we.workflows[workflowID]
	return workflow, exists
}

// ListWorkflows returns all workflows
func (we *WorkflowEngine) ListWorkflows() []*Workflow {
	we.mu.RLock()
	defer we.mu.RUnlock()
	
	workflows := make([]*Workflow, 0, len(we.workflows))
	for _, workflow := range we.workflows {
		workflows = append(workflows, workflow)
	}
	
	return workflows
}

// GetExecution returns an execution by ID
func (we *WorkflowEngine) GetExecution(executionID string) (*WorkflowExecution, bool) {
	we.executionMu.RLock()
	defer we.executionMu.RUnlock()
	execution, exists := we.executions[executionID]
	return execution, exists
}

// CancelExecution cancels a running execution
func (we *WorkflowEngine) CancelExecution(ctx context.Context, executionID string) error {
	we.executionMu.Lock()
	execution, exists := we.executions[executionID]
	we.executionMu.Unlock()
	
	if !exists {
		return fmt.Errorf("execution not found: %s", executionID)
	}
	
	if execution.Status != StatusRunning && execution.Status != StatusPending {
		return fmt.Errorf("execution is not running: %s", executionID)
	}
	
	we.completeExecution(ctx, execution, StatusCanceled, "Execution canceled by user")
	return nil
}