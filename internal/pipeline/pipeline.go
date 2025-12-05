package pipeline

import "fmt"

// Step represents a discrete unit of work executed within a pipeline.
// Implementations should mutate the provided context and return an error
// when the pipeline should halt.
type Step[C any] interface {
	Name() string
	Run(ctx C) error
}

// FuncStep allows registering plain functions as pipeline steps.
type FuncStep[C any] struct {
	name string
	fn   func(C) error
}

// Name returns the human readable identifier for the step.
func (s FuncStep[C]) Name() string { return s.name }

// Run executes the wrapped function.
func (s FuncStep[C]) Run(ctx C) error { return s.fn(ctx) }

// NewFuncStep constructs a pipeline step from the provided function.
func NewFuncStep[C any](name string, fn func(C) error) FuncStep[C] {
	return FuncStep[C]{name: name, fn: fn}
}

// Pipeline orchestrates the sequential execution of registered steps.
type Pipeline[C any] struct {
	steps []Step[C]
}

// New returns an empty pipeline.
func New[C any]() *Pipeline[C] { return &Pipeline[C]{} }

// Add appends a step to the pipeline.
func (p *Pipeline[C]) Add(step Step[C]) {
	p.steps = append(p.steps, step)
}

// Execute runs all steps in order, passing the shared context to each.
// An error returned by any step stops execution and is wrapped with the
// failing step's name for easier debugging.
func (p *Pipeline[C]) Execute(ctx C) error {
	for _, step := range p.steps {
		if err := step.Run(ctx); err != nil {
			return fmt.Errorf("%s step failed: %w", step.Name(), err)
		}
	}
	return nil
}
