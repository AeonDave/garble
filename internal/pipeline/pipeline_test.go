package pipeline

import (
	"errors"
	"testing"
)

func TestPipelineExecutesStepsInOrder(t *testing.T) {
	var ordered []string
	ctx := &struct{}{}

	pipe := New[*struct{}]()
	pipe.Add(NewFuncStep("first", func(_ *struct{}) error {
		ordered = append(ordered, "first")
		return nil
	}))
	pipe.Add(NewFuncStep("second", func(_ *struct{}) error {
		ordered = append(ordered, "second")
		return nil
	}))

	if err := pipe.Execute(ctx); err != nil {
		t.Fatalf("pipeline execute returned error: %v", err)
	}

	if len(ordered) != 2 || ordered[0] != "first" || ordered[1] != "second" {
		t.Fatalf("unexpected execution order: %v", ordered)
	}
}

func TestPipelineWrapsStepErrors(t *testing.T) {
	ctx := &struct{}{}
	pipe := New[*struct{}]()
	errBoom := errors.New("boom")
	pipe.Add(NewFuncStep("failing", func(_ *struct{}) error {
		return errBoom
	}))

	err := pipe.Execute(ctx)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	if !errors.Is(err, errBoom) {
		t.Fatalf("expected wrapped error to contain original message, got %v", err)
	}
	if got, want := err.Error(), "failing step failed"; len(got) < len(want) || got[:len(want)] != want {
		t.Fatalf("error should include step name, got %q", got)
	}
}
