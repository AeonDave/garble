package pipeline

import "testing"

func BenchmarkPipeline(b *testing.B) {
	ctx := &struct{}{}
	pipe := New[*struct{}]()
	pipe.Add(NewFuncStep("step", func(_ *struct{}) error { return nil }))

	for i := 0; i < b.N; i++ {
		if err := pipe.Execute(ctx); err != nil {
			b.Fatalf("execution failed: %v", err)
		}
	}
}
