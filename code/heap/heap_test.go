package heap

import (
	"testing"
)

type intHeap []int

var _ Interface = &intHeap{}

func (h intHeap) Len() int            { return len(h) }
func (h intHeap) Less(i, j int) bool  { return h[i] < h[j] }
func (h intHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *intHeap) Push(x interface{}) { *h = append(*h, x.(int)) }

func (h *intHeap) Pop() interface{} {
	old := *h
	n := len(old)
	rt := old[n-1]
	*h = old[0 : n-1]
	return rt
}

func (h intHeap) verify(t *testing.T, i int) {
	l := 2*i + 1
	r := 2*i + 2
	n := h.Len()
	if l < n {
		if h.Less(l, i) {
			t.Errorf("heap invalid %d", i)
			return
		}
		h.verify(t, l)
	}
	if r < n {
		if h.Less(r, i) {
			t.Errorf("heap invalid %d", i)
			return
		}
		h.verify(t, r)
	}
}

func TestHeap(t *testing.T) {
	h := &intHeap{10, 9, 8, 7, 6, 5, 4, 3, 2, 1}
	Init(h)
	t.Logf("heap after init: %v", h)
	h.verify(t, 0)
	for i := 11; i <= 15; i++ {
		Push(h, i)
	}
	t.Logf("heap after push: %v", h)
	h.verify(t, 0)
	for i := 0; i < 10; i++ {
		Pop(h)
	}
	t.Logf("heap after pop: %v", h)
	h.verify(t, 0)
}
