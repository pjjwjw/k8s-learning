package heap

type Interface interface { // 认为h是个栈
	Len() int
	Less(i, j int) bool
	Swap(i, j int)
	Push(x interface{})
	Pop() interface{}
}

func Init(h Interface) {
	for i := h.Len()/2 - 1; i >= 0; i-- {
		down(h, i, h.Len())
	}
}

func Push(h Interface, x interface{}) {
	h.Push(x)
	up(h, h.Len()-1)
}

func Pop(h Interface) interface{} {
	n := h.Len() - 1
	h.Swap(0, n)
	down(h, 0, n)
	return h.Pop()
}

func down(h Interface, i, n int) {
	for i < n {
		j := i
		l := 2*i + 1
		r := 2*i + 2
		if l < n && h.Less(l, j) {
			j = l
		}
		if r < n && h.Less(r, j) {
			j = r
		}
		if i == j {
			break
		}
		h.Swap(i, j)
		i = j
	}
}

func up(h Interface, i int) {
	for i >= 0 {
		p := (i - 1) / 2
		if h.Less(p, i) {
			break
		}
		h.Swap(i, p)
		i = p
	}
}

/*
0
1   2
3 4 5 6
len = 7
l = 2*i+1
r = 2*i+2
p = (i-1)/2
leaf = n/2-1
*/
