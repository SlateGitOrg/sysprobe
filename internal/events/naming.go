package events

// NameProcesses gives every sample of a process the same comm. Kernel
// histogram keys carry the name of the thread that created them, which may
// be a worker thread or, between fork and exec, the parent. The
// authoritative name comes from known (the kernel's proc_comm map: set on
// exec and whenever the group leader creates a key); without it, the most
// frequent per-key comm wins, ties broken lexicographically, so the choice
// is deterministic for a given snapshot.
func NameProcesses(samples []SyscallSample, known map[uint32]string) {
	votes := map[uint32]map[string]int{}
	for i := range samples {
		s := &samples[i]
		if _, ok := known[s.TGID]; ok || s.Comm == "" {
			continue
		}
		v := votes[s.TGID]
		if v == nil {
			v = map[string]int{}
			votes[s.TGID] = v
		}
		v[s.Comm]++
	}
	chosen := make(map[uint32]string, len(votes))
	for tgid, v := range votes {
		best, bestN := "", 0
		for c, n := range v {
			if n > bestN || (n == bestN && c < best) {
				best, bestN = c, n
			}
		}
		chosen[tgid] = best
	}
	for i := range samples {
		s := &samples[i]
		if c, ok := known[s.TGID]; ok && c != "" {
			s.Comm = c
		} else if c, ok := chosen[s.TGID]; ok {
			s.Comm = c
		}
	}
}
