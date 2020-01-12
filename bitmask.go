package ssh1

// Bitmask represents a bitmask.
type Bitmask uint32

func (m Bitmask) hasFlag(f int) bool { return m&(1<<f) != 0 }

func (m *Bitmask) addFlag(f int) { *m |= 1 << f }

func (m *Bitmask) removeFlag(f int) { *m &= 1 << f }

func (m *Bitmask) toggleFlag(f int) { *m ^= 1 << f }
