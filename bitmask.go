package ssh1

// bitmask represents a bitmask.
type bitmask uint32

func newBitmask(flags ...int) *bitmask {
	var mask = new(bitmask)
	for _, f := range flags {
		mask.addFlag(f)
	}

	return mask
}

func (m *bitmask) hasFlag(f int) bool { return *m&(1<<f) != 0 }

func (m *bitmask) addFlag(f int) { *m |= 1 << f }

func (m *bitmask) removeFlag(f int) { *m &= 1 << f }

func (m *bitmask) toggleFlag(f int) { *m ^= 1 << f }
