package ssh1

import "hash/crc32"

// Return a 32-bit CRC of the data.
func ssh1CRC32(data []byte, len int) uint32 {
	var crc32val uint32
	for i := 0; i < len; i++ {
		crc32val = crc32.IEEETable[(crc32val^uint32(data[i]))&0xff] ^ (crc32val >> 8)
	}
	return crc32val
}
