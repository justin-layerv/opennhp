package core

import "testing"

var benchmarkKDFHashTypes = []struct {
	name     string
	hashType HashTypeEnum
}{
	{name: "BLAKE2s", hashType: HASH_BLAKE2S},
	{name: "SHA256", hashType: HASH_SHA256},
}

func BenchmarkKeyGen1(b *testing.B) {
	benchmarkKDF(b, "KeyGen1", func(b *testing.B, noise *NoiseFactory, key, input []byte) {
		var dst0 [HashSize]byte

		b.ReportAllocs()
		for b.Loop() {
			noise.KeyGen1(&dst0, key, input)
		}
	})
}

func BenchmarkKeyGen2(b *testing.B) {
	benchmarkKDF(b, "KeyGen2", func(b *testing.B, noise *NoiseFactory, key, input []byte) {
		var dst0, dst1 [HashSize]byte

		b.ReportAllocs()
		for b.Loop() {
			noise.KeyGen2(&dst0, &dst1, key, input)
		}
	})
}

func BenchmarkKeyGen3(b *testing.B) {
	benchmarkKDF(b, "KeyGen3", func(b *testing.B, noise *NoiseFactory, key, input []byte) {
		var dst0, dst1, dst2 [HashSize]byte

		b.ReportAllocs()
		for b.Loop() {
			noise.KeyGen3(&dst0, &dst1, &dst2, key, input)
		}
	})
}

func BenchmarkMixKey(b *testing.B) {
	benchmarkKDF(b, "MixKey", func(b *testing.B, noise *NoiseFactory, key, input []byte) {
		var dst [SymmetricKeySize]byte

		b.ReportAllocs()
		for b.Loop() {
			noise.MixKey(&dst, key, input)
		}
	})
}

func benchmarkKDF(b *testing.B, name string, bench func(*testing.B, *NoiseFactory, []byte, []byte)) {
	b.Helper()

	for _, tt := range benchmarkKDFHashTypes {
		b.Run(tt.name, func(b *testing.B) {
			noise := &NoiseFactory{HashType: tt.hashType}
			key := []byte("benchmark key for " + name + " allocation tracking")
			input := []byte("benchmark input for " + name + " allocation tracking")

			bench(b, noise, key, input)
		})
	}
}
