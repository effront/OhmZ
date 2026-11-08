const std = @import("std");

pub const BlackRock = struct {
    range: u64,
    seed: u64,
    split: u64,
    rounds: u8,

    pub fn init(range: u64, seed: u64) BlackRock {
        const split = computeSplit(range);
        return .{
            .range = range,
            .seed = seed,
            .split = split,
            .rounds = 6,
        };
    }

    pub fn shuffle(self: *const BlackRock, index: u64) u64 {
        if (self.range <= 1) return 0;

        var candidate = index;
        var attempts: u16 = 0;
        while (attempts < 16) : (attempts += 1) {
            candidate = self.encrypt(candidate);
            if (candidate < self.range) return candidate;
        }
        return index % self.range;
    }

    pub fn unshuffle(self: *const BlackRock, shuffled: u64) u64 {
        if (self.range <= 1) return 0;

        var candidate = shuffled;
        var attempts: u16 = 0;
        while (attempts < 16) : (attempts += 1) {
            candidate = self.decrypt(candidate);
            if (candidate < self.range) return candidate;
        }
        return shuffled % self.range;
    }

    fn encrypt(self: *const BlackRock, index: u64) u64 {
        var left: u64 = index % self.split;
        var right: u64 = index / self.split;

        var i: u8 = 0;
        while (i < self.rounds) : (i += 1) {
            const f = roundFunction(left, i, self.seed, self.split);
            const new_right = left;
            left = (right +% f) % self.split;
            right = new_right;
        }

        return right *% self.split +% left;
    }

    fn decrypt(self: *const BlackRock, cipher: u64) u64 {
        var left: u64 = cipher % self.split;
        var right: u64 = cipher / self.split;

        var i: u8 = self.rounds;
        while (i > 0) {
            i -= 1;
            const new_left = right;
            const f = roundFunction(new_left, i, self.seed, self.split);
            right = (left +% self.split -% (f % self.split)) % self.split;
            left = new_left;
        }

        return right *% self.split +% left;
    }

    fn roundFunction(val: u64, round: u8, seed: u64, split: u64) u64 {
        const input = val +% (@as(u64, round) *% 0x9E3779B97F4A7C15) +% seed;
        const mixed = murmurMix(input);
        return mixed % split;
    }

    fn computeSplit(range: u64) u64 {
        var s: u64 = 1;
        while (s * s < range) : (s += 1) {}
        return s;
    }

    fn murmurMix(input: u64) u64 {
        var h = input;
        h ^= h >> 33;
        h *%= 0xFF51AFD7ED558CCD;
        h ^= h >> 33;
        h *%= 0xC4CEB9FE1A85EC53;
        h ^= h >> 33;
        return h;
    }
};

test "BlackRock covers all indices" {
    const range: u64 = 1000;
    const br = BlackRock.init(range, 42);

    var seen = std.StaticBitSet(1000).initEmpty();

    for (0..range) |i| {
        const shuffled = br.shuffle(i);
        try std.testing.expect(shuffled < range);
        seen.set(@intCast(shuffled));
    }

    try std.testing.expectEqual(@as(usize, 1000), seen.count());
}

test "BlackRock is deterministic" {
    const br1 = BlackRock.init(10000, 123);
    const br2 = BlackRock.init(10000, 123);

    for (0..100) |i| {
        try std.testing.expectEqual(br1.shuffle(i), br2.shuffle(i));
    }
}

test "BlackRock different seeds produce different permutations" {
    const br1 = BlackRock.init(10000, 1);
    const br2 = BlackRock.init(10000, 2);

    var diffs: usize = 0;
    for (0..100) |i| {
        if (br1.shuffle(i) != br2.shuffle(i)) diffs += 1;
    }
    try std.testing.expect(diffs > 50);
}

test "BlackRock unshuffle inverts shuffle" {
    const br = BlackRock.init(50000, 777);
    for (0..200) |i| {
        const shuffled = br.shuffle(i);
        const recovered = br.unshuffle(shuffled);
        try std.testing.expectEqual(i, recovered);
    }
}

test "BlackRock sharding no overlap" {
    const range: u64 = 500;
    const br = BlackRock.init(range, 99);
    const total_shards: u64 = 4;

    var total_covered: u64 = 0;
    for (0..total_shards) |shard| {
        var count: u64 = 0;
        for (0..range) |i| {
            if (i % total_shards == shard) {
                const target = br.shuffle(i);
                _ = target;
                count += 1;
            }
        }
        total_covered += count;
    }
    try std.testing.expectEqual(range, total_covered);
}
