const std = @import("std");

/// The width of the permutation a in bits.
///
/// The a is organized as an array of 5x5 lanes, each of length w ∈ {1, 2, 4, 8, 16, 32, 64}.
const PLEN: usize = 25;

/// Determines the number of rounds for the KECCAK-f permutation based on the bit width of the permutation.
///
/// The number of rounds `n` is derived from the bit width `w` of the state array, which is split into 25 lanes (5x5 grid).
/// The formula used to calculate the number of rounds is:
/// `n = 12 + 2l`
/// where `2^l = w`, and `w` is the bit width of each lane in the permutation.
///
/// The bit width `w` depends on the size of the type `T` used for the state elements (lanes), typically `u8`, `u16`, `u32`, or `u64`.
/// The function returns the corresponding number of rounds based on the type:
///
/// - 18 rounds for a 200-bit permutation (`T = u8`, where each lane is 8 bits and `w = 200`),
/// - 20 rounds for a 400-bit permutation (`T = u16`, where each lane is 16 bits and `w = 400`),
/// - 22 rounds for a 800-bit permutation (`T = u32`, where each lane is 32 bits and `w = 800`),
/// - 24 rounds for a 1600-bit permutation (`T = u64`, where each lane is 64 bits and `w = 1600`).
///
/// # Parameters:
/// - `T`: The type representing the bit width of each lane in the state array (usually `u8`, `u16`, `u32`, or `u64`).
///
/// # Returns:
/// - The number of rounds corresponding to the bit width `w` of the state array.
///
/// # Rationale:
/// The number of rounds increases with the bit width to provide stronger security guarantees for larger permutations.
/// This function ensures the appropriate number of rounds is selected based on the size of each lane (and thus the total bit width).
fn KECCAK_F_ROUND_COUNT(comptime T: type) usize {
    return switch (T) {
        u8 => 18,
        u16 => 20,
        u32 => 22,
        u64 => 24,
        // This case should never occur because only certain types are supported.
        else => unreachable,
    };
}

/// Rotation offsets for the ρ (rho) step in KECCAK-p.
///
/// The ρ step rotates each lane of the state array by a specific number of bits.
/// The rotation offset for each lane is determined by its position in the 5x5 grid of lanes.
/// This array defines the rotation amounts for each of the 24 lanes, indexed by their position.
/// The first lane at index 0 (A[0, 0]) does not get rotated.
///
/// # Example (Bit Rotations):
/// - Lane A[1, 0] is rotated by 1 bit.
/// - Lane A[2, 0] is rotated by 3 bits.
/// - Lane A[3, 0] is rotated by 6 bits.
/// - And so on, following the predefined pattern.
///
/// These values are applied during the ρ step of the KECCAK-p permutation.
const RHO = [_]u32{
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
};

/// Permutation indices for the π (pi) step in KECCAK-p.
///
/// The π step permutes (reorders) the lanes of the state array.
/// This array defines the new position for each lane in the 5x5 grid after the π step.
/// Each lane A[x, y] is moved to position A'[y, 2x + 3y], where (x, y) is the current position.
///
/// # Example (Lane Movement):
/// - Lane at position A[1, 0] moves to A[0, 2*1 + 3*0] = A[0, 2].
/// - Lane at position A[2, 0] moves to A[0, 2*2 + 3*0] = A[0, 4].
/// - And so on, with all lanes rearranged in a deterministic way.
///
/// These values are used during the π step to shuffle the lanes in the KECCAK-p permutation.
const PI = [_]usize{
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
};

/// For each round of a KECCAK-p permutation, round constant is a lane value determined by the round index.
///
/// The round constant is the second input to the ι step mapping.
const RC = [_]u64{
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
};

/// Performs the KECCAK-p permutation on the given state array `a` over a specified number of rounds.
///
/// The KECCAK-p permutation is a reduced version of the KECCAK-f permutation, which is central to hash functions
/// like SHA-3. KECCAK-p operates on a 5x5 matrix of bit lanes (represented here as a linear array) using a series
/// of transformations known as the θ, ρ, π, χ, and ι steps.
///
/// # Parameters:
/// - `T`: The type of each lane in the permutation. This is typically a u8, u16, u32, or u64.
/// - `a`: A pointer to the state array (5x5 matrix flattened into a linear array of length `PLEN`).
/// - `round_count`: The number of rounds to perform in the KECCAK-p permutation.
/// - The function returns an error if `round_count` exceeds the number of rounds defined for the given type `T`.
///
/// # Preconditions:
/// - The permutation width `w = 25 * size_of(T)` must be one of the standard widths used in KECCAK (e.g., 1600 bits).
/// - `a` must point to an array of size `PLEN` (25 elements).
///
/// # Error:
/// Returns `error.RoundCountTooHigh` if the specified `round_count` exceeds the maximum allowed rounds for the given lane size `T`.
///
/// # Details:
/// The function applies a series of bitwise transformations (θ, ρ, π, χ, and ι) to the state matrix `a` in each round.
/// These transformations mix the bits of the state in a manner designed to provide security properties such as diffusion and resistance to attacks.
///
/// Reference: https://keccak.team/keccak_specs_summary.html
pub fn keccakP(comptime T: type, a: *[PLEN]T, comptime round_count: usize) !void {
    // Check that the given round_count does not exceed the maximum rounds for the given lane size.
    if (round_count > KECCAK_F_ROUND_COUNT(T))
        return error.RoundCountTooHigh;

    // https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf#page=25
    // "the rounds of KECCAK-p[b, nr] match the last rounds of KECCAK-f[b]"
    //
    // For example, KECCAK-p[1600, 19] matches the last 19 rounds of KECCAK-f[1600].
    for (RC[(comptime KECCAK_F_ROUND_COUNT(T) - round_count)..comptime KECCAK_F_ROUND_COUNT(T)]) |rc| {
        var array = [_]T{0} ** 5;

        // Step 1: θ (theta) step
        //
        // θ is responsible for mixing the bits of the state horizontally (across the x-axis).
        // First, we compute the column parity for all five columns (C[x]).
        //
        // C[x] = A[x,0] xor A[x,1] xor A[x,2] xor A[x,3] xor A[x,4], for x in 0…4
        inline for (0..5) |x| {
            inline for (0..5) |y| {
                // XOR each element in a column
                array[x] ^= a[5 * y + x];
            }
        }

        // Then we compute the D[x] values, which adjust the columns based on the rotation of neighboring columns.
        //
        // D[x] = C[x-1] xor rot(C[x+1], 1), for x in 0…4
        inline for (0..5) |x| {
            // Trick using modulo to get the previous column
            const t1 = array[(x + 4) % 5];
            // Rotated next column
            const t2 = std.math.rotl(T, array[(x + 1) % 5], 1);
            inline for (0..5) |y| {
                // XOR the original lane with the adjusted columns
                a[5 * y + x] ^= t1 ^ t2;
            }
        }

        // Step 2: ρ (rho) and π (pi) steps
        //
        // The ρ step rotates each lane by a pre-determined number of bits.
        // The π step then repositions the lanes within the state grid.
        //
        // B[y, 2*x + 3*y] = rot(A[x, y], r[x, y]), for (x, y) in (0…4, 0…4)
        //
        // Start with the second lane in the state
        var last = a[1];
        inline for (0..24) |x| {
            // Save the original value for later use
            array[0] = a[PI[x]];
            // Rotate and move to the new position
            a[PI[x]] = std.math.rotl(T, last, RHO[x]);
            // Update `last` with the saved value
            last = array[0];
        }

        // Step 3: χ (chi) step
        //
        // χ is a non-linear step that mixes bits within rows by XORing each lane with a function of two other lanes in the row.
        //
        // A[x, y] = B[x, y] xor ((not B[x+1, y]) and B[x+2, y]), for (x, y) in (0…4, 0…4)
        inline for (0..5) |y_step| {
            // Process each row
            const y = 5 * y_step;
            inline for (0..5) |x| {
                // Store the current row values
                array[x] = a[y + x];
            }

            inline for (0..5) |x| {
                // XOR the current lane with a non-linear combination of the next two lanes in the row
                a[y + x] = array[x] ^ (~array[(x + 1) % 5] & array[(x + 2) % 5]);
            }
        }

        // Step 4: ι (iota) step
        //
        // In the ι step, we XOR the first lane (A[0, 0]) with a round constant.
        // This step ensures that each round produces a different result, adding "uniqueness" to the permutation.
        //
        // XOR the first lane with the current round constant
        a[0] ^= @truncate(rc);
    }
}

test "Keccak: test Keccak f200" {
    // Test vectors are copied from XKCP (eXtended Keccak Code Package)
    // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-200-IntermediateValues.txt
    const state_first = [_]u8{
        0x3C, 0x28, 0x26, 0x84, 0x1C, 0xB3, 0x5C, 0x17, 0x1E, 0xAA, 0xE9, 0xB8, 0x11, 0x13,
        0x4C, 0xEA, 0xA3, 0x85, 0x2C, 0x69, 0xD2, 0xC5, 0xAB, 0xAF, 0xEA,
    };

    const state_second = [_]u8{
        0x1B, 0xEF, 0x68, 0x94, 0x92, 0xA8, 0xA5, 0x43, 0xA5, 0x99, 0x9F, 0xDB, 0x83, 0x4E,
        0x31, 0x66, 0xA1, 0x4B, 0xE8, 0x27, 0xD9, 0x50, 0x40, 0x47, 0x9E,
    };

    var state = [_]u8{0} ** PLEN;
    try keccakP(u8, &state, @intCast(KECCAK_F_ROUND_COUNT(u8)));
    try std.testing.expectEqualSlices(u8, &state_first, &state);

    try keccakP(u8, &state, @intCast(KECCAK_F_ROUND_COUNT(u8)));
    try std.testing.expectEqualSlices(u8, &state_second, &state);
}

test "Keccak: test Keccak f400" {
    // Test vectors are copied from XKCP (eXtended Keccak Code Package)
    // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-400-IntermediateValues.txt
    const state_first = [_]u16{
        0x09F5, 0x40AC, 0x0FA9, 0x14F5, 0xE89F, 0xECA0, 0x5BD1, 0x7870, 0xEFF0, 0xBF8F, 0x0337,
        0x6052, 0xDC75, 0x0EC9, 0xE776, 0x5246, 0x59A1, 0x5D81, 0x6D95, 0x6E14, 0x633E, 0x58EE,
        0x71FF, 0x714C, 0xB38E,
    };

    const state_second = [_]u16{
        0xE537, 0xD5D6, 0xDBE7, 0xAAF3, 0x9BC7, 0xCA7D, 0x86B2, 0xFDEC, 0x692C, 0x4E5B, 0x67B1,
        0x15AD, 0xA7F7, 0xA66F, 0x67FF, 0x3F8A, 0x2F99, 0xE2C2, 0x656B, 0x5F31, 0x5BA6, 0xCA29,
        0xC224, 0xB85C, 0x097C,
    };

    var state = [_]u16{0} ** PLEN;
    try keccakP(u16, &state, @intCast(KECCAK_F_ROUND_COUNT(u16)));
    try std.testing.expectEqualSlices(u16, &state_first, &state);

    try keccakP(u16, &state, @intCast(KECCAK_F_ROUND_COUNT(u16)));
    try std.testing.expectEqualSlices(u16, &state_second, &state);
}

test "Keccak: test Keccak f800" {
    // Test vectors are copied from XKCP (eXtended Keccak Code Package)
    // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-800-IntermediateValues.txt
    const state_first = [_]u32{
        0xE531D45D, 0xF404C6FB, 0x23A0BF99, 0xF1F8452F, 0x51FFD042, 0xE539F578, 0xF00B80A7,
        0xAF973664, 0xBF5AF34C, 0x227A2424, 0x88172715, 0x9F685884, 0xB15CD054, 0x1BF4FC0E,
        0x6166FA91, 0x1A9E599A, 0xA3970A1F, 0xAB659687, 0xAFAB8D68, 0xE74B1015, 0x34001A98,
        0x4119EFF3, 0x930A0E76, 0x87B28070, 0x11EFE996,
    };

    const state_second = [_]u32{
        0x75BF2D0D, 0x9B610E89, 0xC826AF40, 0x64CD84AB, 0xF905BDD6, 0xBC832835, 0x5F8001B9,
        0x15662CCE, 0x8E38C95E, 0x701FE543, 0x1B544380, 0x89ACDEFF, 0x51EDB5DE, 0x0E9702D9,
        0x6C19AA16, 0xA2913EEE, 0x60754E9A, 0x9819063C, 0xF4709254, 0xD09F9084, 0x772DA259,
        0x1DB35DF7, 0x5AA60162, 0x358825D5, 0xB3783BAB,
    };

    var state = [_]u32{0} ** PLEN;
    try keccakP(u32, &state, @intCast(KECCAK_F_ROUND_COUNT(u32)));
    try std.testing.expectEqualSlices(u32, &state_first, &state);

    try keccakP(u32, &state, @intCast(KECCAK_F_ROUND_COUNT(u32)));
    try std.testing.expectEqualSlices(u32, &state_second, &state);
}

test "Keccak: test Keccak f1600" {
    // Test vectors are copied from XKCP (eXtended Keccak Code Package)
    // https://github.com/XKCP/XKCP/blob/master/tests/TestVectors/KeccakF-1600-IntermediateValues.txt
    const state_first = [_]u64{
        0xF1258F7940E1DDE7,
        0x84D5CCF933C0478A,
        0xD598261EA65AA9EE,
        0xBD1547306F80494D,
        0x8B284E056253D057,
        0xFF97A42D7F8E6FD4,
        0x90FEE5A0A44647C4,
        0x8C5BDA0CD6192E76,
        0xAD30A6F71B19059C,
        0x30935AB7D08FFC64,
        0xEB5AA93F2317D635,
        0xA9A6E6260D712103,
        0x81A57C16DBCF555F,
        0x43B831CD0347C826,
        0x01F22F1A11A5569F,
        0x05E5635A21D9AE61,
        0x64BEFEF28CC970F2,
        0x613670957BC46611,
        0xB87C5A554FD00ECB,
        0x8C3EE88A1CCF32C8,
        0x940C7922AE3A2614,
        0x1841F924A2C509E4,
        0x16F53526E70465C2,
        0x75F644E97F30A13B,
        0xEAF1FF7B5CECA249,
    };

    const state_second = [_]u64{
        0x2D5C954DF96ECB3C,
        0x6A332CD07057B56D,
        0x093D8D1270D76B6C,
        0x8A20D9B25569D094,
        0x4F9C4F99E5E7F156,
        0xF957B9A2DA65FB38,
        0x85773DAE1275AF0D,
        0xFAF4F247C3D810F7,
        0x1F1B9EE6F79A8759,
        0xE4FECC0FEE98B425,
        0x68CE61B6B9CE68A1,
        0xDEEA66C4BA8F974F,
        0x33C43D836EAFB1F5,
        0xE00654042719DBD9,
        0x7CF8A9F009831265,
        0xFD5449A6BF174743,
        0x97DDAD33D8994B40,
        0x48EAD5FC5D0BE774,
        0xE3B8C8EE55B7B03C,
        0x91A0226E649E42E9,
        0x900E3129E7BADD7B,
        0x202A9EC5FAA3CCE8,
        0x5B3402464E1C3DB6,
        0x609F4E62A44C1059,
        0x20D06CD26A8FBF5C,
    };

    var state = [_]u64{0} ** PLEN;
    try keccakP(u64, &state, @intCast(KECCAK_F_ROUND_COUNT(u64)));
    try std.testing.expectEqualSlices(u64, &state_first, &state);

    try keccakP(u64, &state, @intCast(KECCAK_F_ROUND_COUNT(u64)));
    try std.testing.expectEqualSlices(u64, &state_second, &state);
}
