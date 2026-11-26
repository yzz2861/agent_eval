# Health expression static audit

This tool reviews a small C integer expression with pycparser only. It does not invoke a compiler, firmware image, or target binary.

## Run

    python3 health_audit.py --config health_threshold_example.json
    python3 health_audit.py --config health_threshold_example.json --json

The command exits zero only when every configured target has sufficient evidence for the business bounds. An insufficient or pending target exits one; configuration errors exit two.

## Hand-calculable threshold

Expression:

    shared_count = (uint16_t)(
        (samples >= 0 && samples <= 16384) ? samples * 2 : 32766
    )

Caller input:

- samples: int16_t
- shared_count: uint16_t
- business interval: [0, 32768]
- board16: int = 16 bits
- board32: int = 32 bits

For the true branch, the constant conditions reduce samples to [0, 16384]. Therefore samples * 2 has envelope [0, 32768]. The false branch is the constant 32766.

- board32 promotes int16_t to 32-bit int. The largest product is 32768, which is representable, and the uint16_t cast preserves it. Evidence is sufficient for [0, 32768].
- board16 promotes int16_t to 16-bit int. INT16_MAX is 32767, so samples = 16384 makes samples * 2 equal to 32768 and triggers possible signed overflow, which is undefined behavior in C. Evidence is insufficient.
- Lowering the guard to samples < 16384 makes the maximum true value 16383 * 2 = 32766. That variant is provable on board16 for business bound [0, 32766].

## Decisions

- sufficient_evidence: the sound range envelope is inside the business interval and no blocking uncertainty is present.
- insufficient_evidence: possible undefined behavior, unsupported arithmetic, or an out-of-bounds envelope prevents the proof.
- needs_confirmation: a field/cast type or target ABI detail is unknown or implementation-defined. Supply the missing type or target guarantee and rerun.

The analyzer models integer promotions, usual arithmetic conversions, unsigned modulo conversion, common two's-complement diagnostics for signed casts, ternary branches, short-circuit logic, simple constant conditions, and basic assignments. Ranges are conservative envelopes, so an imprecise result can be inconclusive but should not manufacture a proof.

Sufficient evidence applies only to the caller-supplied numeric lower/upper invariant. It does not prove monotonicity, absence of counter reset, log serialization, or other operational properties of the shared log.
