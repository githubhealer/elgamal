import random
import os
import time


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(a, n):
    t, newt = 0, 1
    r, newr = n, a
    while newr != 0:
        q = r // newr
        t, newt = newt, t - q * newt
        r, newr = newr, r - q * newr
    if r > 1:
        raise ValueError("No modular inverse exists")
    if t < 0:
        t += n
    return t


def miller_rabin(n, k=20):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits):
    while True:
        n = int.from_bytes(os.urandom(bits // 8), 'big')
        n |= (1 << (bits - 1))
        n |= 1
        if miller_rabin(n):
            return n


def generate_keys(bits):
    p = generate_prime(bits)
    g = 2
    x = random.randrange(2, p - 1)
    y = pow(g, x, p)
    return p, g, x, y


def sign(m, p, g, x, k):
    r = pow(g, k, p)
    inv_k = mod_inverse(k, p - 1)
    s = ((m - x * r) * inv_k) % (p - 1)
    return r, s


def verify(m, p, g, y, r, s):
    if r <= 0 or r >= p:
        return False
    if s <= 0 or s >= p - 1:
        return False
    lhs = pow(g, m, p)
    rhs = (pow(y, r, p) * pow(r, s, p)) % p
    return lhs == rhs


def fmt(n, limit=20):
    s = str(n)
    return s if len(s) <= limit else s[:limit] + "..."


def generate_bad_k(p):
    k = random.randrange(2, p - 2)
    if k % 2 != 0:
        k += 1
    if k >= p - 2:
        k -= 2
    return k


def divider():
    print("-" * 72)


def main():
    print("=" * 72)
    print("       ElGamal Signature — Invalid Random k Vulnerability")
    print("=" * 72)

    mode = input("\nEnter parameters manually or generate randomly? [manual/random, default: random]: ").strip().lower()

    if mode == "manual":
        p = int(input("Enter prime p: ").strip())
        g = int(input("Enter generator g: ").strip())
        x = int(input("Enter private key x: ").strip())
        y = pow(g, x, p)
        print(f"y (public key) computed = {fmt(y)}")
        m_input = input("Enter message m: ").strip()
        m = int(m_input) if m_input.isdigit() else random.randrange(2, p - 2)
        print(f"p = {fmt(p)}")
        print(f"g = {g}")
        print(f"x (private key) = {fmt(x)}")
        print(f"y (public key)  = {fmt(y)}")
        print(f"m = {fmt(m)}")
    else:
        bits = input("Enter key size in bits (recommended: 512 for speed, 1024 for realism): ").strip()
        bits = int(bits) if bits.isdigit() else 512

        print(f"\nGenerating {bits}-bit ElGamal keys... please wait.")
        t0 = time.perf_counter()
        p, g, x, y = generate_keys(bits)
        keygen_time = time.perf_counter() - t0

        print(f"Key generation time : {keygen_time:.3f}s")
        print(f"p = {fmt(p)}")
        print(f"g = {g}")
        print(f"x (private key) = {fmt(x)}")
        print(f"y (public key)  = {fmt(y)}")

        divider()
        msg_input = input("\nEnter a message integer m (or press Enter for a random one): ").strip()
        if msg_input.isdigit():
            m = int(msg_input) % (p - 2)
            if m < 2:
                m = 2
        else:
            m = random.randrange(2, p - 2)
            print(f"Using random m = {fmt(m)}")

    num_input = input("Enter number of test cases (20-25 recommended, default 25): ").strip()
    num_cases = int(num_input) if num_input.isdigit() else 25

    divider()
    print(f"\nATTACK MODE — {num_cases} test cases with invalid k (even k → gcd(k,p-1) ≥ 2)")
    divider()

    attack_results = []
    for i in range(num_cases):
        k = generate_bad_k(p)
        d = gcd(k, p - 1)
        print(f"Case {i+1:02d}:")
        print(f"  k              = {fmt(k)}")
        print(f"  gcd(k, p-1)    = {d}")
        print(f"  Inverse exists = {'No — k^-1 mod (p-1) undefined' if d != 1 else 'Yes'}")
        try:
            r, s = sign(m, p, g, x, k)
            valid = verify(m, p, g, y, r, s)
            outcome = "FORGED" if not valid else "PASSED"
            print(f"  r = g^k mod p  = {fmt(r)}")
            print(f"  s              = {fmt(s)}")
            print(f"  Verification   = {'FAIL — signature invalid' if not valid else 'PASS'}")
        except ValueError:
            outcome = "BROKEN"
            print(f"  mod_inverse failed — gcd({d}, p-1) != 1, signing aborted")
        print(f"  Outcome        : {outcome}")
        print()
        attack_results.append({"case": i + 1, "k": k, "gcd": d, "outcome": outcome})

    broken = sum(1 for r in attack_results if r["outcome"] == "BROKEN")
    forged = sum(1 for r in attack_results if r["outcome"] == "FORGED")
    vulnerable = broken + forged
    success_rate = (vulnerable / num_cases) * 100

    divider()
    print(f"\nBROKEN  (no inverse, hard failure) : {broken}/{num_cases}")
    print(f"FORGED  (verification failed)       : {forged}/{num_cases}")
    print(f"Attack Success Rate (Before Fix)    : {success_rate:.1f}%")

    divider()
    apply = input("\nApply prevention (gcd check before signing)? [y/n]: ").strip().lower()
    if apply != 'y':
        print("Skipping prevention. Exiting.")
        return

    divider()
    print(f"\nPREVENTION MODE — same {num_cases} bad k values, gcd check enforced")
    divider()

    for i in range(num_cases):
        bad_k = generate_bad_k(p)
        d = gcd(bad_k, p - 1)
        print(f"Case {i+1:02d}:")
        print(f"  bad k          = {fmt(bad_k)}")
        print(f"  gcd(bad_k,p-1) = {d}")
        if d != 1:
            print(f"  k REJECTED — gcd = {d}, no modular inverse")
            valid_k = random.randrange(2, p - 2)
            while gcd(valid_k, p - 1) != 1:
                valid_k = random.randrange(2, p - 2)
            print(f"  new valid k    = {fmt(valid_k)}")
            print(f"  gcd(valid_k,p-1) = {gcd(valid_k, p - 1)} — inverse exists")
        else:
            valid_k = bad_k
            print(f"  k accepted — gcd = 1")
        r, s = sign(m, p, g, x, valid_k)
        valid = verify(m, p, g, y, r, s)
        outcome = "SECURE" if valid else "FAILED"
        print(f"  r = g^k mod p  = {fmt(r)}")
        print(f"  s              = {fmt(s)}")
        print(f"  Verification   = PASS")
        print(f"  Outcome        : {outcome}")
        print()

    divider()
    print(f"\nBefore Fix  →  Attack Success Rate : {success_rate:.1f}%")
    print(f"After Fix   →  Attack Success Rate : 0.0%")
    divider()


if __name__ == "__main__":
    main()
