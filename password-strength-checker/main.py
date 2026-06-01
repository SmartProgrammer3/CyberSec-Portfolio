import os
import sys
 
from checker.base_checks import check
from checker.crack_time import check_crack_time
from checker.entropy import check_entropy
from checker.haveibeenpwned import check_hibp
from checker.reporter import generate_report

def _run_checks(password: str) -> None:
    print(f"\nRunning password Checks...\n")

    results = check(password)
    
    substitutions_failed = any(r.name == "Weak substitutions" and not r.passed for r in results)
    
    entropy_result, entropy = check_entropy(password, penalise=substitutions_failed)
    
    results.append(entropy_result)
    results.extend(check_crack_time(entropy))
    results.append(check_hibp(password))

    total = len(results)
    passed = sum(1 for r in results if r.passed)

    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f" [{status}] {result.name}: {result.message}")

    print(f"\nScore: {passed}/{total} Checks passed.")

    os.makedirs("output", exist_ok=True)
    generate_report(results)
    
    
def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python main.py <password>")
        print("       python main.py <file.txt> (Note: Only one password in the file!)")
        return

    arg = sys.argv[1]

    if os.path.isfile(arg):
        with open(arg, "r") as f:
            passwords = [line.strip() for line in f if line.strip()]

        if not passwords:
            print("No passwords found in file.")
            return

        print(f"Found {len(passwords)} password(s) in '{arg}'.")

        for password in passwords:
            _run_checks(password)
    else:
        _run_checks(arg)
 
 
if __name__ == "__main__":
    main()