import os
import sys
 
from checker.base_checks import check
from checker.entropy import check_entropy
from checker.haveibeenpwned import check_hibp
from checker.reporter import generate_report

def main() -> None:
    if len(sys.argv) != 2:
        print("Usage: python main.py <password>")
        return
    
    password = sys.argv[1]

    if not password:
        print("No password provided. Exiting.")
        return

    print("\nRunning checks...\n")
 
    # Run all checks and aggregate results.
    results = check(password)
    results.append(check_entropy(password))
    results.append(check_hibp(password))
 
    # Print a quick summary to the terminal.
    total = len(results)
    passed = sum(1 for r in results if r.passed)
 
    for result in results:
        status = "PASS" if result.passed else "FAIL"
        print(f"  [{status}] {result.name}: {result.message}")
 
    print(f"\nScore: {passed}/{total} checks passed.")
 
    # Generate the PDF report.
    os.makedirs("output", exist_ok=True)
    generate_report(results)
 
 
if __name__ == "__main__":
    main()