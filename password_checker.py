import re


def check_password_strength(password):
    """
    Evaluates the strength of a password based on multiple criteria.
    Returns a strength rating and feedback for improvement.
    """
    score = 0
    feedback = []
    passed = []

    # 1. Length Check
    length = len(password)
    if length < 8:
        feedback.append("❌ Too short — use at least 8 characters (you have {})".format(length))
    elif length < 12:
        score += 1
        passed.append("✅ Acceptable length ({} characters)".format(length))
        feedback.append("💡 Consider using 12+ characters for stronger security")
    else:
        score += 2
        passed.append("✅ Great length ({} characters)".format(length))

    # 2. Uppercase Letters
    if re.search(r'[A-Z]', password):
        score += 1
        passed.append("✅ Contains uppercase letters")
    else:
        feedback.append("❌ Add at least one uppercase letter (A-Z)")

    # 3. Lowercase Letters
    if re.search(r'[a-z]', password):
        score += 1
        passed.append("✅ Contains lowercase letters")
    else:
        feedback.append("❌ Add at least one lowercase letter (a-z)")

    # 4. Numbers
    if re.search(r'\d', password):
        score += 1
        passed.append("✅ Contains numbers")
    else:
        feedback.append("❌ Add at least one number (0-9)")

    # 5. Special Characters
    # Use a safe character class that doesn't require complex escaping.
    if re.search(r'[^\w\s]', password):
        score += 1
        passed.append("✅ Contains special characters")
    else:
        feedback.append("❌ Add at least one special character (!@#$%^&* etc.)")

    # 6. No Common Patterns
    common_patterns = ['123456', 'password', 'qwerty', 'abc123', '111111', 'letmein', 'welcome']
    if any(pattern in password.lower() for pattern in common_patterns):
        score -= 1
        feedback.append("⚠️  Avoid common patterns like '123456' or 'password'")
    else:
        passed.append("✅ No common patterns detected")

    # 7. No Repeated Characters
    if re.search(r'(.)\1{2,}', password):
        score -= 1
        feedback.append("⚠️  Avoid repeating the same character 3+ times in a row")
    else:
        passed.append("✅ No excessive character repetition")

    # Clamp score
    score = max(0, score)

    # Classify strength
    if score <= 2:
        strength = "🔴 WEAK"
        color_hint = "Your password is easy to crack. Please improve it!"
    elif score <= 4:
        strength = "🟡 MODERATE"
        color_hint = "Your password is okay but can be stronger."
    elif score <= 5:
        strength = "🟢 STRONG"
        color_hint = "Your password is strong. Good job!"
    else:
        strength = "🟢 VERY STRONG"
        color_hint = "Excellent! Your password is very secure."

    return strength, score, passed, feedback, color_hint


def display_result(password, strength, score, passed, feedback, color_hint):
    print("\n" + "=" * 50)
    print("       PASSWORD STRENGTH CHECKER")
    print("=" * 50)
    print(f"\n🔑 Password : {'*' * len(password)}  ({len(password)} chars)")
    print(f"📊 Score    : {score}/7")
    print(f"💪 Strength : {strength}")
    print(f"ℹ️  Summary  : {color_hint}")

    if passed:
        print("\n✔  What's Good:")
        for p in passed:
            print(f"   {p}")

    if feedback:
        print("\n✘  What to Improve:")
        for f in feedback:
            print(f"   {f}")

    print("\n" + "=" * 50)


def main():
    print("\n╔══════════════════════════════════════════╗")
    print("║       🔐 PASSWORD STRENGTH CHECKER 🔐    ║")
    print("╚══════════════════════════════════════════╝")
    print("Type 'quit' to exit.\n")

    while True:
        try:
            password = input("Enter a password to check: ")
        except EOFError:
            print("\n\n👋 Goodbye! Stay secure!\n")
            break

        if password.lower() == 'quit':
            print("\n👋 Goodbye! Stay secure!\n")
            break

        if not password:
            print("⚠️  Please enter a password.\n")
            continue

        strength, score, passed, feedback, color_hint = check_password_strength(password)
        display_result(password, strength, score, passed, feedback, color_hint)

        another = input("\nCheck another password? (yes/no): ").strip().lower()
        if another not in ['yes', 'y']:
            print("\n👋 Goodbye! Stay secure!\n")
            break
        print()


if __name__ == "__main__":
    main()
