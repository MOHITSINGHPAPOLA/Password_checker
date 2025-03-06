import re
from collections import Counter
import requests
import hashlib
import time

class AdvancedPasswordChecker:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()
        self.common_patterns = [
            r'12345', r'qwerty', r'abc', r'password',
            r'(\d)\1{2,}',  # Repeated numbers
            r'([a-zA-Z])\1{2,}'  # Repeated letters
        ]
        
    def load_common_passwords(self):
        # You could load from a file or API
        return {'password123', 'admin123', '123456', 'qwerty', 'letmein'}

    def check_haveibeenpwned(self, password):
        """Check if password has been exposed in data breaches"""
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        try:
            response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for hash_suffix, count in hashes:
                    if hash_suffix == suffix:
                        return int(count)
            return 0
        except:
            return -1  # Error checking

    def check_entropy(self, password):
        """Calculate password entropy (randomness)"""
        length = len(password)
        char_types = {
            'lowercase': len([c for c in password if c.islower()]),
            'uppercase': len([c for c in password if c.isupper()]),
            'numbers': len([c for c in password if c.isdigit()]),
            'special': len([c for c in password if not c.isalnum()])
        }
        
        # Calculate character set size
        charset_size = 0
        if char_types['lowercase']: charset_size += 26
        if char_types['uppercase']: charset_size += 26
        if char_types['numbers']: charset_size += 10
        if char_types['special']: charset_size += 32
        
        # Calculate entropy
        if charset_size:
            entropy = length * (len(str(charset_size)) / len(str(2)))
            return entropy
        return 0

    def check_keyboard_patterns(self, password):
        """Check for keyboard patterns"""
        keyboard_rows = [
            "qwertyuiop",
            "asdfghjkl",
            "zxcvbnm"
        ]
        
        # Check for horizontal patterns
        for row in keyboard_rows:
            for i in range(len(row) - 2):
                pattern = row[i:i+3].lower()
                if pattern in password.lower():
                    return True
        return False

    def analyze_password(self, password):
        score = 0
        feedback = []
        security_report = {}

        # Basic checks
        if len(password) < 12:
            feedback.append("Password should be at least 12 characters long")
        else:
            score += len(password) // 6

        # Character variety checks
        char_types = {
            'lowercase': any(c.islower() for c in password),
            'uppercase': any(c.isupper() for c in password),
            'numbers': any(c.isdigit() for c in password),
            'special': any(not c.isalnum() for c in password)
        }

        for char_type, present in char_types.items():
            if present:
                score += 1
            else:
                feedback.append(f"Add {char_type} characters")

        # Advanced checks
        # 1. Check for common patterns
        for pattern in self.common_patterns:
            if re.search(pattern, password):
                score -= 1
                feedback.append("Avoid common patterns")
                break

        # 2. Check for repeated characters
        char_counts = Counter(password)
        if max(char_counts.values()) > 3:
            score -= 1
            feedback.append("Avoid repeating characters too many times")

        # 3. Check entropy
        entropy = self.check_entropy(password)
        security_report['entropy'] = entropy
        if entropy < 50:
            feedback.append("Increase password complexity")
        else:
            score += 1

        # 4. Check keyboard patterns
        if self.check_keyboard_patterns(password):
            score -= 1
            feedback.append("Avoid keyboard patterns")

        # 5. Check common passwords
        if password.lower() in self.common_passwords:
            score -= 3
            feedback.append("This is a commonly used password")

        # 6. Check haveibeenpwned database
        breach_count = self.check_haveibeenpwned(password)
        if breach_count > 0:
            score -= 2
            feedback.append(f"This password appears in {breach_count} data breaches")
        security_report['breach_count'] = breach_count

        # Calculate final strength
        if score < 2:
            strength = "Very Weak"
        elif score < 3:
            strength = "Weak"
        elif score < 4:
            strength = "Moderate"
        elif score < 5:
            strength = "Strong"
        else:
            strength = "Very Strong"

        security_report.update({
            'strength': strength,
            'score': score,
            'feedback': feedback,
            'char_variety': char_types
        })

        return security_report

def main():
    checker = AdvancedPasswordChecker()
    
    print("Advanced Password Strength Analyzer")
    print("==================================")
    
    while True:
        password = input("\nEnter a password to analyze (or 'q' to quit): ")
        
        if password.lower() == 'q':
            break
            
        print("\nAnalyzing password security...")
        start_time = time.time()
        
        report = checker.analyze_password(password)
        
        print(f"\nAnalysis completed in {time.time() - start_time:.2f} seconds")
        print(f"\nStrength: {report['strength']}")
        print(f"Score: {report['score']}")
        print(f"Entropy: {report['entropy']:.2f} bits")
        
        if report['breach_count'] >= 0:
            print(f"Found in data breaches: {report['breach_count']} times")
        
        print("\nCharacter Variety:")
        for char_type, present in report['char_variety'].items():
            print(f"- {char_type}: {'✓' if present else '✗'}")
        
        if report['feedback']:
            print("\nSuggestions for improvement:")
            for suggestion in report['feedback']:
                print(f"- {suggestion}")
        else:
            print("\nExcellent password! No improvements needed.")

if __name__ == "__main__":
    main()