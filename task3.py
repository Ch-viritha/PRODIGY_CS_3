import re

def check_password_strength(password):
    length_criteria = len(password) >= 8
    uppercase_criteria = bool(re.search(r'[A-Z]', password))
    lowercase_criteria = bool(re.search(r'[a-z]', password))
    number_criteria = bool(re.search(r'[0-9]', password))
    special_char_criteria = bool(re.search(r'[\W_]', password))  # \W matches any non-alphanumeric character

    criteria_met = sum([length_criteria, uppercase_criteria, lowercase_criteria, number_criteria, special_char_criteria])

    if criteria_met == 5:
        return "Password is very strong!"
    elif criteria_met == 4:
        return "Password is strong!"
    elif criteria_met == 3:
        return "Password is moderate!"
    elif criteria_met == 2:
        return "Password is weak!"
    else:
        return "Password is very weak!"

def provide_feedback(password):
    feedback = []
    
    if len(password) < 8:
        feedback.append("Password should be at least 8 characters long.")
    if not re.search(r'[A-Z]', password):
        feedback.append("Password should contain at least one uppercase letter.")
    if not re.search(r'[a-z]', password):
        feedback.append("Password should contain at least one lowercase letter.")
    if not re.search(r'[0-9]', password):
        feedback.append("Password should contain at least one digit.")
    if not re.search(r'[\W_]', password):
        feedback.append("Password should contain at least one special character (e.g., @, #, $, etc.).")
    
    return feedback

if __name__ == "__main__":
    password = input("Enter your password: ")
    
    strength = check_password_strength(password)
    print(strength)
    
    feedback = provide_feedback(password)
    
    if feedback:
        print("Suggestions to improve your password:")
        for f in feedback:
            print(f"- {f}")
  