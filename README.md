## PSSWD-Checker
- PSSWD-Checker is a powerful and user-friendly password strength evaluation tool designed to help users create secure passwords. In an age where data breaches are common, having a strong password is essential for protecting personal and sensitive information.

# PSSWD-Checker 🔒

## Table of Contents
- [Features](#features)
- [Technologies Used](#technologies-used)
- [Installation](#installation)
- [Usage](#usage)
- [Example](#example)
- [Future Enhancements](#future-enhancements)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

## Features
- **🔍 Strength Assessment:** Evaluates passwords against multiple criteria, including:
  - Minimum length (at least 12 characters)
  - Character variety (uppercase, lowercase, numbers, special characters)
  - Common password patterns
- **🚫 Leet Speak Detection:** Identifies and discourages the use of common leet speak substitutions (e.g., "3" for "e") that can weaken password security.
- **📊 Entropy Calculation:** Measures the randomness of passwords to provide a quantitative strength score, helping users understand the strength of their passwords.
- **🔐 Breach Check:** Utilizes the [Have I Been Pwned API](https://haveibeenpwned.com/API/v2) to check if a password has been compromised in known data breaches, alerting users to potential risks.
- **🛡️ Strong Password Generation:** Offers suggestions for generating strong, random passwords to enhance security.

## Technologies Used
- **Python:** The primary programming language used for development.
- **Regular Expressions:** For pattern matching and validation.
- **Hashing (SHA-1):** To securely check password breaches.
- **RESTful APIs:** For interacting with external services.
- **Command-line Interface:** For user interaction.

## Installation
To run PSSWD-Checker, ensure you have Python installed on your machine. Follow these steps to clone the repository and run the script:

```bash
git clone https://github.com/CYBER-4RMY/PSSWD-Checker.git
cd PSSWD-Checker
python3 setup.py
```

## Usage
Run the script using Python:

```bash
python3 PSSWD-Checker.py
```

You will be prompted to enter a password to check its strength. The tool will provide feedback on the password's strength and whether it has been breached.

![Screenshot at 2025-03-10 15-57-40](https://github.com/user-attachments/assets/3f55a8c1-0284-4c4c-be87-78a030697453)


## Example
```
-->>Enter A Password To Check It's Strength: yourpassword123
-> Length Check: True
-> Complexity Check: False
-> Common Patterns Check: False
-> Leet Speak Check: True
-> Repeated Characters Check: True
-> Sequential Characters Check: True
-> Entropy: 28.5
-> Character Set Entropy: 56.0
-> Strength Score: 3

-->> The password 'yourpassword123' is Weak.
-> Password should include uppercase, lowercase, numbers & special characters.
```

## Future Enhancements
- **🌍 Expand Common Password List:** Increase the list of common passwords for more comprehensive checks.
- **🖥️ User-Friendly GUI:** Implement a graphical user interface for easier interaction.
- **🌐 Multilingual Support:** Add support for multiple languages to reach a broader audience.

## Contributing
Contributions are welcome! If you have suggestions for improvements, bug fixes, or new features, please feel free to open an issue or submit a pull request. Your feedback is invaluable in making PSSWD-Checker even better.

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Thank you for checking out PSSWD-Checker! Stay safe and secure online! 🔐
