# Phishing Email Detection Model

# Training dataset
emails = [
    ("You have won a free iPhone. Click here now!", "Phishing"),
    ("Your bank account needs verification.", "Phishing"),
    ("Claim your reward immediately.", "Phishing"),
    ("Meeting scheduled for tomorrow.", "Safe"),
    ("Please submit the project report.", "Safe"),
    ("Thank you for attending the workshop.", "Safe")
]

# Phishing keywords
phishing_keywords = [
    "win", "won", "free", "click", "verify",
    "bank", "reward", "urgent", "password",
    "lottery", "prize"
]

# Testing on training data
tp = tn = fp = fn = 0

for email, actual in emails:
    prediction = "Safe"

    for keyword in phishing_keywords:
        if keyword in email.lower():
            prediction = "Phishing"
            break

    if actual == "Phishing" and prediction == "Phishing":
        tp += 1
    elif actual == "Safe" and prediction == "Safe":
        tn += 1
    elif actual == "Safe" and prediction == "Phishing":
        fp += 1
    elif actual == "Phishing" and prediction == "Safe":
        fn += 1

# Accuracy
total = tp + tn + fp + fn
accuracy = ((tp + tn) / total) * 100

print("PHISHING EMAIL DETECTION MODEL")
print("-" * 35)
print("Accuracy: {:.2f}%".format(accuracy))

print("\nConfusion Matrix")
print("                 Predicted")
print("              Phishing  Safe")
print("Actual Phishing   ", tp, "      ", fn)
print("Actual Safe       ", fp, "      ", tn)

# User input
while True:
    print("\nEnter an email to test (type 'exit' to quit):")
    email_text = input()

    if email_text.lower() == "exit":
        break

    result = "Safe"

    for keyword in phishing_keywords:
        if keyword in email_text.lower():
            result = "Phishing"
            break

    print("Classification:", result)
