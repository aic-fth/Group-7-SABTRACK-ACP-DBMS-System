#!/usr/bin/env python3
"""
Setup script to create .env file for SABTRACK email configuration
"""
import os

def create_env_file():
    """Create .env file with email configuration"""

    print("🔧 Setting up SABTRACK Email Configuration")
    print("=" * 50)

    # Get email credentials from user
    email_address = input("Enter your Gmail address (e.g., yourname@gmail.com): ").strip()
    email_password = input("Enter your Gmail App Password (16 characters): ").strip()

    # Validate inputs
    if not email_address or not email_password:
        print("❌ Error: Both email address and app password are required!")
        return False

    if len(email_password) != 16:
        print("⚠️  Warning: Gmail App Passwords are typically 16 characters.")
        print("Make sure you're using an App Password, not your regular password.")

    # Create .env content
    env_content = f"""# SABTRACK Email Configuration
EMAIL_ADDRESS={email_address}
EMAIL_PASSWORD={email_password}
SMTP_SERVER=smtp.gmail.com
SMTP_PORT=587
"""

    # Write to .env file
    try:
        with open('.env', 'w') as f:
            f.write(env_content)

        print("✅ .env file created successfully!")
        print(f"📧 Email: {email_address}")
        print("🔒 Password: Configured")
        print("\n📋 Next steps:")
        print("1. Restart your Flask application")
        print("2. Run: python check_email_config.py")
        print("3. Run: python test_email_send.py")
        print("4. Test reminder emails in the application")

        return True

    except Exception as e:
        print(f"❌ Error creating .env file: {e}")
        return False

if __name__ == "__main__":
    create_env_file()
