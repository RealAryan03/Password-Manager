# Password Manager Setup Instructions

## Prerequisites
- Python 3.8 or higher
- pip package manager

## Installation

1. **Clone or download the project files:**
   ```bash
   # Download the following files:
   # - secure_password_manager.py
   # - requirements.txt
   # - README.md (this file)
   ```

2. **Create a virtual environment (recommended):**
   ```bash
   python -m venv password_manager_env

   # Activate on Windows:
   password_manager_env\Scripts\activate

   # Activate on macOS/Linux:
   source password_manager_env/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### First Time Setup
1. Run the password manager:
   ```bash
   python secure_password_manager.py
   ```

2. Set a master password when prompted
   - Must be at least 8 characters
   - Should include uppercase, lowercase, numbers, and special characters

### Daily Usage
1. Run the application: `python secure_password_manager.py`
2. Enter your master password
3. Use the menu to:
   - Add new passwords
   - Retrieve existing passwords
   - Update or delete entries
   - Generate secure passwords
   - List all stored websites

## Security Features

### Encryption
- **AES-256 encryption** using Fernet symmetric encryption
- **PBKDF2 key derivation** with 100,000 iterations
- **Salt-based hashing** to prevent rainbow table attacks

### Storage
- Passwords stored in encrypted JSON format
- Master password never stored in plain text
- Each session requires re-authentication

### Audit Trail
- All activities logged to `audit.log`
- Timestamps for all operations
- Failed login attempts tracked

## File Structure
```
password_manager/
├── secure_password_manager.py  # Main application
├── requirements.txt           # Dependencies
├── README.md                 # This file
├── password_vault.json       # Created on first run (encrypted data)
└── audit.log                 # Created on first run (activity log)
```

## Command Reference

### Menu Options
1. **Add password** - Store new website credentials
2. **Get password** - Retrieve stored credentials
3. **List websites** - Show all stored websites
4. **Update password** - Modify existing entries
5. **Delete password** - Remove entries permanently
6. **Generate password** - Create secure random passwords
7. **Logout** - End current session
8. **Exit** - Close application

### Password Generation
- Default length: 16 characters
- Customizable length
- Optional symbol inclusion
- Cryptographically secure random generation

## Security Best Practices

### Master Password
- Use a unique, strong master password
- Don't reuse from other accounts
- Consider using a memorable passphrase
- Change periodically (every 6-12 months)

### General Usage
- Always logout when finished
- Don't leave the application running unattended
- Keep the vault file backed up securely
- Regularly review audit logs

### System Security
- Keep your operating system updated
- Use antivirus software
- Encrypt your hard drive
- Use secure networks only

## Backup and Recovery

### Backing Up
- Copy `password_vault.json` to a secure location
- Encrypt backup files additionally
- Store in multiple secure locations
- Test restore process periodically

### Recovery
- Restore `password_vault.json` to the application directory
- Master password required to access restored data
- Audit logs will show restoration activity

## Troubleshooting

### Common Issues
1. **"Invalid master password"**
   - Verify password is correct
   - Check for caps lock
   - Ensure vault file is not corrupted

2. **"Failed to decrypt password data"**
   - Vault file may be corrupted
   - Restore from backup if available

3. **Import errors**
   - Ensure all dependencies are installed
   - Check Python version compatibility

### Error Recovery
- Check `audit.log` for detailed error information
- Restore from backup if vault is corrupted
- Recreate vault if necessary (will lose all data)

## Advanced Configuration

### Customization Options
- Modify encryption parameters in source code
- Adjust password generation rules
- Change file locations
- Add additional security features

### Integration
- Can be integrated with system keychains
- API endpoints can be added for web interface
- Database backends can replace JSON storage

## Security Considerations

### Known Limitations
- Master password stored in memory during session
- JSON format readable when decrypted
- No built-in network security features
- Single-user design

### Recommended Enhancements
- Add two-factor authentication
- Implement secure sharing features
- Add password health monitoring
- Include breach detection
- Add automatic backup features

## Development

### Testing
```bash
# Run basic functionality tests
python secure_password_manager.py

# Test password generation
python -c "from secure_password_manager import PasswordManager; pm = PasswordManager(); print(pm.generate_password(20))"
```

### Contributing
- Follow PEP 8 style guidelines
- Add comprehensive error handling
- Include unit tests for new features
- Update documentation accordingly

## License
This project is provided for educational purposes. Use at your own risk.

## Support
- Review audit logs for troubleshooting
- Check Python documentation for cryptography module
- Refer to OWASP guidelines for password security
