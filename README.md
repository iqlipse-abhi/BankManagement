# Bank Management System (C++ CLI Application)

A secure and modular command-line banking system built in C++, supporting multiple user roles, savings/checking account types, and full transaction management with persistent storage.

## Features

- **User Management**
  - Registration with password confirmation
  - Secure login with salted password hashing
  - Account lockout after multiple failed attempts

- **Account Operations**
  - Create Savings or Checking accounts
  - Deposit and withdraw funds
  - View balance and transaction history
  - Apply interest to savings accounts
  - Support for overdraft and transaction fees on checking accounts

- **Security**
  - Salted and hashed password storage
  - Account lockout with timestamp-based recovery
  - File integrity checks using checksum verification

- **Persistence**
  - Data saved across sessions using structured file I/O:
    - `s_users.txt`, `s_accounts.txt`, `s_transactions.txt`
  - Checksums used to detect file tampering
  - Centralized logging to `secure_bank_log.txt`

- **Admin Features**
  - View all users and accounts in the system
  - Auto-provisioned default admin user (`admin` / `adminP@$$wOrd`)

## Technologies Used

- C++11/14
- Standard Library: `<fstream>`, `<chrono>`, `<sstream>`, `<map>`, `<memory>`, etc.
- Cross-platform support: Windows, Linux, macOS

