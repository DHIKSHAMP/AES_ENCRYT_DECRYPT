# AES Encryption/Decryption Tool

This project is a Python-based AES encryption/decryption tool with an interactive GUI built using `CustomTkinter`. It allows users to securely encrypt and decrypt text using a 256-bit key.

## Features

- **AES-256 Encryption & Decryption**: Secure text encryption and decryption using the AES algorithm.
- **Modern GUI**: A user-friendly and visually appealing interface created with `CustomTkinter`.
- **Toggle Password Visibility**: Option to show/hide the encryption key during input.
- **Error Handling**: Ensures correct key length and provides user-friendly error messages.

## Installation

To run this project locally, follow these steps:

1. **Clone the repository**:
    ```bash
    git clone https://github.com/your-username/AES-Encryption-Decryption.git
    ```
2. **Navigate to the project directory**:
    ```bash
    cd AES-Encryption-Decryption
    ```
3. **Install the required Python packages**:
    ```bash
    pip install customtkinter cryptography
    ```
4. **Run the application**:
    ```bash
    python main.py
    ```

## Usage

- **Enter Plain Text**: Input the text you want to encrypt.
- **Enter Key**: Provide a 32-character (256-bit) key.
- **Encrypt/Decrypt**: Use the provided buttons to encrypt or decrypt your text.
- **Toggle Password Visibility**: Click the "Show Password" button to view or hide your key.

## Contributing

Contributions are welcome! Please fork this repository and submit a pull request for any improvements.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
