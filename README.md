-----

# Secure File Transfer System

This project implements a secure file transfer system using Java, featuring client-server architecture, user authentication, and encrypted file transfers. The system employs RSA for key exchange and AES for file encryption, ensuring confidentiality and integrity of transferred data.

-----

## Features

  * **User Authentication:** Secure login system using `jBCrypt` for password hashing and verification against a PostgreSQL database.
  * **Encrypted File Transfer:** Files are encrypted using AES (Advanced Encryption Standard) in CBC mode before transmission.
  * **Secure Key Exchange:** AES session keys are securely exchanged using RSA public-key cryptography.
  * **Data Integrity:** SHA-256 hashing is used to verify file integrity upon reception.
  * **Timestamp Verification:** Files received are checked against a timestamp to prevent replay attacks (files older than 5 minutes are rejected).
  * **Graphical User Interface (GUI):** A user-friendly Swing GUI for both client and server applications.
  * **File Preview and Download:** Users can preview received text and image files and choose to download them.

-----

## Technologies Used

  * **Java:** Core programming language.
  * **Swing:** For building the graphical user interface.
  * **jBCrypt:** For secure password hashing.
  * **PostgreSQL:** Database for user management.
  * **RSA:** For asymmetric encryption (key exchange).
  * **AES:** For symmetric encryption (file data).
  * **SHA-256:** For data integrity checks.

-----

## Setup Instructions

### Prerequisites

  * Java Development Kit (JDK) 11 or higher.
  * PostgreSQL database.
  * Maven (for dependency management, though manual jar addition is also an option).

### Database Setup

1.  **Create a PostgreSQL database** (e.g., `file_transfer_db`).

2.  **Create a `users` table** in your database:

    ```sql
    CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL
    );
    ```

3.  **Set environment variables** for database connection:

      * `DB_URL`: Your PostgreSQL JDBC URL (e.g., `jdbc:postgresql://localhost:5432/file_transfer_db`)
      * `DB_USER`: Your PostgreSQL username
      * `DB_PASSWORD`: Your PostgreSQL password

### Project Dependencies

You'll need the `jbcrypt` and PostgreSQL JDBC driver libraries.

  * **jBCrypt:**
      * Maven:
        ```xml
        <dependency>
            <groupId>org.mindrot</groupId>
            <artifactId>jbcrypt</artifactId>
            <version>0.4</version>
        </dependency>
        ```
      * Download: [jBCrypt-0.4.jar](https://www.google.com/search?q=https://repo1.maven.org/maven2/org/mindrot/jbcrypt/0.4/jbcrypt-0.4.jar)
  * **PostgreSQL JDBC Driver:**
      * Maven:
        ```xml
        <dependency>
            <groupId>org.postgresql</groupId>
            <artifactId>postgresql</artifactId>
            <version>42.7.3</version> </dependency>
        ```
      * Download: [PostgreSQL JDBC Driver](https://jdbc.postgresql.org/download/)

Add these JAR files to your project's classpath. If you're using an IDE like IntelliJ IDEA or Eclipse, you can add them via the project structure/build path settings.

### Running the Application

1.  **Compile the Java files.**

2.  **Register Users:**
    Run the `RegisterUser` class to add new users to the database. Follow the prompts to enter a username and password.

    ```bash
    java RegisterUser
    ```

3.  **Start the Server:**
    The `Server` application needs to be running first. Execute the `Server` class.

    ```bash
    java Server
    ```

4.  **Start the Client:**
    Run the `Client` class. This will open the login window.

    ```bash
    java Client
    ```

      * Enter the username and password you registered.
      * Upon successful login, the main client window will appear.
      * You can then select a file (text or image) and send it to the server.

-----

## How it Works

### Authentication

The `Client` application presents a login screen. When a user attempts to log in, the provided username and password are sent to the `authenticateUser` method. This method connects to the PostgreSQL database, retrieves the stored hashed password for the given username, and uses `BCrypt.checkpw` to securely verify the password.

### Key Exchange and File Encryption

1.  **Server Public Key Transmission:** When a `Client` connects to the `Server`, the `Server` first sends its RSA public key to the `Client`.
2.  **AES Key Generation:** The `Client` generates a random AES symmetric key and an Initialization Vector (IV).
3.  **Encrypted AES Key Transmission:** The `Client` then encrypts the generated AES key using the `Server`'s RSA public key. Both the encrypted AES key and the IV are sent to the `Server`.
4.  **AES Decryption by Server:** The `ClientHandler` on the `Server` side receives the encrypted AES key and decrypts it using the `Server`'s RSA private key.
5.  **File Encryption:** Before sending, the `Client` encrypts the file content using the generated AES key and IV.
6.  **File Decryption by Server:** Upon receiving the encrypted file, the `ClientHandler` decrypts it using the now-known AES key and IV.

### Data Integrity and Timestamp Verification

  * **Hash Generation (Client):** Before sending the encrypted file, the `Client` calculates a SHA-256 hash of the **original file bytes**, the **timestamp**, the **username**, and the **AES key**. This hash is sent along with the encrypted file.
  * **Timestamp Check (Server):** The `ClientHandler` first checks if the received file's timestamp is within a reasonable timeframe (e.g., less than 5 minutes old) to mitigate replay attacks.
  * **Hash Verification (Server):** After decrypting the file, the `ClientHandler` independently calculates the SHA-256 hash using the **decrypted file bytes**, the **received timestamp**, the **received username**, and the **decrypted AES key**. This computed hash is then compared with the hash received from the client to ensure data integrity.

-----

## Contributing

Feel free to fork the repository, make improvements, and submit pull requests.

-----
