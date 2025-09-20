LAN File Transfer

A simple, fast, and powerful desktop application for transferring files and folders between different computers on a local network (Wi-Fi or LAN), without needing an internet connection or cloud services.
✨ Features

Focusing on simplicity and efficiency, this application offers the following professional features:

    Automatic Device Discovery: Automatically finds and displays all computers running the application on the network (using Zeroconf/mDNS technology).

    Cross-Platform Support: Fully tested and functional on both Windows and Linux.

    Multiple File & Folder Transfer: Ability to send a single file, multiple files at once, or a complete folder with all its contents.

    Drag & Drop Support: Easily drag and drop your files and folders directly onto the application window.

    Dual Progress Bars: Simultaneously displays the overall progress (e.g., File 3 of 10) and the progress of the current file being transferred.

    Live Transfer Info: Shows the real-time transfer speed, the amount of data transferred, and the estimated time remaining (ETA).

    Cancel Transfer: The ability to stop the transfer at any moment, from either the sender's or the receiver's side.

    Receiver Confirmation: Prompts the receiving user for confirmation before a transfer begins.

    File Integrity Check (Checksum): After each transfer, the file's integrity is verified using the SHA-256 algorithm to ensure data correctness.

    Show in Folder: After a successful download, open the file manager directly to the save location with a single click.

    Native File Dialogs on Linux: Uses the native file selection windows of the Linux operating system for a better user experience.

📥 Download & Usage

To use the application, you don't need to install Python or any other tools. Simply download the appropriate version for your operating system from the Releases section of this page and run it.
How to Use:

    Run the application on both computers (sender and receiver).

    The application will automatically display other computers in the "Target" dropdown list.

    Select the file or folder you want to send using the buttons or by dragging and dropping.

    Choose the destination computer from the dropdown list and click the Send Content button.

    On the destination computer, accept the incoming transfer request.

🛠️ Building from Source (For Developers)

If you want to run or modify the application from the source code, follow the steps below.
1. Prerequisites

    Python 3.8 or higher

    pip (Python package manager)

2. Install Dependencies

Open a terminal or Command Prompt and enter the following commands to install the required libraries:

pip install zeroconf
pip install tkinterdnd2
pip install pyopenssl # Recommended for TLS certificate generation

3. Run the Application

To run the application from the source code, enter the following command in the terminal:

python main.py

4. Build an Executable

To create a standalone executable (e.g., an .exe file on Windows), the PyInstaller tool is used.

Install PyInstaller:

pip install pyinstaller

Build Command:
The icon file (icon.png) must be in the same directory as main.py. Then, run the following command in your terminal.

For Linux:

pyinstaller --onefile --windowed --name "FileTransferApp" --icon="icon.png" --add-data="icon.png:." main.py

For Windows:
First, convert the icon.png file to icon.ico using an online tool.

pyinstaller --onefile --windowed --name "FileTransferApp" --icon="icon.ico" --add-data="icon.png;." main.py

The final executable file will be created in a folder named dist.
📜 License

This project is licensed under the MIT License.

Created by cheetahcoder
