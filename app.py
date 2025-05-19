"""
File Encryption/Decryption Tool

A GUI application for encrypting and decrypting files using AES-256 encryption.
"""

import os
import sys
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from typing import Optional, Tuple, Dict, Any
import threading
import time
from pathlib import Path

# Import our encryption utilities
import encryption_utils


class FileEncryptionApp:
    """Main application class for the file encryption/decryption tool."""
    
    def __init__(self, root: tk.Tk):
        """Initialize the application."""
        self.root = root
        self.root.title("File Encryption Tool")
        self.root.geometry("900x700")
        self.root.minsize(800, 600)
        
        # Set application icon if available
        try:
            self.root.iconbitmap("lock_icon.ico")
        except:
            pass  # Icon not found, use default
        
        # File paths
        self.input_file_path: Optional[str] = None
        self.output_file_path: Optional[str] = None
        
        # Create the UI
        self.create_ui()
        
        # Current operation thread
        self.current_thread: Optional[threading.Thread] = None
        self.operation_cancelled = False
    
    def create_ui(self):
        """Create the user interface."""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Style configuration
        style = ttk.Style()
        style.configure("TButton", padding=6, font=('Helvetica', 10))
        style.configure("TLabel", font=('Helvetica', 10))
        style.configure("Header.TLabel", font=('Helvetica', 12, 'bold'))
        
        # Title
        title_label = ttk.Label(
            main_frame, 
            text="File Encryption/Decryption Tool", 
            style="Header.TLabel"
        )
        title_label.pack(pady=(0, 20))
        
        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="File Selection", padding=10)
        file_frame.pack(fill=tk.X, pady=10)
        
        # Input file selection
        input_file_frame = ttk.Frame(file_frame)
        input_file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_file_frame, text="Input File:").pack(side=tk.LEFT, padx=(0, 10))
        
        self.input_file_var = tk.StringVar()
        input_file_entry = ttk.Entry(input_file_frame, textvariable=self.input_file_var, width=50)
        input_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_btn = ttk.Button(
            input_file_frame, 
            text="Browse...", 
            command=self.browse_input_file
        )
        browse_btn.pack(side=tk.LEFT)
        
        # Output file selection
        output_file_frame = ttk.Frame(file_frame)
        output_file_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(output_file_frame, text="Output File:").pack(side=tk.LEFT, padx=(0, 10))
        
        self.output_file_var = tk.StringVar()
        output_file_entry = ttk.Entry(output_file_frame, textvariable=self.output_file_var, width=50)
        output_file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        save_as_btn = ttk.Button(
            output_file_frame, 
            text="Save As...", 
            command=self.browse_output_file
        )
        save_as_btn.pack(side=tk.LEFT)
        
        # Password frame
        password_frame = ttk.LabelFrame(main_frame, text="Password", padding=10)
        password_frame.pack(fill=tk.X, pady=10)
        
        password_input_frame = ttk.Frame(password_frame)
        password_input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(password_input_frame, text="Password:").pack(side=tk.LEFT, padx=(0, 10))
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(password_input_frame, textvariable=self.password_var, show="*", width=30)
        self.password_entry.pack(side=tk.LEFT, padx=(0, 10))
        
        self.show_password_var = tk.BooleanVar()
        show_password_cb = ttk.Checkbutton(
            password_input_frame, 
            text="Show Password", 
            variable=self.show_password_var,
            command=self.toggle_password_visibility
        )
        show_password_cb.pack(side=tk.LEFT)
        
        # Action buttons
        action_frame = ttk.Frame(main_frame)
        action_frame.pack(fill=tk.X, pady=10)
        
        encrypt_btn = ttk.Button(
            action_frame, 
            text="Encrypt File", 
            command=self.encrypt_file
        )
        encrypt_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        decrypt_btn = ttk.Button(
            action_frame, 
            text="Decrypt File", 
            command=self.decrypt_file
        )
        decrypt_btn.pack(side=tk.LEFT)
        
        # Progress bar
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=10)
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame, 
            variable=self.progress_var, 
            maximum=100
        )
        self.progress_bar.pack(fill=tk.X)
        
        # Status label
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_label = ttk.Label(progress_frame, textvariable=self.status_var)
        status_label.pack(anchor=tk.W, pady=(5, 0))
        
        # File preview
        preview_frame = ttk.LabelFrame(main_frame, text="File Preview", padding=10)
        preview_frame.pack(fill=tk.BOTH, expand=True, pady=10)
        
        self.preview_text = scrolledtext.ScrolledText(
            preview_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=15
        )
        self.preview_text.pack(fill=tk.BOTH, expand=True)
        self.preview_text.config(state=tk.DISABLED)
    
    def browse_input_file(self):
        """Open file dialog to select an input file."""
        file_path = filedialog.askopenfilename(
            title="Select File",
            filetypes=[("All Files", "*.*")]
        )
        
        if file_path:
            self.input_file_path = file_path
            self.input_file_var.set(file_path)
            
            # Suggest an output file name
            if not self.output_file_var.get():
                input_path = Path(file_path)
                if self.is_encrypted_file(input_path):
                    # For encrypted files, suggest removing the .encrypted extension
                    output_path = input_path.with_suffix('')
                    if output_path.suffix == '':
                        output_path = output_path.with_suffix('.decrypted')
                else:
                    # For regular files, add .encrypted extension
                    output_path = input_path.with_suffix(input_path.suffix + '.encrypted')
                
                self.output_file_path = str(output_path)
                self.output_file_var.set(str(output_path))
            
            # Show file preview
            self.show_file_preview(file_path)
    
    def browse_output_file(self):
        """Open file dialog to select an output file."""
        file_path = filedialog.asksaveasfilename(
            title="Save As",
            filetypes=[("All Files", "*.*")]
        )
        
        if file_path:
            self.output_file_path = file_path
            self.output_file_var.set(file_path)
    
    def toggle_password_visibility(self):
        """Toggle password visibility."""
        if self.show_password_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def is_encrypted_file(self, file_path: Path) -> bool:
        """Check if a file appears to be encrypted."""
        return file_path.suffix.lower() == '.encrypted'
    
    def show_file_preview(self, file_path: str):
        """Show a preview of the file content."""
        try:
            preview_text, truncated = encryption_utils.get_file_preview(file_path)
            
            self.preview_text.config(state=tk.NORMAL)
            self.preview_text.delete(1.0, tk.END)
            self.preview_text.insert(tk.END, preview_text)
            
            if truncated:
                self.preview_text.insert(tk.END, "\n\n[File content truncated...]")
            
            self.preview_text.config(state=tk.DISABLED)
            
        except Exception as e:
            self.preview_text.config(state=tk.NORMAL)
            self.preview_text.delete(1.0, tk.END)
            self.preview_text.insert(tk.END, f"Error loading file preview: {str(e)}")
            self.preview_text.config(state=tk.DISABLED)
    
    def encrypt_file(self):
        """Encrypt the selected file."""
        if not self.validate_inputs():
            return
        
        self.status_var.set("Encrypting file...")
        self.progress_var.set(0)
        
        # Start encryption in a separate thread
        self.operation_cancelled = False
        self.current_thread = threading.Thread(
            target=self._encrypt_file_thread,
            daemon=True
        )
        self.current_thread.start()
        
        # Start progress monitoring
        self.root.after(100, self.check_progress)
    
    def decrypt_file(self):
        """Decrypt the selected file."""
        if not self.validate_inputs():
            return
        
        self.status_var.set("Decrypting file...")
        self.progress_var.set(0)
        
        # Start decryption in a separate thread
        self.operation_cancelled = False
        self.current_thread = threading.Thread(
            target=self._decrypt_file_thread,
            daemon=True
        )
        self.current_thread.start()
        
        # Start progress monitoring
        self.root.after(100, self.check_progress)
    
    def _encrypt_file_thread(self):
        """Thread function for file encryption."""
        try:
            encryption_utils.encrypt_file(
                self.input_file_path,
                self.output_file_path,
                self.password_var.get()
            )
            
            if not self.operation_cancelled:
                # Update UI from main thread
                self.root.after(0, lambda: self.status_var.set("Encryption completed successfully!"))
                self.root.after(0, lambda: self.progress_var.set(100))
                self.root.after(0, lambda: messagebox.showinfo("Success", "File encrypted successfully!"))
                
                # Show preview of encrypted file
                self.root.after(0, lambda: self.show_file_preview(self.output_file_path))
        
        except Exception as e:
            if not self.operation_cancelled:
                # Update UI from main thread
                self.root.after(0, lambda: self.status_var.set(f"Error: {str(e)}"))
                self.root.after(0, lambda: messagebox.showerror("Error", f"Encryption failed: {str(e)}"))
    
    def _decrypt_file_thread(self):
        """Thread function for file decryption."""
        try:
            encryption_utils.decrypt_file(
                self.input_file_path,
                self.output_file_path,
                self.password_var.get()
            )
            
            if not self.operation_cancelled:
                # Update UI from main thread
                self.root.after(0, lambda: self.status_var.set("Decryption completed successfully!"))
                self.root.after(0, lambda: self.progress_var.set(100))
                self.root.after(0, lambda: messagebox.showinfo("Success", "File decrypted successfully!"))
                
                # Show preview of decrypted file
                self.root.after(0, lambda: self.show_file_preview(self.output_file_path))
        
        except Exception as e:
            if not self.operation_cancelled:
                # Update UI from main thread
                self.root.after(0, lambda: self.status_var.set(f"Error: {str(e)}"))
                self.root.after(0, lambda: messagebox.showerror("Error", f"Decryption failed: {str(e)}"))
    
    def check_progress(self):
        """Check the progress of the current operation."""
        if self.current_thread and self.current_thread.is_alive():
            # Simulate progress for now (in a real app, we'd get actual progress)
            current = self.progress_var.get()
            if current < 90:  # Cap at 90% until complete
                self.progress_var.set(current + 10)
            
            # Check again in 100ms
            self.root.after(100, self.check_progress)
        else:
            # Thread is done or not running
            if self.progress_var.get() < 100 and not self.operation_cancelled:
                self.progress_var.set(100)
    
    def validate_inputs(self) -> bool:
        """Validate user inputs before processing."""
        # Check input file
        if not self.input_file_path or not os.path.isfile(self.input_file_path):
            messagebox.showerror("Error", "Please select a valid input file.")
            return False
        
        # Check output file
        if not self.output_file_path:
            messagebox.showerror("Error", "Please specify an output file.")
            return False
        
        # Check if output file already exists
        if os.path.exists(self.output_file_path):
            result = messagebox.askyesno(
                "Warning", 
                "Output file already exists. Do you want to overwrite it?"
            )
            if not result:
                return False
        
        # Check password
        if not self.password_var.get():
            messagebox.showerror("Error", "Please enter a password.")
            return False
        
        return True


def main():
    """Main entry point for the application."""
    root = tk.Tk()
    app = FileEncryptionApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
