import argparse
import os
import pyperclip


class PaladinVaultCLI:

    _OptionHandlers = {}

    def __init__(self):
        self.arg_parser = argparse.ArgumentParser(
            prog="Paladin Vault",
            description="Paladin Vault manages your passwords securely"
        )

    def _mapOptionHandlers(self):
        self._OptionHandlers[1] = self.add_password

    def _initializeArgsParser(self):
        self.arg_parser.add_argument()

    def copy_to_clipboard(self,text:str):
        # To-Do work on clearing the clipboard
        pyperclip.copy(text)

    def clear_screen():
        os.system('cls' if os.name == 'nt' else 'clear')


    def show_menu():
        print("\n📋 Please choose an action:")
        print("1. Add password")
        print("2. Get password")
        print("3. Backup")
        print("4. Create USB security key")
        print("5. Exit")
        choice = input("Enter your choice (1-4): ")
        return choice.strip()
    
    def handleOption(self,option:int):
        # To-Do implement the adapter pattern for rendering the menu for each options (same interface all implement start_flow but different implementation)
        self._mapOptionHandlers[option]().start_flow()
