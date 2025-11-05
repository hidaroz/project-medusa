"""
Tab completion support for MEDUSA interactive shell
Provides context-aware command completion
"""

from typing import List, Dict, Any, Optional
from prompt_toolkit.completion import Completer, Completion
from prompt_toolkit.document import Document


class MedusaCompleter(Completer):
    """
    Custom completer for MEDUSA interactive shell
    Provides tab completion for commands, targets, and parameters
    """

    def __init__(self):
        """Initialize completer with command vocabulary"""
        # Built-in commands
        self.builtin_commands = [
            "help",
            "suggestions",
            "exit",
            "quit",
            "clear",
            "set target",
            "show context",
            "show findings",
            "show history",
        ]

        # Natural language command templates
        self.nl_commands = [
            "scan for open ports",
            "scan the target",
            "scan network",
            "enumerate services",
            "enumerate API endpoints",
            "enumerate databases",
            "find vulnerabilities",
            "test for SQL injection",
            "test for XSS",
            "test authentication",
            "exploit vulnerability",
            "exploit SQL injection",
            "exfiltrate data",
            "extract sensitive data",
            "what should I do next?",
            "show me high severity findings",
            "show me critical findings",
            "show vulnerabilities",
        ]

        # Common pentesting terms for mid-word completion
        self.keywords = [
            "port", "ports", "scan", "scanning",
            "enumerate", "enumeration",
            "vulnerability", "vulnerabilities",
            "exploit", "exploitation",
            "SQL", "injection", "XSS",
            "authentication", "bypass",
            "data", "exfiltrate", "extract",
            "findings", "results",
        ]

        # Combine all completions
        self.all_commands = self.builtin_commands + self.nl_commands

    def get_completions(self, document: Document, complete_event):
        """
        Generate completions based on current input

        Args:
            document: Current document/input
            complete_event: Completion event

        Yields:
            Completion objects
        """
        text = document.text_before_cursor.lower()
        word = document.get_word_before_cursor()

        # If empty or just whitespace, show common commands
        if not text.strip():
            for cmd in self.builtin_commands[:5]:  # Show top 5
                yield Completion(cmd, start_position=0, display=cmd, display_meta="built-in")
            return

        # Complete built-in commands
        for cmd in self.builtin_commands:
            if cmd.lower().startswith(text):
                yield Completion(
                    cmd,
                    start_position=-len(text),
                    display=cmd,
                    display_meta="built-in"
                )

        # Complete natural language commands
        for cmd in self.nl_commands:
            if cmd.lower().startswith(text):
                yield Completion(
                    cmd,
                    start_position=-len(text),
                    display=cmd,
                    display_meta="natural language"
                )

        # Mid-word keyword completion
        if word:
            for keyword in self.keywords:
                if keyword.lower().startswith(word.lower()) and keyword.lower() != word.lower():
                    yield Completion(
                        keyword,
                        start_position=-len(word),
                        display=keyword,
                        display_meta="keyword"
                    )


class CommandAliasManager:
    """
    Manage command aliases for shorter input
    """

    def __init__(self):
        """Initialize with default aliases"""
        self.aliases: Dict[str, str] = {
            # Short forms
            "s": "scan for open ports",
            "e": "enumerate services",
            "f": "find vulnerabilities",
            "v": "show findings",
            "h": "show history",
            "c": "show context",
            "?": "help",

            # Common shortcuts
            "scan": "scan for open ports",
            "enum": "enumerate services",
            "vulns": "find vulnerabilities",
            "sqli": "test for SQL injection",
            "xss": "test for XSS",

            # Action shortcuts
            "next": "what should I do next?",
            "suggest": "suggestions",

            # Longer aliases
            "scan-ports": "scan for open ports",
            "scan-vulns": "find vulnerabilities",
            "enum-api": "enumerate API endpoints",
            "test-sqli": "test for SQL injection",
            "test-xss": "test for XSS",
            "show-vulns": "show me high severity findings",
        }

    def resolve(self, command: str) -> str:
        """
        Resolve alias to full command

        Args:
            command: Command or alias

        Returns:
            Full command (or original if not an alias)
        """
        # Check for exact match
        if command.lower() in self.aliases:
            return self.aliases[command.lower()]

        # Check if command starts with an alias
        for alias, full_cmd in self.aliases.items():
            if command.lower().startswith(alias + " "):
                # Replace alias with full command, keep rest
                rest = command[len(alias):].strip()
                return f"{full_cmd} {rest}"

        return command

    def add_alias(self, alias: str, command: str):
        """
        Add a new alias

        Args:
            alias: Short alias
            command: Full command
        """
        self.aliases[alias.lower()] = command

    def remove_alias(self, alias: str):
        """
        Remove an alias

        Args:
            alias: Alias to remove
        """
        if alias.lower() in self.aliases:
            del self.aliases[alias.lower()]

    def list_aliases(self) -> Dict[str, str]:
        """
        Get all aliases

        Returns:
            Dictionary of alias -> command
        """
        return self.aliases.copy()

    def get_alias_for_command(self, command: str) -> List[str]:
        """
        Find aliases that map to a command

        Args:
            command: Command to search for

        Returns:
            List of aliases
        """
        return [alias for alias, cmd in self.aliases.items() if cmd == command]
