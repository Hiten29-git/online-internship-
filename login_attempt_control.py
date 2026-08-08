"""
Login Attempt Control System
-----------------------------
Mitigates brute-force login attacks by tracking failed attempts per
user (or IP) and enforcing a progressive lockout: each additional
failed attempt within a tracking window increases the lockout
duration, making automated guessing increasingly expensive.

Author: Hiten G
"""

import time
from dataclasses import dataclass, field


@dataclass
class UserRecord:
    failed_attempts: int = 0
    lockout_until: float = 0.0
    lockout_count: int = 0  # how many times this user has been locked out


class LoginAttemptControl:
    """
    Tracks failed login attempts and enforces progressive lockouts.

    Parameters
    ----------
    max_attempts : int
        Number of failed attempts allowed before a lockout is triggered.
    base_lockout_seconds : int
        Lockout duration after the first lockout. Doubles on each
        subsequent lockout for the same user (progressive backoff).
    max_lockout_seconds : int
        Upper cap on lockout duration, so it doesn't grow unbounded.
    """

    def __init__(self, max_attempts: int = 3,
                 base_lockout_seconds: int = 5,
                 max_lockout_seconds: int = 300):
        self.max_attempts = max_attempts
        self.base_lockout_seconds = base_lockout_seconds
        self.max_lockout_seconds = max_lockout_seconds
        self._users: dict[str, UserRecord] = {}

    def _get_record(self, identifier: str) -> UserRecord:
        if identifier not in self._users:
            self._users[identifier] = UserRecord()
        return self._users[identifier]

    def is_locked_out(self, identifier: str) -> bool:
        record = self._get_record(identifier)
        return time.time() < record.lockout_until

    def time_remaining(self, identifier: str) -> float:
        record = self._get_record(identifier)
        remaining = record.lockout_until - time.time()
        return max(0.0, remaining)

    def record_failed_attempt(self, identifier: str) -> str:
        """
        Registers a failed login attempt. Returns a status message
        describing the outcome (locked out / attempts remaining).
        """
        record = self._get_record(identifier)

        if self.is_locked_out(identifier):
            return (f"Account '{identifier}' is locked. "
                    f"Try again in {self.time_remaining(identifier):.0f}s.")

        record.failed_attempts += 1

        if record.failed_attempts >= self.max_attempts:
            lockout_duration = min(
                self.base_lockout_seconds * (2 ** record.lockout_count),
                self.max_lockout_seconds,
            )
            record.lockout_until = time.time() + lockout_duration
            record.lockout_count += 1
            record.failed_attempts = 0
            return (f"Too many failed attempts. '{identifier}' is now "
                    f"locked out for {lockout_duration:.0f} seconds.")

        remaining = self.max_attempts - record.failed_attempts
        return f"Incorrect credentials. {remaining} attempt(s) remaining."

    def record_successful_attempt(self, identifier: str) -> str:
        """Resets failed-attempt count on a successful login."""
        record = self._get_record(identifier)
        record.failed_attempts = 0
        record.lockout_count = 0
        record.lockout_until = 0.0
        return f"Login successful. Welcome, '{identifier}'."

    def attempt_login(self, identifier: str, password: str,
                       correct_password: str) -> str:
        """Convenience wrapper: verifies a password and updates state."""
        if self.is_locked_out(identifier):
            return (f"Account '{identifier}' is locked. "
                    f"Try again in {self.time_remaining(identifier):.0f}s.")
        if password == correct_password:
            return self.record_successful_attempt(identifier)
        return self.record_failed_attempt(identifier)


def _demo():
    """Simple CLI demo using an in-memory fake user database."""
    fake_db = {"alice": "correcthorsebattery", "bob": "hunter2"}
    controller = LoginAttemptControl(max_attempts=3, base_lockout_seconds=5)

    print("=== Login Attempt Control Demo ===")
    print("Users: alice / bob   (Ctrl+C to quit)\n")

    while True:
        try:
            username = input("Username: ").strip()
            if username not in fake_db:
                print("No such user.\n")
                continue
            password = input("Password: ").strip()
            print(controller.attempt_login(username, password, fake_db[username]))
            print()
        except KeyboardInterrupt:
            print("\nExiting.")
            break


if __name__ == "__main__":
    _demo()
