import os
import shutil
from rich import print as rprint
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

class CRT:
    def __init__(self, config, kind, sessions, is_jumphost=False):
        self.config = config
        self.kind = kind
        self.sessions = sessions
        self.is_jumphost = is_jumphost

        self.path = config["crt_path"]
        self.top_dir = config["directory"][kind]["top_dir"]
        self.jumphost_dir = config["directory"][kind].get("jumphost_dir")
        self.top_path = os.path.join(self.path, self.top_dir)

    def run(self) -> None:
        self._check_base_dirs()
        self._make_dirs()

    def _check_base_dirs(self):
        if not os.path.exists(self.path):
            raise Exception("[Error] Default SecureCRT's session directory not found.")

        if not os.path.exists(self.top_path):
            os.makedirs(self.top_path)
            rprint(f"[dark_orange]'Top dir'[/dark_orange] created at [green]{self.top_path}[/green].")

    def _make_dirs(self):
        created_dirs = 0
        created_sessions = 0

        for folder, session_list in self.sessions.items():
            sub_path = os.path.join(self.top_path, folder)
            os.makedirs(sub_path, exist_ok=True)
            rprint(f"[blue]Created directory:[/blue] {sub_path}")
            created_dirs += 1

            for session in session_list:
                if self._create_session_file(sub_path, session):
                    created_sessions += 1

        rprint(f"[green]Created {created_dirs} directories and {created_sessions} session files.[/green]")

    def _create_session_file(self, dir_path, session):
        file_path = os.path.join(dir_path, session["file_name"])
        try:
            default_ini = os.path.join(self.path, "Default.ini")
            temp_ini = os.path.join(dir_path, "Default.ini")

            shutil.copyfile(default_ini, temp_ini)
            shutil.move(temp_ini, file_path)

            new_content = []
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.startswith('S:"Hostname"='):
                        line = f'S:"Hostname"={session["host"]}\n'
                    elif 'S:"Username"=' in line:
                        line = f'S:"Username"={session.get("username", "")}\n'
                    elif line.startswith('S:"Password V2"='):
                        password = session.get("password", "")
                        enc_pass = self.encrypt_pass(password) if password else ""
                        line = f'S:"Password V2"=02:{enc_pass}\n'
                    elif line.startswith('D:"Session Password Saved"='):
                        line = 'D:"Session Password Saved"=00000001\n'
                    elif line.startswith('S:"Protocol Name"='):
                        line = f'S:"Protocol Name"={session["protocol"]}\n'
                    elif line.startswith('D:"Port"=') or line.startswith('D:"[SSH2] Port"='):
                        port_hex = f'{int(session["port"]):08x}'
                        if session["protocol"] == "SSH2":
                            line = f'D:"[SSH2] Port"={port_hex}\n'
                        else:
                            line = f'D:"Port"={port_hex}\n'
                    elif line.startswith('S:"Firewall Name"=') and session.get("jumphost"):
                        line = f'S:"Firewall Name"=Session:{session["jumphost"]}\n'
                    new_content.append(line)

            with open(file_path, "w", encoding="utf-8") as f:
                f.writelines(new_content)

            rprint(f" - [cyan]{session['file_name']}[/cyan] created")
            return True
        except Exception as e:
            rprint(f"[red][Error][/red] Failed to create {session['file_name']}: {e}")
            return False

    def encrypt_pass(self, password):
        iv = b"\x00" * AES.block_size
        key = SHA256.new(b"").digest()
        plain_bytes = password.encode("utf-8")

        if len(plain_bytes) > 0xFFFFFFFF:
            raise OverflowError("Plaintext too long.")

        plain_bytes = (
            len(plain_bytes).to_bytes(4, "little") +
            plain_bytes +
            SHA256.new(plain_bytes).digest()
        )

        padded = plain_bytes + os.urandom(AES.block_size - len(plain_bytes) % AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(padded).hex()
