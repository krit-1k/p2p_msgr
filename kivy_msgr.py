#!/usr/bin/env python3
"""
P2P Messenger - версия на Kivy для Android
Компилируется в APK через Buildozer
"""

import socket
import threading
import json
import os
import base64
import hashlib
import sqlite3
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from kivy.app import App
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.gridlayout import GridLayout
from kivy.uix.scrollview import ScrollView
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from kivy.uix.listview import ListView
from kivy.uix.listitem import ListItemButton
from kivy.core.window import Window
from kivy.clock import Clock
from kivy.metrics import dp

# ============================================================================
# КОНФИГУРАЦИЯ
# ============================================================================
DATA_DIR = os.path.join(os.path.expanduser("~"), "P2PMessenger")
os.makedirs(DATA_DIR, exist_ok=True)

CONFIG = {
    "p2p_port": 14888,
    "db_name": os.path.join(DATA_DIR, "p2p_messenger.db"),
    "config_file": os.path.join(DATA_DIR, "p2p_config.json"),
    "dns_registry": os.path.join(DATA_DIR, "dns_registry.json"),
}

# ============================================================================
# ЛОКАЛЬНОЕ ХРАНИЛИЩЕ
# ============================================================================
class LocalStorage:
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                phone TEXT,
                password_hash TEXT NOT NULL,
                salt TEXT NOT NULL,
                my_ip TEXT,
                public_key TEXT,
                avatar BLOB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        try:
            cursor.execute("ALTER TABLE users ADD COLUMN avatar BLOB")
        except sqlite3.OperationalError:
            pass

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS contacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                phone TEXT,
                ip_address TEXT,
                public_key TEXT,
                last_seen TIMESTAMP,
                UNIQUE(username)
            )
        """)

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_username TEXT NOT NULL,
                receiver_username TEXT NOT NULL,
                content TEXT NOT NULL,
                encrypted INTEGER DEFAULT 0,
                sent_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                delivered INTEGER DEFAULT 0,
                read_at TIMESTAMP
            )
        """)
        self.conn.commit()

    def get_password_hash(self, username):
        cursor = self.conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        return (row["password_hash"], row["salt"]) if row else (None, None)

    def create_user(self, username, phone, password):
        salt = base64.b64encode(os.urandom(32)).decode()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt.encode(), iterations=100000)
        password_hash = base64.b64encode(kdf.derive(password.encode())).decode()
        try:
            cursor = self.conn.cursor()
            cursor.execute("INSERT INTO users (username, phone, password_hash, salt) VALUES (?, ?, ?, ?)",
                          (username, phone, password_hash, salt))
            self.conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

    def verify_user(self, username, password):
        cursor = self.conn.cursor()
        cursor.execute("SELECT password_hash, salt FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
        if not row:
            return False
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=row["salt"].encode(), iterations=100000)
        password_hash = base64.b64encode(kdf.derive(password.encode())).decode()
        return password_hash == row["password_hash"]

    def save_message(self, sender, receiver, content, encrypted=0, check_duplicate=True):
        if check_duplicate:
            cursor = self.conn.cursor()
            cursor.execute("""SELECT id FROM messages WHERE sender_username = ? AND receiver_username = ?
                           AND content = ? AND delivered = 0 ORDER BY id DESC LIMIT 1""",
                          (sender, receiver, content))
            existing = cursor.fetchone()
            if existing:
                self.mark_message_delivered(existing["id"])
                return existing["id"]
        cursor = self.conn.cursor()
        cursor.execute("INSERT INTO messages (sender_username, receiver_username, content, encrypted) VALUES (?, ?, ?, ?)",
                      (sender, receiver, content, encrypted))
        self.conn.commit()
        return cursor.lastrowid

    def get_messages(self, username1, username2, limit=100):
        cursor = self.conn.cursor()
        cursor.execute("""SELECT * FROM messages WHERE (sender_username = ? AND receiver_username = ?)
                       OR (sender_username = ? AND receiver_username = ?) ORDER BY sent_at ASC LIMIT ?""",
                      (username1, username2, username2, username1, limit))
        return cursor.fetchall()

    def mark_message_delivered(self, message_id):
        cursor = self.conn.cursor()
        cursor.execute("UPDATE messages SET delivered = 1 WHERE id = ?", (message_id,))
        self.conn.commit()

    def add_contact(self, username, phone=None, ip_address=None):
        cursor = self.conn.cursor()
        cursor.execute("""INSERT OR REPLACE INTO contacts (username, phone, ip_address, last_seen)
                       VALUES (?, ?, ?, ?)""", (username, phone, ip_address, datetime.now()))
        self.conn.commit()

    def get_contact(self, username):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM contacts WHERE username = ?", (username,))
        return cursor.fetchone()

    def get_all_contacts(self):
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM contacts ORDER BY username")
        return cursor.fetchall()

    def close(self):
        self.conn.close()

# ============================================================================
# P2P СОЕДИНЕНИЕ
# ============================================================================
class P2PConnection:
    def __init__(self, storage, callback=None):
        self.storage = storage
        self.callback = callback
        self.server_socket = None
        self.running = False
        self.my_ip = None
        self.local_ip = None

    def get_external_ip(self):
        try:
            import urllib.request
            response = urllib.request.urlopen("https://api.ipify.org?format=json", timeout=3)
            return json.loads(response.read().decode()).get("ip")
        except:
            return None

    def get_local_ip(self):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except:
            return "127.0.0.1"

    def start_server(self, port):
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.server_socket.bind(("0.0.0.0", port))
            self.server_socket.listen(10)
            self.running = True
            self.local_ip = self.get_local_ip()
            
            def get_ip_async():
                self.my_ip = self.get_external_ip()
            
            threading.Thread(target=get_ip_async, daemon=True).start()
            threading.Thread(target=self._accept_connections, daemon=True).start()
            return True
        except Exception as e:
            print(f"Ошибка сервера: {e}")
            return False

    def _accept_connections(self):
        while self.running:
            try:
                self.server_socket.settimeout(1.0)
                client_socket, addr = self.server_socket.accept()
                threading.Thread(target=self._handle_client, args=(client_socket, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    print(f"Ошибка: {e}")

    def _handle_client(self, client_socket, addr):
        try:
            data = client_socket.recv(4096).decode()
            if not data:
                return
            message = json.loads(data)
            if message.get("type") == "message":
                sender = message.get("sender")
                content = message.get("content")
                receiver = message.get("receiver")
                msg_id = self.storage.save_message(sender, receiver, content, encrypted=0, check_duplicate=True)
                if msg_id:
                    self.storage.mark_message_delivered(msg_id)
                if self.callback:
                    self.callback(sender, content)
                client_socket.send(json.dumps({"status": "received", "msg_id": msg_id}).encode())
        except Exception as e:
            print(f"Ошибка: {e}")
        finally:
            client_socket.close()

    def send_message(self, peer_ip, message_data, timeout=5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((peer_ip, CONFIG["p2p_port"]))
            sock.send(json.dumps(message_data).encode())
            sock.close()
            return True
        except Exception as e:
            print(f"Ошибка отправки: {e}")
            return False

    def stop(self):
        self.running = False
        if self.server_socket:
            self.server_socket.close()

# ============================================================================
# DNS ОБНАРУЖЕНИЕ
# ============================================================================
class DNSDiscovery:
    @staticmethod
    def register_username(username, ip_address, ttl=300):
        try:
            dns_file = CONFIG.get("dns_registry", os.path.join(DATA_DIR, "dns_registry.json"))
            registry = {}
            if os.path.exists(dns_file):
                with open(dns_file, "r") as f:
                    registry = json.load(f)
            registry[username] = {"ip": ip_address, "timestamp": datetime.now().isoformat(), "ttl": ttl}
            with open(dns_file, "w") as f:
                json.dump(registry, f, indent=2)
            return True
        except Exception as e:
            print(f"Ошибка DNS: {e}")
            return False

    @staticmethod
    def lookup_username(username):
        dns_file = CONFIG.get("dns_registry", os.path.join(DATA_DIR, "dns_registry.json"))
        if not os.path.exists(dns_file):
            return None
        try:
            with open(dns_file, "r") as f:
                registry = json.load(f)
            entry = registry.get(username)
            if entry:
                return entry["ip"]
        except:
            pass
        return None

# ============================================================================
# ЭКРАНЫ
# ============================================================================
class LoginScreen(GridLayout):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.cols = 1
        self.padding = dp(20)
        self.spacing = dp(10)
        
        # Заголовок
        self.add_widget(Label(
            text="🔐 P2P Messenger",
            font_size=dp(28),
            bold=True,
            size_hint=(1, 0.15),
            color=(1, 1, 1, 1)
        ))
        
        self.add_widget(Label(
            text="Децентрализованный мессенджер",
            font_size=dp(14),
            size_hint=(1, 0.1),
            color=(0.7, 0.7, 0.7, 1)
        ))
        
        # Поля ввода
        self.username_input = TextInput(
            hint_text="Username",
            multiline=False,
            size_hint=(1, 0.1),
            font_size=dp(16)
        )
        self.add_widget(self.username_input)
        
        self.password_input = TextInput(
            hint_text="Пароль",
            password=True,
            multiline=False,
            size_hint=(1, 0.1),
            font_size=dp(16)
        )
        self.add_widget(self.password_input)
        
        # Кнопки
        btn_layout = BoxLayout(
            orientation='horizontal',
            size_hint=(1, 0.15),
            spacing=dp(10),
            padding=dp(5)
        )
        
        self.login_btn = Button(
            text="Войти",
            font_size=dp(16),
            background_color=(0.06, 0.2, 0.38, 1)
        )
        self.login_btn.bind(on_press=self.login)
        btn_layout.add_widget(self.login_btn)
        
        self.register_btn = Button(
            text="Регистрация",
            font_size=dp(16),
            background_color=(0.09, 0.29, 0.45, 1)
        )
        self.register_btn.bind(on_press=self.go_to_register)
        btn_layout.add_widget(self.register_btn)
        
        self.add_widget(btn_layout)
        
        self.status_label = Label(
            text="",
            size_hint=(1, 0.1),
            color=(1, 0.3, 0.3, 1)
        )
        self.add_widget(self.status_label)

    def login(self, instance):
        username = self.username_input.text.strip()
        password = self.password_input.text
        
        if not username or not password:
            self.status_label.text = "Введите username и пароль"
            return
        
        self.app.storage = LocalStorage(CONFIG["db_name"])
        if self.app.storage.verify_user(username, password):
            self.app.current_user = username
            self.app.init_p2p()
            self.app.screen_manager.current = 'main'
        else:
            self.status_label.text = "Неверный username или пароль"

    def go_to_register(self, instance):
        self.app.screen_manager.current = 'register'


class RegisterScreen(GridLayout):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.cols = 1
        self.padding = dp(20)
        self.spacing = dp(10)
        
        self.add_widget(Label(
            text="📝 Регистрация",
            font_size=dp(24),
            bold=True,
            size_hint=(1, 0.15),
            color=(1, 1, 1, 1)
        ))
        
        self.username_input = TextInput(
            hint_text="Username",
            multiline=False,
            size_hint=(1, 0.1),
            font_size=dp(16)
        )
        self.add_widget(self.username_input)
        
        self.phone_input = TextInput(
            hint_text="Телефон (необязательно)",
            multiline=False,
            size_hint=(1, 0.1),
            font_size=dp(16)
        )
        self.add_widget(self.phone_input)
        
        self.password_input = TextInput(
            hint_text="Пароль",
            password=True,
            multiline=False,
            size_hint=(1, 0.1),
            font_size=dp(16)
        )
        self.add_widget(self.password_input)
        
        btn_layout = BoxLayout(
            orientation='horizontal',
            size_hint=(1, 0.15),
            spacing=dp(10)
        )
        
        reg_btn = Button(
            text="Зарегистрироваться",
            font_size=dp(16),
            background_color=(0.06, 0.2, 0.38, 1)
        )
        reg_btn.bind(on_press=self.register)
        btn_layout.add_widget(reg_btn)
        
        back_btn = Button(
            text="Назад",
            font_size=dp(16),
            background_color=(0.09, 0.29, 0.45, 1)
        )
        back_btn.bind(on_press=self.go_back)
        btn_layout.add_widget(back_btn)
        
        self.add_widget(btn_layout)
        
        self.status_label = Label(
            text="",
            size_hint=(1, 0.1),
            color=(0.3, 1, 0.3, 1)
        )
        self.add_widget(self.status_label)

    def register(self, instance):
        username = self.username_input.text.strip()
        phone = self.phone_input.text.strip()
        password = self.password_input.text
        
        if not username or not password:
            self.status_label.text = "Заполните username и пароль"
            self.status_label.color = (1, 0.3, 0.3, 1)
            return
        
        self.app.storage = LocalStorage(CONFIG["db_name"])
        if self.app.storage.create_user(username, phone, password):
            self.status_label.text = "Регистрация успешна!"
            self.status_label.color = (0.3, 1, 0.3, 1)
            Clock.schedule_once(lambda dt: setattr(self.app.screen_manager, 'current', 'login'), 1.5)
        else:
            self.status_label.text = "Username уже занят"
            self.status_label.color = (1, 0.3, 0.3, 1)

    def go_back(self, instance):
        self.app.screen_manager.current = 'login'


class MainScreen(BoxLayout):
    def __init__(self, app, **kwargs):
        super().__init__(**kwargs)
        self.app = app
        self.orientation = 'vertical'
        
        # Верхняя панель
        header = BoxLayout(
            orientation='horizontal',
            size_hint=(1, 0.08),
            padding=dp(10)
        )
        
        self.user_label = Label(
            text=f"👤 {self.app.current_user}",
            font_size=dp(16),
            bold=True,
            halign='left',
            color=(1, 1, 1, 1)
        )
        header.add_widget(self.user_label)
        
        self.ip_label = Label(
            text="🌐 Получение IP...",
            font_size=dp(12),
            halign='right',
            color=(1, 0.6, 0, 1)
        )
        header.add_widget(self.ip_label)
        
        logout_btn = Button(
            text="🚪",
            font_size=dp(20),
            size_hint=(None, None),
            width=dp(50)
        )
        logout_btn.bind(on_press=self.logout)
        header.add_widget(logout_btn)
        
        self.add_widget(header)
        
        # Основной контент
        content = BoxLayout(
            orientation='horizontal',
            size_hint=(1, 1)
        )
        
        # Левая панель - контакты
        left_panel = BoxLayout(
            orientation='vertical',
            size_hint=(0.35, 1),
            padding=dp(10)
        )
        
        contacts_header = BoxLayout(
            orientation='horizontal',
            size_hint=(1, 0.08)
        )
        contacts_header.add_widget(Label(
            text="Контакты",
            font_size=dp(18),
            bold=True,
            halign='left',
            color=(1, 1, 1, 1)
        ))
        
        add_btn = Button(
            text="+",
            font_size=dp(20),
            size_hint=(None, None),
            width=dp(40),
            background_color=(0.3, 0.6, 0.9, 1)
        )
        add_btn.bind(on_press=self.add_contact)
        contacts_header.add_widget(add_btn)
        
        left_panel.add_widget(contacts_header)
        
        # Список контактов
        self.contacts_layout = GridLayout(
            cols=1,
            size_hint=(1, 1),
            spacing=dp(5),
            padding=dp(5)
        )
        
        scroll = ScrollView(size_hint=(1, 1))
        scroll.add_widget(self.contacts_layout)
        left_panel.add_widget(scroll)
        
        content.add_widget(left_panel)
        
        # Правая панель - чат
        right_panel = BoxLayout(
            orientation='vertical',
            size_hint=(0.65, 1),
            padding=dp(10)
        )
        
        self.chat_label = Label(
            text="Чат",
            font_size=dp(18),
            bold=True,
            size_hint=(1, 0.08),
            halign='left',
            color=(1, 1, 1, 1)
        )
        right_panel.add_widget(self.chat_label)
        
        # Сообщения
        self.messages_layout = GridLayout(
            cols=1,
            size_hint=(1, 0.82),
            spacing=dp(5),
            padding=dp(5)
        )
        
        msg_scroll = ScrollView(size_hint=(1, 1))
        msg_scroll.add_widget(self.messages_layout)
        right_panel.add_widget(msg_scroll)
        
        # Ввод сообщения
        input_layout = BoxLayout(
            orientation='horizontal',
            size_hint=(1, 0.1),
            spacing=dp(10)
        )
        
        self.message_input = TextInput(
            hint_text="Введите сообщение...",
            multiline=False,
            font_size=dp(16)
        )
        self.message_input.bind(on_text_validate=self.send_message)
        input_layout.add_widget(self.message_input)
        
        send_btn = Button(
            text="➤",
            font_size=dp(20),
            size_hint=(None, 1),
            width=dp(50),
            background_color=(0.06, 0.2, 0.38, 1)
        )
        send_btn.bind(on_press=self.send_message)
        input_layout.add_widget(send_btn)
        
        right_panel.add_widget(input_layout)
        
        content.add_widget(right_panel)
        self.add_widget(content)
        
        self.selected_contact = None

    def update_ip(self, dt):
        if self.app.p2p:
            if self.app.p2p.my_ip:
                self.ip_label.text = f"🌐 {self.app.p2p.my_ip}"
                self.ip_label.color = (0.3, 1, 0.3, 1)
            else:
                self.ip_label.text = "🌐 Получение IP..."
                self.ip_label.color = (1, 0.6, 0, 1)

    def refresh_contacts(self):
        self.contacts_layout.clear_widgets()
        contacts = self.app.storage.get_all_contacts()
        for contact in contacts:
            btn = ListItemButton(
                text=contact["username"],
                font_size=dp(16),
                height=dp(50),
                size_hint=(None, None),
                background_color=(0.09, 0.29, 0.45, 1) if self.selected_contact == contact["username"] else (0.15, 0.15, 0.15, 1)
            )
            btn.bind(on_press=lambda inst, c=contact["username"]: self.select_contact(c))
            self.contacts_layout.add_widget(btn)

    def select_contact(self, username):
        self.selected_contact = username
        self.chat_label.text = f"Чат с {username}"
        self.refresh_contacts()
        self.refresh_messages()

    def refresh_messages(self):
        if not self.selected_contact:
            return
        self.messages_layout.clear_widgets()
        messages = self.app.storage.get_messages(self.app.current_user, self.selected_contact)
        for msg in messages:
            is_me = msg["sender_username"] == self.app.current_user
            self.add_message_bubble(msg["content"], is_me)

    def add_message_bubble(self, content, is_me):
        bubble = Label(
            text=content,
            font_size=dp(14),
            size_hint=(0.7, None),
            height=dp(40),
            padding=dp(10),
            color=(1, 1, 1, 1),
            halign='right' if is_me else 'left',
            valign='middle'
        )
        # Цвет пузыря
        bubble.canvas.before.clear()
        with bubble.canvas.before:
            from kivy.graphics import Color, RoundedRectangle
            Color(0.06, 0.2, 0.38, 1 if is_me else 0.2, 0.2, 0.3, 1)
            RoundedRectangle(pos=bubble.pos, size=bubble.size, radius=[dp(15)])
        
        bubble.bind(pos=bubble.update_graphics, size=bubble.update_graphics)
        
        # Выравнивание
        wrapper = BoxLayout(
            size_hint=(1, None),
            height=dp(50)
        )
        if is_me:
            wrapper.add_widget(Label(size_hint=(0.3, 1)))
            wrapper.add_widget(bubble)
        else:
            wrapper.add_widget(bubble)
            wrapper.add_widget(Label(size_hint=(0.3, 1)))
        
        self.messages_layout.add_widget(wrapper)

    def send_message(self, instance):
        content = self.message_input.text.strip()
        if not content or not self.selected_contact:
            return
        
        self.app.storage.save_message(self.app.current_user, self.selected_contact, content, check_duplicate=False)
        self.add_message_bubble(content, True)
        
        # Отправка пиру
        contact = self.app.storage.get_contact(self.selected_contact)
        if contact and contact.get("ip_address"):
            msg_data = {"type": "message", "sender": self.app.current_user, "receiver": self.selected_contact, "content": content}
            threading.Thread(target=lambda: self.app.p2p.send_message(contact["ip_address"], msg_data), daemon=True).start()
        
        self.message_input.text = ""

    def add_contact(self, instance):
        # Простой диалог через popup
        from kivy.uix.popup import Popup
        
        popup_layout = GridLayout(cols=1, padding=dp(20), spacing=dp(10))
        
        title = Label(text="Добавить контакт", font_size=dp(20), size_hint=(1, 0.2))
        popup_layout.add_widget(title)
        
        username_input = TextInput(hint_text="Username", multiline=False, size_hint=(1, 0.3), font_size=dp(16))
        popup_layout.add_widget(username_input)
        
        btn_layout = BoxLayout(orientation='horizontal', size_hint=(1, 0.2), spacing=dp(10))
        
        add_btn = Button(text="Добавить", background_color=(0.06, 0.2, 0.38, 1))
        def add_pressed(inst):
            username = username_input.text.strip()
            if username:
                self.app.storage.add_contact(username)
                self.refresh_contacts()
                popup.dismiss()
        add_btn.bind(on_press=add_pressed)
        btn_layout.add_widget(add_btn)
        
        cancel_btn = Button(text="Отмена", background_color=(0.3, 0.3, 0.3, 1))
        cancel_btn.bind(on_press=lambda inst: popup.dismiss())
        btn_layout.add_widget(cancel_btn)
        
        popup_layout.add_widget(btn_layout)
        
        popup = Popup(
            title="Новый контакт",
            content=popup_layout,
            size_hint=(0.8, 0.4)
        )
        popup.open()

    def logout(self, instance):
        if self.app.p2p:
            self.app.p2p.stop()
        self.app.current_user = None
        self.app.selected_contact = None
        self.app.screen_manager.current = 'login'


# ============================================================================
# ПРИЛОЖЕНИЕ
# ============================================================================
class P2PMessengerApp(App):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.storage = None
        self.p2p = None
        self.current_user = None
        self.selected_contact = None

    def build(self):
        self.title = "P2P Messenger"
        Window.clearcolor = (0.1, 0.1, 0.18, 1)
        
        self.screen_manager = ScreenManager()
        
        # Экраны
        login_screen = LoginScreen(self)
        self.screen_manager.add_widget(Screen(name='login', children=[login_screen]))
        
        register_screen = RegisterScreen(self)
        self.screen_manager.add_widget(Screen(name='register', children=[register_screen]))
        
        self.main_screen = MainScreen(self)
        self.screen_manager.add_widget(Screen(name='main', children=[self.main_screen]))
        
        return self.screen_manager

    def init_p2p(self):
        self.storage = LocalStorage(CONFIG["db_name"])
        self.p2p = P2PConnection(self.storage, callback=self.on_new_message)
        self.p2p.start_server(CONFIG["p2p_port"])
        
        if self.p2p.my_ip:
            DNSDiscovery.register_username(self.current_user, self.p2p.my_ip)
        
        # Обновление IP
        Clock.schedule_interval(self.main_screen.update_ip, 1)

    def on_new_message(self, sender, content):
        Clock.schedule_once(lambda dt: self.handle_new_message(sender, content))

    def handle_new_message(self, sender, content):
        if self.main_screen.selected_contact == sender:
            self.main_screen.add_message_bubble(content, False)
        self.main_screen.refresh_contacts()


if __name__ == "__main__":
    P2PMessengerApp().run()
